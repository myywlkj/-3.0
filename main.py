"""
黄客联盟 · 渗透测试工具箱 v3.0
HuangKe Alliance — Red Team Web Penetration Toolkit

用法:
  python -m huangke                        交互式菜单
  python -m huangke full   -u <URL>        完整扫描
  python -m huangke scan   -u <URL>        目录扫描
  python -m huangke port   -u <URL>        端口扫描
  python -m huangke finger -u <URL>        指纹识别
  python -m huangke batch  -f <FILE>       批量扫描
  python -m huangke info   -u <URL>        信息收集
"""

import argparse
import asyncio
import sys
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .core.engine import HTTPEngine, EngineConfig
from .core.scanner import DirectoryScanner, ScanConfig
from .core.fingerprint import WebFingerprinter
from .core.analyzer import ContentAnalyzer
from .core.port_scanner import PortScanner, TOP_PORTS
from .data.wordlists import load_wordlist, load_default_wordlist
from .output.console import (
    console, print_banner, print_banner_compact, print_scan_results,
    print_fingerprint, print_analysis, print_port_results,
    print_summary, print_usage_guide, print_menu, print_about,
    create_progress,
)
from .output.json_out import save_json
from .output.html_out import save_html
from .output.csv_out import save_csv
from .output.md_out import save_markdown


@dataclass
class ScanOptions:
    """Consolidated scan options shared across all scan types."""
    url: str = ""
    wordlist: str = "default"
    threads: int = 30
    delay: float = 0.0
    timeout: int = 10
    proxy: str | None = None
    verbose: bool = False
    recursive: bool = False
    depth: int = 2
    ua: str | None = None
    no_verify: bool = False
    output: str | None = None

    # Scan-specific
    no_analyze: bool = False
    no_port: bool = False
    no_finger: bool = False
    port_list: str | None = None
    port_timeout: float = 2.0
    port_speed: int = 200
    include_status: str | None = None
    exclude_status: str | None = None
    min_length: int = 0
    match: str | None = None
    filter: str | None = None

    # Batch scanning
    jobs: int = 0  # 0 = auto (sequential, or min(4, targets) for batch)


# ═══════════════════════════════════════════════
# 依赖检查
# ═══════════════════════════════════════════════

def _check_dependencies():
    missing = []
    try:
        import aiohttp
    except ImportError:
        missing.append("aiohttp")
    try:
        import rich
    except ImportError:
        missing.append("rich")
    if missing:
        console.print(f"\n  [red]缺少依赖: {', '.join(missing)}[/red]")
        console.print(f"  [yellow]请运行: pip install {' '.join(missing)}[/yellow]\n")
        sys.exit(1)


# ═══════════════════════════════════════════════
# CLI 构建
# ═══════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="huangke",
        description="黄客联盟 · 渗透测试工具箱",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="直接运行 'python -m huangke' 进入交互式菜单\n仅供授权安全测试使用",
    )

    # 全局自动化选项
    parser.add_argument("--config", default=None, help="从 JSON/YAML 配置文件加载扫描设置 (自动化模式)")

    subs = parser.add_subparsers(dest="command", help="可用命令")

    def _common(p, url_required=True):
        if url_required:
            p.add_argument("-u", "--url", required=True, help="目标 URL")
        else:
            p.add_argument("-u", "--url", default=None, help="目标 URL")
        p.add_argument("-t", "--threads", type=int, default=50, help="并发数 (默认: 50)")
        p.add_argument("-d", "--delay", type=float, default=0, help="请求间隔秒数 (防封 IP)")
        p.add_argument("--timeout", type=int, default=10, help="请求超时秒数 (默认: 10)")
        p.add_argument("-p", "--proxy", default=None, help="代理地址 (http:// 或 socks5://)")
        p.add_argument("--ua", default=None, help="自定义 User-Agent")
        p.add_argument("-o", "--output", default=None, help="导出报告文件 (.html/.json/.csv/.md)")
        p.add_argument("-v", "--verbose", action="store_true", help="显示响应内容预览")
        p.add_argument("-k", "--no-verify", action="store_true", help="跳过 SSL 证书验证")
        # 自动化选项
        p.add_argument("--json", action="store_true", help="JSON 输出模式 (静默执行，结构化结果输出到 stdout)")
        p.add_argument("--webhook", default=None, help="扫描完成回调 URL (HTTP POST JSON 结果)")
        p.add_argument("--ci", action="store_true", help="CI 模式 (高危以上发现时返回非零退出码)")

    # full — 完整扫描
    p = subs.add_parser("full", help="完整扫描: 目录 + 端口 + 指纹 + 内容分析")
    _common(p)
    p.add_argument("-w", "--wordlist", default="default", help="词表 (default/common/sensitive/api/路径)")
    p.add_argument("-r", "--recursive", action="store_true", help="递归扫描发现的目录")
    p.add_argument("--depth", type=int, default=2, help="递归深度 (默认: 2)")
    p.add_argument("--no-analyze", action="store_true", help="跳过内容分析")
    p.add_argument("--no-port", action="store_true", help="跳过端口扫描")
    p.add_argument("--no-finger", action="store_true", help="跳过指纹识别")
    p.add_argument("--port-list", default=None, help="自定义端口列表文件")

    # scan — 目录扫描
    p = subs.add_parser("scan", help="目录和接口暴力破解")
    _common(p)
    p.add_argument("-w", "--wordlist", default="default", help="词表 (default/common/sensitive/api/路径)")
    p.add_argument("-r", "--recursive", action="store_true", help="递归扫描")
    p.add_argument("--depth", type=int, default=2, help="递归深度 (默认: 2)")
    p.add_argument("--include-status", default=None, help="仅显示指定状态码 (逗号分隔)")
    p.add_argument("--exclude-status", default="404", help="排除指定状态码 (默认: 404)")
    p.add_argument("--min-length", type=int, default=0, help="最小响应体长度")
    p.add_argument("--match", default=None, help="仅显示匹配该正则的内容")
    p.add_argument("--filter", default=None, help="排除匹配该正则的内容")

    # port — 端口扫描
    p = subs.add_parser("port", help="TCP 端口扫描 + 服务识别")
    _common(p)
    p.add_argument("--port-list", default=None, help="自定义端口列表文件")
    p.add_argument("--port-timeout", type=float, default=2.0, help="端口超时秒数 (默认: 2)")
    p.add_argument("--port-speed", type=int, default=200, help="端口并发数 (默认: 200)")

    # finger — 指纹识别
    p = subs.add_parser("finger", help="Web 技术栈指纹识别")
    _common(p)

    # batch — 批量扫描
    p = subs.add_parser("batch", help="批量扫描: 从文件读取多个目标，支持多进程并行")
    p.add_argument("-f", "--file", required=True, help="目标列表文件 (每行一个 URL)")
    _common(p, url_required=False)
    p.add_argument("-w", "--wordlist", default="default", help="词表")
    p.add_argument("-j", "--jobs", type=int, default=0, help="并行扫描任务数 (0=自动，默认按目标数量)")
    p.add_argument("-r", "--recursive", action="store_true", help="递归扫描")
    p.add_argument("--depth", type=int, default=1, help="递归深度 (默认: 1)")
    p.add_argument("--no-port", action="store_true", help="跳过端口扫描")
    p.add_argument("--no-analyze", action="store_true", help="跳过内容分析")

    # web — Web 控制面板
    p = subs.add_parser("web", help="启动 Web 控制面板 (黄客联盟)")
    p.add_argument("--host", default="127.0.0.1", help="监听地址 (默认: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="监听端口 (默认: 8080)")
    p.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")

    # info — 信息收集
    p = subs.add_parser("info", help="信息收集: WHOIS | DNS | SSL | 子域名")
    _common(p)

    return parser


# ═══════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════

def _make_engine(args) -> EngineConfig:
    return EngineConfig(
        timeout=args.timeout, delay=args.delay,
        max_concurrency=args.threads, proxy=args.proxy,
        user_agent=args.ua, verify_ssl=not args.no_verify,
    )


def _load_wordlist(wl_arg: str) -> list:
    valid = {"default", "common", "sensitive", "api", "tech", "vuln", "backup", "admin", "framework"}
    if wl_arg in valid:
        return load_default_wordlist() if wl_arg == "default" else load_wordlist(wl_arg)
    return load_wordlist(wl_arg)


def _parse_csv_int(s: str) -> list | None:
    if not s:
        return None
    return [int(x.strip()) for x in s.split(",") if x.strip().isdigit()]


def _save_report(filepath: str, scan_results: list, fingerprint_info, content_findings,
                 target_url: str, elapsed: float):
    ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
    if ext == "html":
        save_html(filepath, scan_results, fingerprint_info, content_findings, target_url, elapsed)
    elif ext == "csv":
        save_csv(filepath, scan_results, fingerprint_info, content_findings, target_url, elapsed)
    elif ext == "md":
        save_markdown(filepath, scan_results, fingerprint_info, content_findings, target_url, elapsed)
    else:
        save_json(filepath, scan_results, fingerprint_info, content_findings, target_url, elapsed)
    console.print(f"\n  [green]报告已保存:[/green] {filepath}")


# ═══════════════════════════════════════════════
# 自动化功能 — 配置 / JSON 输出 / Webhook / CI
# ═══════════════════════════════════════════════

def load_scan_config(config_path: str) -> dict:
    """从 JSON 或 YAML 文件加载扫描配置。"""
    import json
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"配置文件不存在: {config_path}")
    with open(path, "r", encoding="utf-8") as f:
        ext = path.suffix.lower()
        if ext in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(f)
            except ImportError:
                console.print("  [red]需要安装 PyYAML: pip install pyyaml[/red]")
                sys.exit(1)
        else:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("配置文件格式错误: 需要 JSON 对象或 YAML 映射")
    return data


def _send_webhook(url: str, payload: dict) -> None:
    """异步发送 webhook POST 请求 (fire-and-forget)。"""
    try:
        import aiohttp
        import asyncio
        async def _post():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        pass  # Webhook errors are silently ignored
            except Exception:
                pass
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(_post())
        else:
            # No running loop — schedule for when loop starts
            loop.create_task(_post())
    except Exception:
        pass


def _serialize_result(scan_results: list, fingerprint_info, content_findings: list,
                      port_results: list, target_url: str, elapsed: float,
                      scan_type: str = "", error: str = "") -> dict:
    """将扫描结果序列化为可 JSON 序列化的 dict。"""
    import json
    from datetime import datetime

    def _sev_dict(s):
        return {"label": s.label, "score": s.score, "color": s.color} if hasattr(s, "label") else {"label": str(s)}

    def _fp_dict(fp):
        if fp is None:
            return None
        return {
            "server": fp.server or "",
            "page_title": fp.page_title or "",
            "powered_by": fp.powered_by or "",
            "generator": fp.generator or "",
            "ip": fp.ip or "",
            "technologies": [
                {"category": t.category, "name": t.name, "evidence": t.evidence, "confidence": t.confidence}
                for t in getattr(fp, "technologies", [])
            ],
            "waf": [{"name": w.name, "evidence": w.evidence} for w in getattr(fp, "waf", [])],
            "cdn": [{"name": c.name, "evidence": c.evidence} for c in getattr(fp, "cdn", [])],
            "security_headers": getattr(fp, "security_headers", {}),
            "cookies": getattr(fp, "cookies", {}),
        }

    result = {
        "tool": "huangke",
        "version": "3.1.0",
        "target": target_url,
        "scan_type": scan_type,
        "elapsed": round(elapsed, 2),
        "timestamp": datetime.now().isoformat(),
    }

    if error:
        result["error"] = error

    result["results"] = {}
    if scan_results is not None:
        result["results"]["scan_results"] = [
            {
                "path": r.path, "url": r.url, "status": r.status,
                "content_type": r.content_type, "content_length": r.content_length,
                "severity": _sev_dict(r.severity),
                "risk_desc": r.risk_desc, "service": getattr(r, "service", ""),
                "body_preview": r.body_preview[:200] if r.body_preview else "",
            }
            for r in sorted(scan_results, key=lambda x: x.severity.score, reverse=True)
        ]

    if port_results is not None:
        result["results"]["port_results"] = [
            {"port": r.port, "service": r.service, "state": r.state,
             "banner": r.banner[:120] if r.banner else "",
             "severity": _sev_dict(r.severity), "risk_desc": r.risk_desc}
            for r in sorted(port_results, key=lambda x: x.severity.score, reverse=True)
        ]

    if fingerprint_info is not None:
        result["results"]["fingerprint"] = _fp_dict(fingerprint_info)

    if content_findings is not None:
        result["results"]["content_findings"] = [
            {"type": f.finding_type, "detail": f.detail, "severity": _sev_dict(f.severity), "url": f.url}
            for f in sorted(content_findings, key=lambda x: x.severity.score, reverse=True)
        ]

    # Summary
    sr = scan_results or []
    pr = port_results or []
    cf = content_findings or []
    fi = fingerprint_info
    high_risk = sum(1 for r in sr if r.severity.score >= 4) + sum(1 for r in pr if r.severity.score >= 4)
    high_risk += sum(1 for f in cf if f.severity.score >= 4)
    medium_risk = sum(1 for r in sr if r.severity.score == 3) + sum(1 for r in pr if r.severity.score == 3)
    medium_risk += sum(1 for f in cf if f.severity.score == 3)

    result["summary"] = {
        "endpoints_found": len(sr),
        "open_ports": len(pr),
        "technologies": len(fi.technologies) if fi else 0,
        "findings": len(cf),
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "page_title": fi.page_title if fi else "",
        "server": fi.server if fi else "",
    }
    return result


async def run_config_mode(config: dict, cli_args: argparse.Namespace) -> dict:
    """按配置文件定义运行扫描任务 — 自动化入口。"""
    import json
    targets = config.get("targets", [])
    if not targets:
        console.print("  [red]配置文件中没有定义 targets[/red]")
        return {"batch_results": []}

    # 合并配置与 CLI 参数 (配置为默认值，CLI 参数覆盖)
    json_mode = cli_args.json or config.get("json", False)
    webhook_url = cli_args.webhook or config.get("webhook")
    ci_mode = cli_args.ci or config.get("ci", False)
    global_output = config.get("output", cli_args.output)

    all_results = []
    total = len(targets)

    if json_mode:
        console.quiet = True

    console.print(f"\n  [bold cyan]自动化扫描[/bold cyan] — [green]{total}[/green] 个目标\n")

    for i, target_def in enumerate(targets, 1):
        url = target_def.get("url", "")
        scan_type = target_def.get("type", "full")
        if not url:
            continue
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # 合并配置层级: 全局配置 → 目标特定配置
        target_opts = {**{k: v for k, v in config.items() if k not in ("targets", "json", "webhook", "ci")}}
        target_opts.update({k: v for k, v in target_def.items() if k not in ("url", "type")})
        target_opts["url"] = url
        target_opts["output"] = target_opts.get("output") or global_output

        opts = ScanOptions(**{k: v for k, v in target_opts.items() if k in ScanOptions.__dataclass_fields__})

        console.print(f"  [bold][{i}/{total}] {url} ({scan_type})[/bold]")
        start = time.time()

        try:
            if scan_type == "scan":
                result = await run_scan(opts)
            elif scan_type == "port":
                result = await run_portscan(opts)
            elif scan_type == "finger":
                result = await run_fingerprint(opts)
            elif scan_type == "info":
                from .info.gather import InfoGatherer
                gatherer = InfoGatherer(url, timeout=opts.timeout, proxy=opts.proxy)
                info_result = await gatherer.gather_all()
                result = {"info_result": info_result.to_dict(), "scan_results": [],
                          "fingerprint": None, "content_findings": [], "port_results": []}
            else:
                result = await run_full(opts)

            elapsed = time.time() - start
            sr = result.get("scan_results", [])
            fi = result.get("fingerprint")
            cf = result.get("content_findings", [])
            pr = result.get("port_results", [])

            console.print(f"  [green]  ✓ 完成 ({elapsed:.1f}s) — 端点: {len(sr)} 端口: {len(pr)}[/green]")

            # 保存报告
            if opts.output:
                _save_report(opts.output, sr, fi, cf, url, elapsed)

            all_results.append({
                "target": url, "type": scan_type, "elapsed": elapsed,
                "result": result,
            })

            # Webhook (每完成一个目标发送一次)
            if webhook_url:
                payload = _serialize_result(sr, fi, cf, pr, url, elapsed, scan_type)
                _send_webhook(webhook_url, payload)

        except Exception as e:
            console.print(f"  [red]  ✗ 失败: {e}[/red]")
            all_results.append({"target": url, "type": scan_type, "error": str(e)})
            if webhook_url:
                _send_webhook(webhook_url, {"tool": "huangke", "target": url, "error": str(e)})

    # 汇总
    success = sum(1 for r in all_results if "error" not in r)
    console.print(f"\n  [bold green]自动化扫描完成[/bold green] — {success}/{total} 个成功\n")

    # JSON 模式: 输出完整结果到 stdout
    if json_mode:
        batch_payload = {
            "tool": "huangke",
            "version": "3.1.0",
            "mode": "config",
            "config_file": cli_args.config,
            "timestamp": __import__("datetime").datetime.now().isoformat(),
            "summary": {"total": total, "success": success, "failed": total - success},
            "results": [{
                "target": r["target"], "type": r.get("type"),
                "elapsed": r.get("elapsed", 0), "error": r.get("error", ""),
            } for r in all_results],
        }
        print(json.dumps(batch_payload, ensure_ascii=False, indent=2))

    # CI 模式: 检测高危结果
    if ci_mode:
        has_high = False
        for r in all_results:
            res = r.get("result", {})
            for key in ("scan_results", "port_results", "content_findings"):
                for item in res.get(key, []):
                    if hasattr(item, "severity") and item.severity.score >= 4:
                        has_high = True
                        break
        if has_high:
            console.print("  [red]CI 模式: 检测到高危风险[/red]")

    return {"batch_results": all_results}


# ═══════════════════════════════════════════════
# 多进程扫描 Worker
# ═══════════════════════════════════════════════

def _batch_scan_worker(target: str, opts_dict: dict) -> dict:
    """多进程批量扫描 worker — 在子进程中独立运行完整扫描"""
    import asyncio
    import os
    import sys

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    from huangke.main import ScanOptions, run_full

    opts = ScanOptions(**opts_dict)
    opts.url = target

    # 在子进程中抑制输出 (rich console + stdout)
    from huangke.output.console import console
    console.quiet = True
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        with open(os.devnull, "w") as devnull:
            sys.stdout = devnull
            sys.stderr = devnull
            result = asyncio.run(run_full(opts))
            result["_target"] = target
            return result
    except Exception as e:
        return {"scan_results": [], "fingerprint": None,
                "content_findings": [], "port_results": [],
                "_target": target, "_error": str(e)}
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr


# ═══════════════════════════════════════════════
# 扫描执行器
# ═══════════════════════════════════════════════

async def run_scan(opts: ScanOptions):
    cfg = EngineConfig(
        timeout=opts.timeout, delay=opts.delay, max_concurrency=opts.threads,
        proxy=opts.proxy, user_agent=opts.ua, verify_ssl=not opts.no_verify,
    )
    wl = _load_wordlist(opts.wordlist)

    scfg = ScanConfig(
        recursive=opts.recursive, max_depth=opts.depth,
        include_status=_parse_csv_int(opts.include_status),
        exclude_status=_parse_csv_int(opts.exclude_status),
        min_content_length=opts.min_length,
        match_pattern=opts.match, filter_pattern=opts.filter,
    )

    print_banner_compact()
    console.print(f"\n  [bold cyan]目录扫描[/bold cyan]")
    console.print(f"  目标: [green]{opts.url}[/green]  ·  词表: [cyan]{len(wl)}[/cyan] 条  ·  并发: [cyan]{opts.threads}[/cyan]")
    if opts.delay:
        console.print(f"  延迟: [yellow]{opts.delay}s[/yellow]")
    console.print()

    async with HTTPEngine(cfg) as eng:
        scanner = DirectoryScanner(eng, opts.url, wl, config=scfg)
        await scanner.scan()
        print_scan_results(scanner.results, opts.url, verbose=opts.verbose)
        return {"scan_results": scanner.results}


async def run_portscan(opts: ScanOptions):
    from urllib.parse import urlparse
    parsed = urlparse(opts.url if "://" in opts.url else f"https://{opts.url}")
    host = parsed.hostname or opts.url

    if opts.port_list:
        with open(opts.port_list) as f:
            ports = [int(p.strip()) for p in f.read().replace("\n", ",").split(",") if p.strip().isdigit()]
    else:
        ports = TOP_PORTS

    print_banner_compact()
    console.print(f"\n  [bold cyan]TCP 端口扫描[/bold cyan]")
    console.print(f"  主机: [green]{host}[/green]  ·  端口数: [cyan]{len(ports)}[/cyan]  ·  超时: [cyan]{opts.port_timeout}s[/cyan]")
    console.print()

    scanner = PortScanner(host, ports=ports, timeout=opts.port_timeout, concurrency=opts.port_speed)
    await scanner.scan()
    print_port_results(scanner.results, host)
    return {"port_results": scanner.results}


async def run_fingerprint(opts: ScanOptions):
    cfg = EngineConfig(
        timeout=opts.timeout, delay=0, max_concurrency=5,
        proxy=opts.proxy, user_agent=opts.ua, verify_ssl=not opts.no_verify,
    )
    print_banner_compact()
    console.print(f"\n  [bold cyan]Web 指纹识别[/bold cyan]")
    console.print(f"  目标: [green]{opts.url}[/green]")
    console.print()

    async with HTTPEngine(cfg) as eng:
        fp = WebFingerprinter(eng, opts.url)
        info = await fp.fingerprint()
        print_fingerprint(info)
        return {"fingerprint": info}


async def run_full(opts: ScanOptions):
    """完整扫描: 目录 + 端口 + 指纹 + 内容分析 — 独立引擎每个阶段"""
    cfg = EngineConfig(
        timeout=opts.timeout, delay=opts.delay, max_concurrency=opts.threads,
        proxy=opts.proxy, user_agent=opts.ua, verify_ssl=not opts.no_verify,
    )
    wl = _load_wordlist(opts.wordlist)

    print_banner()
    console.print(f"  目标: [bold green]{opts.url}[/bold green]  ·  词表: [cyan]{len(wl)}[/cyan] 条  ·  并发: [cyan]{opts.threads}[/cyan]")
    if opts.delay:
        console.print(f"  延迟: [yellow]{opts.delay}s[/yellow]")
    console.print()

    total_phases = 4 - sum([opts.no_analyze, opts.no_port, opts.no_finger])
    phase = 0
    scan_results, port_results, fp_info, content_findings = [], [], None, []

    # Phase 1: 目录扫描 — 专属引擎
    phase += 1
    console.print(f"  [bold cyan]>>> 阶段 {phase}/{total_phases}: 目录扫描[/bold cyan]\n")
    try:
        async with HTTPEngine(cfg) as eng:
            scfg = ScanConfig(recursive=opts.recursive, max_depth=opts.depth)
            sc = DirectoryScanner(eng, opts.url, wl, config=scfg)
            await sc.scan()
            scan_results = sc.results
            print_scan_results(scan_results, opts.url, verbose=opts.verbose)
    except Exception as e:
        console.print(f"  [red]目录扫描失败: {e}[/red]")

    # Phase 2: 端口扫描 — 独立引擎 (raw sockets)
    if not opts.no_port:
        phase += 1
        console.print(f"\n  [bold cyan]>>> 阶段 {phase}/{total_phases}: TCP 端口扫描[/bold cyan]\n")
        try:
            from urllib.parse import urlparse
            host = urlparse(opts.url if "://" in opts.url else f"https://{opts.url}").hostname or opts.url
            ports = None
            if opts.port_list:
                with open(opts.port_list) as f:
                    ports = [int(p.strip()) for p in f.read().replace("\n", ",").split(",") if p.strip().isdigit()]
            else:
                ports = TOP_PORTS
            ps = PortScanner(host, ports=ports, timeout=min(opts.timeout * 0.3, 2.0))
            await ps.scan()
            port_results = ps.results
            print_port_results(port_results, host)
        except Exception as e:
            console.print(f"  [red]端口扫描失败: {e}[/red]")

    # Phase 3: 指纹识别 — 新引擎
    if not opts.no_finger:
        phase += 1
        console.print(f"\n  [bold cyan]>>> 阶段 {phase}/{total_phases}: Web 指纹识别[/bold cyan]\n")
        try:
            fp_cfg = EngineConfig(
                timeout=opts.timeout, delay=0, max_concurrency=5,
                proxy=opts.proxy, user_agent=opts.ua, verify_ssl=not opts.no_verify,
            )
            async with HTTPEngine(fp_cfg) as eng:
                fp = WebFingerprinter(eng, opts.url)
                fp_info = await fp.fingerprint()
                print_fingerprint(fp_info)
        except Exception as e:
            console.print(f"  [red]指纹识别失败: {e}[/red]")

    # Phase 4: 内容分析 — 新引擎
    if not opts.no_analyze and scan_results:
        phase += 1
        console.print(f"\n  [bold cyan]>>> 阶段 {phase}/{total_phases}: 页面内容分析[/bold cyan]\n")
        try:
            ca_cfg = EngineConfig(
                timeout=opts.timeout, delay=opts.delay, max_concurrency=opts.threads,
                proxy=opts.proxy, user_agent=opts.ua, verify_ssl=not opts.no_verify,
            )
            async with HTTPEngine(ca_cfg) as eng:
                urls = [opts.url]
                for r in scan_results:
                    if r.status == 200 and r.severity.score >= 3:
                        urls.append(r.url)
                uniq = list(dict.fromkeys(urls))
                az = ContentAnalyzer(eng, opts.url)
                await az.analyze_urls(uniq[:50])
                content_findings = az.all_findings()
                print_analysis(content_findings)
                if az.is_rate_limited:
                    console.print("  [yellow]检测到速率限制 (429 状态码)[/yellow]")
        except Exception as e:
            console.print(f"  [red]内容分析失败: {e}[/red]")

    return {
        "scan_results": scan_results,
        "fingerprint": fp_info,
        "content_findings": content_findings,
        "port_results": port_results,
    }


async def run_batch(opts: ScanOptions):
    """批量扫描文件中的多个目标 — 支持多进程并行加速"""
    file_path = opts.url  # Reuse url field for batch file path
    if not os.path.exists(file_path):
        console.print(f"\n  [red]文件不存在: {file_path}[/red]")
        return

    with open(file_path, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    if not targets:
        console.print("\n  [red]目标文件中没有找到有效 URL[/red]")
        return

    # Normalize targets
    norm_targets = []
    for t in targets:
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        norm_targets.append(t)

    jobs = opts.jobs
    if jobs <= 0:
        jobs = min(4, len(norm_targets))
    use_mp = jobs > 1

    console.print(f"\n  [bold cyan]批量扫描[/bold cyan] — 共 [bold green]{len(norm_targets)}[/bold green] 个目标"
                  f"{'  ·  并行: [cyan]' + str(jobs) + '[/cyan] 进程' if use_mp else ''}")
    console.print()

    all_results = []

    if not use_mp:
        # ── 顺序扫描 (原始行为) ──
        for i, target in enumerate(norm_targets, 1):
            console.print(f"\n  [bold]── [{i}/{len(norm_targets)}] {target} ──[/bold]\n")
            batch_opts = ScanOptions(
                url=target, wordlist=opts.wordlist, threads=opts.threads,
                delay=opts.delay, timeout=opts.timeout, proxy=opts.proxy,
                verbose=opts.verbose, recursive=opts.recursive, depth=opts.depth,
                no_analyze=opts.no_analyze, no_port=opts.no_port,
                ua=opts.ua, no_verify=opts.no_verify,
            )
            try:
                result = await run_full(batch_opts)
                all_results.append({"target": target, "result": result})
            except Exception as e:
                console.print(f"  [red]扫描失败: {e}[/red]")
                continue
    else:
        # ── 多进程并行扫描 ──
        from concurrent.futures import ProcessPoolExecutor
        import asyncio

        # Build serializable options dict for worker processes
        opts_dict = {
            "wordlist": opts.wordlist, "threads": opts.threads,
            "delay": opts.delay, "timeout": opts.timeout,
            "proxy": opts.proxy, "verbose": opts.verbose,
            "recursive": opts.recursive, "depth": opts.depth,
            "no_analyze": opts.no_analyze, "no_port": opts.no_port,
            "no_finger": opts.no_finger,
            "ua": opts.ua, "no_verify": opts.no_verify,
        }

        loop = asyncio.get_event_loop()
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            futures = [
                loop.run_in_executor(executor, _batch_scan_worker, target, opts_dict)
                for target in norm_targets
            ]

            completed = 0
            for coro in asyncio.as_completed(futures):
                completed += 1
                try:
                    result = await coro
                    target = result.pop("_target", "")
                    error = result.pop("_error", None)
                    all_results.append({"target": target, "result": result})
                    status = "[red]失败" if error else "[green]✓"
                    label = f"({error})" if error else ""
                    console.print(f"  {status}[/] [{completed}/{len(norm_targets)}] {target} {label}")
                except Exception as e:
                    console.print(f"  [red]✗ [{completed}/{len(norm_targets)}] 进程异常: {e}[/red]")

    # ── 汇总 ──
    console.print(f"\n  [bold green]══════════════════════════════════════[/bold green]")
    console.print(f"  [bold]批量扫描完成[/bold] — {len(all_results)}/{len(norm_targets)} 个成功\n")
    for r in all_results:
        t = r["target"]
        sr = r["result"].get("scan_results", [])
        fi = r["result"].get("fingerprint")
        pr = r["result"].get("port_results", [])
        console.print(f"  [cyan]{t}[/cyan] — 端点: [green]{len(sr)}[/green]", end="")
        if fi and fi.page_title:
            console.print(f" | 标题: {fi.page_title}", end="")
        if fi and fi.waf:
            console.print(f" | WAF: [red]{len(fi.waf)}[/red]", end="")
        if pr:
            console.print(f" | 端口: [green]{len(pr)}[/green] 开放", end="")
        console.print()

    if opts.output:
        _save_report(opts.output, all_results, None, None, f"{len(targets)} 个目标", 0)

    return {"batch_results": all_results}


# ═══════════════════════════════════════════════
# 交互式菜单
# ═══════════════════════════════════════════════

def _input_url():
    while True:
        u = input("  [>] 目标 URL: ").strip()
        if u:
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            return u
        console.print("  [red]URL 不能为空[/red]")


def _ask(prompt, default=""):
    v = input(f"  [>] {prompt}" + (f" [默认:{default}]" if default else "") + ": ").strip()
    return v if v else default


def _ask_bool(prompt, default="n"):
    return _ask(f"{prompt} (y/n)", default).lower() == "y"


async def _menu_full():
    opts = ScanOptions(
        url=_input_url(),
        wordlist=_ask("词表 (default/common/sensitive/api/路径)", "default"),
        threads=int(_ask("并发数", "50") or "50"),
        delay=float(_ask("请求间隔/秒 (防封)", "0") or "0"),
        timeout=int(_ask("超时/秒", "10") or "10"),
        recursive=_ask_bool("递归扫描"),
        verbose=_ask_bool("显示响应预览"),
        no_analyze=_ask_bool("跳过内容分析"),
        no_port=_ask_bool("跳过端口扫描"),
        output=_ask("导出报告 (留空不保存，支持 .html/.json/.csv/.md)") or None,
    )
    console.print()
    result = await run_full(opts)
    result["_output"] = opts.output
    result["_url"] = opts.url
    return result


async def _menu_scan():
    opts = ScanOptions(
        url=_input_url(),
        wordlist=_ask("词表 (default/common/sensitive/api/路径)", "default"),
        threads=int(_ask("并发数", "50") or "50"),
        delay=float(_ask("请求间隔/秒", "0") or "0"),
        timeout=int(_ask("超时/秒", "10") or "10"),
        recursive=_ask_bool("递归扫描"),
        verbose=_ask_bool("显示响应预览"),
        output=_ask("导出报告 (留空不保存)") or None,
    )
    console.print()
    result = await run_scan(opts)
    result["_output"] = opts.output
    result["_url"] = opts.url
    return result


async def _menu_port():
    opts = ScanOptions(
        url=_input_url(),
        port_timeout=float(_ask("端口超时/秒", "2") or "2"),
        port_list=_ask("端口列表文件 (留空=默认 1000)") or None,
    )
    console.print()
    return await run_portscan(opts)


async def _menu_finger():
    opts = ScanOptions(
        url=_input_url(),
        timeout=int(_ask("超时/秒", "10") or "10"),
    )
    console.print()
    return await run_fingerprint(opts)


async def _menu_batch():
    opts = ScanOptions(
        url=_ask("目标列表文件路径 (每行一个URL)", "targets.txt"),
        wordlist=_ask("词表", "default"),
        threads=int(_ask("并发数", "50") or "50"),
        delay=float(_ask("请求间隔/秒 (防封)", "0") or "0"),
        timeout=int(_ask("超时/秒", "10") or "10"),
        jobs=int(_ask("并行进程数 (0=自动)", "4") or "4"),
        output=_ask("导出报告 (留空不保存)") or None,
    )
    console.print()
    return await run_batch(opts)


async def _menu_info():
    opts = ScanOptions(
        url=_input_url(),
        timeout=int(_ask("超时/秒", "10") or "10"),
        proxy=_ask("代理地址 (留空=无)") or None,
    )
    console.print()
    try:
        from .info.gather import InfoGatherer, InfoResult
        gatherer = InfoGatherer(opts.url, timeout=opts.timeout, proxy=opts.proxy)
        console.print(f"  [bold cyan]>>> 信息收集: {opts.url}[/bold cyan]\n")
        result = await gatherer.gather_all()
        result.display(console)
    except ImportError as e:
        console.print(f"  [red]信息收集模块不可用: {e}[/red]")
    except Exception as e:
        console.print(f"  [red]信息收集失败: {e}[/red]")


async def interactive_mode():
    while True:
        console.clear()
        print_menu()
        try:
            ch = input("  黄客联盟 > ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n  [dim]已退出[/dim]")
            break

        if ch == "0":
            console.clear()
            console.print("\n  [cyan]黄客联盟 · 感谢使用[/cyan]\n")
            break

        # ── 选项 5-9：独立输出 + 统一错误处理 ──
        if ch in ("5", "6", "7", "8", "9"):
            console.clear()
            try:
                if ch == "5":
                    await _menu_batch()
                elif ch == "6":
                    print_banner_compact()
                    console.print("\n  [bold cyan]启动 Web 控制面板...[/bold cyan]\n")
                    try:
                        from .web.server import start_web_server
                        await start_web_server(open_browser=True)
                    except ImportError:
                        console.print("  [red]Web 模块不可用，请确保 aiohttp 已安装[/red]")
                elif ch == "7":
                    print_usage_guide()
                elif ch == "8":
                    print_about()
                elif ch == "9":
                    await _menu_info()
            except Exception as e:
                console.print(f"\n  [red]操作执行失败: {e}[/red]")
            input("\n  按回车返回...")
            continue

        # ── 选项 1-4：扫描任务 + 结果汇总 ──
        start = time.time()
        try:
            if ch == "1":
                result = await _menu_full()
            elif ch == "2":
                result = await _menu_scan()
            elif ch == "3":
                result = await _menu_port()
            elif ch == "4":
                result = await _menu_finger()
            else:
                console.print(f"  [red]无效选择: {ch}, 请输入 0-9[/red]")
                await asyncio.sleep(1)
                continue
        except Exception as e:
            console.print(f"\n  [red]扫描执行失败: {e}[/red]")
            input("  按回车返回...")
            continue

        elapsed = time.time() - start
        sr = result.get("scan_results", [])
        fi = result.get("fingerprint")
        cf = result.get("content_findings", [])
        pr = result.get("port_results", [])
        out = result.get("_output", "")
        target = result.get("_url", "")

        if out and target:
            _save_report(out, sr, fi, cf, target, elapsed)

        if any([sr, fi, cf, pr]):
            print_summary(sr, fi, cf, elapsed)
            if pr:
                console.print(f"  开放端口: [green]{len(pr)}[/green]")
        input("\n  按回车返回...")


# ═══════════════════════════════════════════════
# CLI 入口
# ═══════════════════════════════════════════════

async def main_async():
    if len(sys.argv) == 1:
        _check_dependencies()
        print_banner()
        await asyncio.sleep(0.3)
        await interactive_mode()
        return

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print_usage_guide()
        return

    parser = build_parser()
    args = parser.parse_args()

    # ── 配置文件模式 (无子命令) ──
    if args.config and not args.command:
        config = load_scan_config(args.config)
        if "targets" in config:
            await run_config_mode(config, args)
            return
        console.print("  [red]配置文件中未定义 targets，请添加扫描目标[/red]")
        return

    if not args.command:
        parser.print_help()
        return

    # ── 自动化标志 ──
    json_mode = getattr(args, "json", False)
    webhook_url = getattr(args, "webhook", None)
    ci_mode = getattr(args, "ci", False)

    if json_mode:
        console.quiet = True

    opts = ScanOptions(
        url=getattr(args, "url", ""),
        wordlist=getattr(args, "wordlist", "default"),
        threads=getattr(args, "threads", 50),
        delay=getattr(args, "delay", 0),
        timeout=getattr(args, "timeout", 10),
        proxy=getattr(args, "proxy", None),
        verbose=getattr(args, "verbose", False),
        recursive=getattr(args, "recursive", False),
        depth=getattr(args, "depth", 2),
        ua=getattr(args, "ua", None),
        no_verify=getattr(args, "no_verify", False),
        output=getattr(args, "output", None),
        no_analyze=getattr(args, "no_analyze", False),
        no_port=getattr(args, "no_port", False),
        no_finger=getattr(args, "no_finger", False),
        port_list=getattr(args, "port_list", None),
        port_timeout=getattr(args, "port_timeout", 2.0),
        port_speed=getattr(args, "port_speed", 200),
        include_status=getattr(args, "include_status", None),
        exclude_status=getattr(args, "exclude_status", None),
        min_length=getattr(args, "min_length", 0),
        match=getattr(args, "match", None),
        filter=getattr(args, "filter", None),
        jobs=getattr(args, "jobs", 0),
    )

    start = time.time()
    scan_results, fingerprint_info, content_findings, port_results = [], None, [], []
    scan_error = None

    try:
        if args.command == "scan":
            r = await run_scan(opts)
            scan_results = r.get("scan_results", [])

        elif args.command == "port":
            r = await run_portscan(opts)
            port_results = r.get("port_results", [])

        elif args.command == "finger":
            r = await run_fingerprint(opts)
            fingerprint_info = r.get("fingerprint")

        elif args.command == "full":
            r = await run_full(opts)
            scan_results = r.get("scan_results", [])
            fingerprint_info = r.get("fingerprint")
            content_findings = r.get("content_findings", [])
            port_results = r.get("port_results", [])

        elif args.command == "batch":
            opts.url = args.file
            await run_batch(opts)
            return

        elif args.command == "web":
            from .web.server import start_web_server
            await start_web_server(
                host=args.host, port=args.port,
                open_browser=not args.no_browser,
            )
            return

        elif args.command == "info":
            from .info.gather import InfoGatherer
            gatherer = InfoGatherer(opts.url, timeout=opts.timeout, proxy=opts.proxy)
            if not json_mode:
                print_banner_compact()
                console.print(f"\n  [bold cyan]信息收集: {opts.url}[/bold cyan]\n")
            result = await gatherer.gather_all()
            if json_mode:
                print(__import__("json").dumps(
                    _serialize_result([], None, [], [], opts.url, time.time() - start, "info"),
                    ensure_ascii=False, indent=2,
                ))
            else:
                result.display(console)
            return

    except Exception as e:
        scan_error = str(e)
        if json_mode:
            print(__import__("json").dumps(
                _serialize_result([], None, [], [], opts.url, time.time() - start, args.command, str(e)),
                ensure_ascii=False, indent=2,
            ))
        else:
            console.print(f"\n  [red]扫描失败: {e}[/red]")
        sys.exit(2)

    elapsed = time.time() - start
    target_url = getattr(args, "url", "")

    # ── JSON 输出模式 ──
    if json_mode:
        payload = _serialize_result(
            scan_results, fingerprint_info, content_findings, port_results,
            target_url, elapsed, args.command,
        )
        print(__import__("json").dumps(payload, ensure_ascii=False, indent=2))

    # ── 控制台输出 (非 JSON 模式) ──
    else:
        if any([scan_results, fingerprint_info, content_findings, port_results]):
            print_summary(scan_results, fingerprint_info, content_findings, elapsed)
            if port_results:
                console.print(f"  开放端口: [green]{len(port_results)}[/green]")

    # ── 保存报告 ──
    if opts.output and target_url:
        _save_report(opts.output, scan_results, fingerprint_info, content_findings,
                     target_url, elapsed)

    # ── Webhook ──
    if webhook_url:
        payload = _serialize_result(
            scan_results, fingerprint_info, content_findings, port_results,
            target_url, elapsed, args.command, scan_error or "",
        )
        _send_webhook(webhook_url, payload)

    # ── CI 模式退出码 (在 main() 中处理) ──
    if ci_mode and any([
        any(r.severity.score >= 4 for r in (scan_results or [])),
        any(r.severity.score >= 4 for r in (port_results or [])),
        any(f.severity.score >= 4 for f in (content_findings or [])),
    ]):
        sys.exit(1)


def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
