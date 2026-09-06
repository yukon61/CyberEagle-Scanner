#!/usr/bin/env python3
"""
CyberEagle-Scanner - 轻量级 Web 漏洞扫描器
支持：目录扫描、SQL注入、XSS、命令注入、MQTT检测
"""

import argparse
import sys
import logging
import json
import os
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def banner():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║      CyberEagle-Scanner v0.3.0                               ║
    ║      轻量级 Web 漏洞扫描器                                   ║
    ║      支持: 目录扫描 | SQL注入 | XSS | 命令注入 | MQTT        ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="CyberEagle-Scanner - 轻量级 Web 漏洞扫描器",
        epilog="示例: python main.py -u http://127.0.0.1 --dir --sqli"
    )
    parser.add_argument("-u", "--url", required=True, help="目标 URL")
    parser.add_argument("--dir", action="store_true", help="启用目录扫描")
    parser.add_argument("--sqli", action="store_true", help="启用 SQL 注入检测")
    parser.add_argument("--xss", action="store_true", help="启用 XSS 检测")
    parser.add_argument("--cmd", action="store_true", help="启用命令注入检测")
    parser.add_argument("-t", "--threads", type=int, default=10, help="线程数（默认10）")
    parser.add_argument("-o", "--output", help="报告输出路径（默认自动生成）")
    parser.add_argument("--cookie", help="手动指定 Cookie 字符串")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    parser.add_argument("--all", action="store_true", help="启用所有检测模块")
    parser.add_argument(
        "--mqtt", action="store_true",
        help="启用 MQTT 弱口令/匿名访问检测"
    )
    parser.add_argument(
        "--mqtt-host",
        help="MQTT Broker 地址（默认使用 -u 的主机部分）"
    )
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=1883,
        help="MQTT Broker 端口（默认 1883）"
    )
    return parser.parse_args()


def generate_report(all_results, url, output_path=None):
    """生成 TXT 和 HTML 报告"""
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"scan_report_{timestamp}"
    
    txt_path = f"{output_path}.txt"
    html_path = f"{output_path}.html"
    
    # ---- 统计漏洞总数 ----
    total_vulns = 0
    for module, results in all_results.items():
        if isinstance(results, dict):
            # MQTT 模块返回字典
            if results.get('anonymous'):
                total_vulns += 1
            total_vulns += len(results.get('weak_credentials', []))
        else:
            # 其他模块返回列表
            total_vulns += len(results)
    
    # ---- 生成 TXT 报告 ----
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("CyberEagle-Scanner 扫描报告\n")
        f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"目标 URL: {url}\n")
        f.write(f"发现漏洞总数: {total_vulns}\n")
        f.write("="*60 + "\n\n")
        
        for module, results in all_results.items():
            module_name = module.upper()
            if isinstance(results, dict):
                # ---- MQTT 模块 ----
                f.write(f"[{module_name}] 检测结果:\n")
                f.write(f"  匿名访问: {'开启 (高危)' if results.get('anonymous') else '关闭'}\n")
                weak = results.get('weak_credentials', [])
                if weak:
                    f.write(f"  弱口令: {len(weak)} 组\n")
                    for cred in weak:
                        f.write(f"    {cred[0]}:{cred[1]}\n")
                else:
                    f.write(f"  弱口令: 未发现\n")
                f.write("\n")
            else:
                # ---- 其他模块 ----
                f.write(f"[{module_name}] 共发现 {len(results)} 个漏洞\n")
                for idx, vuln in enumerate(results, 1):
                    f.write(f"  {idx}. {vuln.get('details', '')}\n")
                    f.write(f"     参数: {vuln.get('param', 'N/A')}\n")
                    f.write(f"     Payload: {vuln.get('payload', 'N/A')[:80]}\n")
                    f.write(f"     URL: {vuln.get('url', 'N/A')}\n\n")
    
    # ---- 生成 HTML 报告 ----
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>CyberEagle 扫描报告</title>
<style>
body {{ font-family: sans-serif; margin: 20px; }}
h1 {{ color: #2c3e50; }}
h2 {{ color: #34495e; border-bottom: 2px solid #3498db; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #2c3e50; color: white; }}
tr:nth-child(even) {{ background-color: #f2f2f2; }}
.summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
.vuln-count {{ font-weight: bold; color: #e74c3c; }}
code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
</style></head>
<body>
<h1>🦅 CyberEagle-Scanner 扫描报告</h1>
<div class="summary">
<p><strong>目标:</strong> {url}</p>
<p><strong>时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>漏洞总数:</strong> <span class="vuln-count">{total_vulns}</span></p>
</div>
<h2>漏洞详情</h2>
<table>
<tr><th>模块</th><th>详情</th></tr>
""")
        for module, results in all_results.items():
            if isinstance(results, dict):
                # ---- MQTT 模块 ----
                details = f"匿名访问: {'开启' if results.get('anonymous') else '关闭'}"
                weak = results.get('weak_credentials', [])
                if weak:
                    details += f", 弱口令: {', '.join([f'{u}:{p}' for u, p in weak])}"
                f.write(f"<tr><td>{module}</td><td>{details}</td></tr>")
            else:
                # ---- 其他模块 ----
                for vuln in results:
                    payload = vuln.get('payload', '')[:60]
                    f.write(f"<tr><td>{module}</td><td>{vuln.get('param','')}: {vuln.get('details','')} <code>{payload}</code></td></tr>")
        f.write("</table></body></html>")
    
    logger.info(f"✅ 报告已生成: {txt_path}, {html_path}")
    return txt_path, html_path


def run_scanners(args):
    url = args.url.rstrip('/')
    threads = args.threads
    verbose = args.verbose

    if args.all:
        args.dir = args.sqli = args.xss = args.cmd = args.mqtt = True

    # 解析 Cookie
    cookies = None
    if args.cookie:
        cookies = {}
        for item in args.cookie.split(';'):
            item = item.strip()
            if '=' in item:
                k, v = item.split('=', 1)
                cookies[k.strip()] = v.strip()
        logger.info(f"[*] 使用自定义 Cookie: {cookies}")

    logger.info(f"目标 URL: {url}")
    logger.info(f"线程数: {threads}")
    logger.info("=" * 60)

    all_results = {}

    # 各模块调用（仅当启用）
    if args.dir:
        logger.info("[*] 开始目录扫描...")
        try:
            from scanner.dir_scanner import DirScanner
            scanner = DirScanner(base_url=url, wordlist_path="payloads/dirs.txt",
                                 threads=threads, verbose=verbose)
            all_results['dir'] = scanner.scan()
        except Exception as e:
            logger.error(f"目录扫描失败: {e}")

    if args.sqli:
        logger.info("[*] 开始 SQL 注入检测...")
        try:
            from scanner.sqli_scanner import SQLiScanner
            scanner = SQLiScanner(base_url=url, threads=threads, timeout=5,
                                  verbose=verbose, delay=0.1, cookies=cookies)
            all_results['sqli'] = scanner.scan()
        except Exception as e:
            logger.error(f"SQL注入检测失败: {e}")

    if args.xss:
        logger.info("[*] 开始 XSS 检测...")
        try:
            from scanner.xss_scanner import XSSScanner
            scanner = XSSScanner(base_url=url, threads=threads, timeout=5,
                                 verbose=verbose, delay=0.1, cookies=cookies)
            all_results['xss'] = scanner.scan()
        except Exception as e:
            logger.error(f"XSS检测失败: {e}")

    if args.cmd:
        logger.info("[*] 开始命令注入检测...")
        try:
            from scanner.cmd_scanner import CmdScanner
            scanner = CmdScanner(base_url=url, threads=threads, timeout=5,
                                 verbose=verbose, delay=0.1, cookies=cookies)
            all_results['cmd'] = scanner.scan()
        except Exception as e:
            logger.error(f"命令注入检测失败: {e}")

    if args.mqtt:
        logger.info("[*] 开始 MQTT 检测...")
        try:
            from scanner.mqtt_scanner import MQTTScanner
        
            # 确定 MQTT 主机
            if args.mqtt_host:
                host = args.mqtt_host
            else:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                host = parsed.hostname or 'localhost'
        
            port = args.mqtt_port
        
            scanner = MQTTScanner(host, port)
            results = scanner.scan()
            all_results['mqtt'] = results
        except ImportError as e:
            logger.error(f"MQTT模块导入失败: {e}")
        except Exception as e:
            logger.error(f"MQTT检测失败: {e}")



    logger.info("=" * 60)
    logger.info("[+] 扫描完成！")

    # 生成报告
    if any(all_results.values()):
        output_path = args.output
        generate_report(all_results, url, output_path)
    else:
        logger.warning("未发现任何漏洞或没有启用模块")

    return all_results


def main():
    args = parse_arguments()
    banner()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        run_scanners(args)
    except KeyboardInterrupt:
        print("\n[!] 用户中断，退出...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"扫描过程中发生错误: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
