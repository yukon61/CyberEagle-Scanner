#!/usr/bin/env python3
"""
CyberEagle-Scanner - 轻量级 Web 漏洞扫描器
支持：目录扫描、SQL注入、XSS、命令注入、MQTT检测
"""

import argparse
import sys
import logging
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


def banner():
    """打印项目 Banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║      CyberEagle-Scanner v0.2.0                               ║
    ║      轻量级 Web 漏洞扫描器                                   ║
    ║      支持: 目录扫描 | SQL注入 | XSS | 命令注入 | MQTT        ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="CyberEagle-Scanner - 轻量级 Web 漏洞扫描器",
        epilog="示例: python main.py -u http://127.0.0.1 --dir --sqli"
    )

    # 必选参数：目标 URL
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="目标 URL（如 http://127.0.0.1）"
    )

    # 模块开关（使用 store_true 表示 flag 参数）
    parser.add_argument(
        "--dir", action="store_true",
        help="启用目录/文件扫描"
    )
    parser.add_argument(
        "--sqli", action="store_true",
        help="启用 SQL 注入检测"
    )
    parser.add_argument(
        "--xss", action="store_true",
        help="启用 XSS 检测"
    )
    parser.add_argument(
        "--cmd", action="store_true",
        help="启用命令注入检测"
    )
    parser.add_argument(
        "--mqtt", action="store_true",
        help="启用 MQTT 弱口令/匿名访问检测"
    )

    # 通用参数
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="线程数（默认 10）"
    )
    parser.add_argument(
        "-o", "--output",
        help="输出报告的文件路径"
    )
    parser.add_argument(
        "--cookie",
        help="手动指定 Cookie 字符串（如 'PHPSESSID=xxx; security=low'）"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="显示详细输出"
    )

    # 便捷参数：一键全开
    parser.add_argument(
        "--all", action="store_true",
        help="启用所有检测模块（等价于 --dir --sqli --xss --cmd --mqtt）"
    )

    return parser.parse_args()


def run_scanners(args):
    """
    根据用户选择的模块调用相应的扫描函数
    """
    url = args.url.rstrip('/')
    threads = args.threads
    verbose = args.verbose

    # 如果启用了 --all，自动开启所有模块
    if args.all:
        args.dir = args.sqli = args.xss = args.cmd = args.mqtt = True

    logger.info(f"目标 URL: {url}")
    logger.info(f"线程数: {threads}")
    logger.info("=" * 60)


    # ========== 解析 --cookie 参数 ==========
    cookies = None
    if args.cookie:
        try:
            # 解析 "key1=value1; key2=value2" 格式
            cookies = {}
            for item in args.cookie.split(';'):
                item = item.strip()
                if '=' in item:
                    k, v = item.split('=', 1)
                    cookies[k.strip()] = v.strip()
            logger.info(f"[*] 使用自定义 Cookie: {cookies}")
        except Exception as e:
            logger.warning(f"解析 Cookie 失败: {e}，将不使用 Cookie")
    # ========================================


    if args.dir:
        logger.info("[*] 开始目录扫描...")
        try:
            from scanner.dir_scanner import DirScanner
            scanner = DirScanner(
                    base_url=url,
                    wordlist_path="payloads/dirs.txt",
                    threads=threads,
                    verbose=verbose
            )
            results = scanner.scan()
            # 保存结果到全局，供后续报告使用
            if hasattr(args, '_results'):
                    args._results['dir'] = results
            else:
                    args._results = {'dir': results}
        except ImportError:
            logger.error("目录扫描模块导入失败，请检查 scanner/dir_scanner.py")
        except Exception as e:
            logger.error(f"目录扫描失败: {e}")




    if args.sqli:
        logger.info("[*] 开始 SQL 注入检测...")
        try:
            from scanner.sqli_scanner import SQLiScanner
            scanner = SQLiScanner(
                    base_url=url,
                    threads=threads,
                    timeout=5,
                    verbose=verbose,
                    delay=0.1,
                    cookies=cookies
            )
            results = scanner.scan()
            if hasattr(args, '_results'):
                    args._results['sqli'] = results
            else:
                    args._results = {'sqli': results}
        except ImportError as e:
            logger.error(f"SQL注入模块导入失败: {e}")
        except Exception as e:
            logger.error(f"SQL注入检测失败: {e}")


    if args.xss:
        logger.info("[*] 开始 XSS 检测...")
        try:
            from scanner.xss_scanner import XSSScanner
            scanner = XSSScanner(
                base_url=url,
                threads=threads,
                timeout=5,
                verbose=verbose,
                delay=0.1,
                cookies=cookies
            )
            results = scanner.scan()
            if hasattr(args, '_results'):
                args._results['xss'] = results
            else:
                args._results = {'xss': results}
        except ImportError as e:
            logger.error(f"XSS模块导入失败: {e}")
        except Exception as e:
            logger.error(f"XSS检测失败: {e}")


    if args.cmd:
        logger.info("[*] 开始命令注入检测...")
        try:
            from scanner.cmd_scanner import CmdScanner
            scanner = CmdScanner(
                base_url=url,
                threads=threads,
                timeout=5,
                verbose=verbose,
                delay=0.1,
                cookies=cookies
            )
            results = scanner.scan()
            if hasattr(args, '_results'):
                args._results['cmd'] = results
            else:
                args._results = {'cmd': results}
        except ImportError as e:
            logger.error(f"命令注入模块导入失败: {e}")
        except Exception as e:
            logger.error(f"命令注入检测失败: {e}")



def main():
    args = parse_arguments()

    # 显示 Banner
    banner()

    # 如果启用 verbose，调整日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 执行扫描
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
