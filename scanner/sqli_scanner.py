#!/usr/bin/env python3
"""
SQL注入检测模块
支持三种检测方式：
1. 报错注入（Error-based）：通过数据库报错信息判断
2. 布尔盲注（Boolean-based）：通过页面内容/长度变化判断
3. 时间盲注（Time-based）：通过响应时间延迟判断
"""

import requests
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time
import re

# 控制台颜色
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'


class SQLiScanner:
    """
    SQL注入检测器类
    
    支持三种注入检测方式：
    1. 报错注入（Error-based）     → 适合有数据库错误回显的场景
    2. 布尔盲注（Boolean-based）   → 适合页面有内容/长度差异的场景
    3. 时间盲注（Time-based）      → 适合页面无任何差异的场景
    """

    def __init__(self, base_url, threads=10, timeout=5, verbose=False, delay=0.1,cookies=None):
        """
        初始化扫描器
        
        参数：
            base_url: 目标URL
            threads: 线程数
            timeout: 请求超时（秒）
            verbose: 是否显示详细输出
            delay: 每次请求间隔（秒），避免触发WAF
        """
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.delay = delay
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberEagle-Scanner/0.2.0 (https://github.com/yukon61/CyberEagle-Scanner)'
        })
        
        if cookies:
            self.session.cookies.update(cookies)
        
        self.results = []
        self.lock = threading.Lock()
        
        # ---------- SQL错误关键词（用于报错注入检测） ----------
        # 不同数据库的错误信息特征
        self.error_keywords = [
            # MySQL
            'SQL syntax', 'mysql_fetch', 'MySQLSyntaxErrorException',
            'You have an error in your SQL syntax',
            'Unclosed quotation mark',
            'Microsoft OLE DB Provider for ODBC Drivers',
            # PostgreSQL
            'PostgreSQL', 'psql: FATAL', 'ERROR:  syntax error',
            'org.postgresql.util.PSQLException',
            # Oracle
            'ORA-', 'Oracle Database', 'ORA-[0-9]{5}',
            # MSSQL
            'Microsoft OLE DB', 'SQL Server', 'Unclosed quotation mark',
            'System.Data.SqlClient.SqlException',
            # SQLite
            'SQLite', 'sqlite3.OperationalError',
            # 通用
            'sql error', 'database error', 'DB Error',
            'Warning: mysql', 'mysqli', 'PDOException'
        ]

    def get_url_params(self, url):
        """
        提取URL中的查询参数
        
        例如：http://a.com/page.php?id=1&name=test
        返回：{'id': '1', 'name': 'test'}
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # parse_qs 返回 {key: [value1, value2]}，我们取第一个值
        return {k: v[0] if v else '' for k, v in params.items()}

    def get_forms(self, url):
        """
        使用 BeautifulSoup 解析页面中的表单
        
        返回：表单列表，每个表单包含 action, method, inputs
        """
        try:
            resp = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                # 提取表单属性
                action = form.get('action', '')
                # 如果没有action，使用当前URL
                if not action:
                    action = url
                elif not action.startswith('http'):
                    # 相对路径 → 拼接完整URL
                    action = requests.compat.urljoin(url, action)
                
                method = form.get('method', 'get').lower()
                
                # 提取所有 input 字段
                inputs = []
                for inp in form.find_all('input'):
                    name = inp.get('name')
                    if name:
                        value = inp.get('value', '')
                        input_type = inp.get('type', 'text')
                        inputs.append({
                            'name': name,
                            'value': value,
                            'type': input_type
                        })
                
                # 提取 textarea
                for ta in form.find_all('textarea'):
                    name = ta.get('name')
                    if name:
                        inputs.append({
                            'name': name,
                            'value': '',
                            'type': 'textarea'
                        })
                
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                    'original_url': url
                })
            
            return forms
        except Exception as e:
            if self.verbose:
                print(f"[!] 解析表单失败: {e}")
            return []

    def build_payload_url(self, url, param, payload):
        """
        构造带 payload 的测试 URL
        
        例如：
            url = "http://a.com/page.php?id=1"
            param = "id"
            payload = "'"
            → "http://a.com/page.php?id='"
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

    def contains_error(self, text):
        """
        检查响应内容是否包含数据库错误关键词
        """
        text_lower = text.lower()
        for keyword in self.error_keywords:
            if keyword.lower() in text_lower:
                return True
        # 正则匹配（如 ORA-数字）
        if re.search(r'ORA-[0-9]{5}', text):
            return True
        return False

    # ==================== 第3天：报错注入检测 ====================
    
    def is_vulnerable_by_error(self, url, param):
        """
        报错注入检测
        
        原理：向参数注入特殊字符（', ", ), --），
        如果页面返回了SQL错误信息，说明存在报错注入。
        """
        # 常用报错注入 Payload
        payloads = [
            "'",                      # 单引号闭合
            '"',                      # 双引号闭合
            "')",                     # 单引号+括号闭合
            '")',                     # 双引号+括号闭合
            "' OR 1=1-- ",            # 布尔注入（触发报错）
            "' OR '1'='1'-- ",        # 布尔注入（另一种形式）
            "' UNION SELECT NULL-- ",  # 联合查询（触发列数错误）
            "' AND 1=1-- ",           # 恒真条件
            "' AND 1=2-- ",           # 恒假条件
            "';-- ",                  # 语句终止
            "'/*",                    # 注释符
            "1'",                     # 数字+单引号
            "1' AND '1'='1",          # 经典测试
        ]
        
        for payload in payloads:
            # 构造测试 URL
            test_url = self.build_payload_url(url, param, payload)
            
            # 添加延迟，防止触发WAF
            time.sleep(self.delay)
            
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                
                # 检查响应是否包含错误关键词
                if self.contains_error(resp.text):
                    return True, payload, test_url
                    
            except Exception as e:
                if self.verbose:
                    print(f"  [调试] {param}={payload} 请求失败: {e}")
                continue
        
        return False, None, None

    # ==================== 第4天：布尔盲注检测 ====================
    
    def is_vulnerable_boolean(self, url, param):
        """
        布尔盲注检测
        
        原理：
        1. 发送两个请求：一个恒真条件（1=1），一个恒假条件（1=2）
        2. 比较两个响应的长度（或内容）
        3. 如果差异明显，说明存在布尔盲注
        """
        # 构建恒真和恒假的 payload
        # 注意：这里假设参数是数字型注入，如果是字符型需要加引号
        true_payloads = [
            "1 AND 1=1",           # 数字型
            "1' AND '1'='1",       # 字符型（单引号）
            '1" AND "1"="1',       # 字符型（双引号）
        ]
        false_payloads = [
            "1 AND 1=2",
            "1' AND '1'='2",
            '1" AND "1"="2',
        ]
        
        for i in range(len(true_payloads)):
            true_payload = true_payloads[i]
            false_payload = false_payloads[i]
            
            # 构造两个测试 URL
            true_url = self.build_payload_url(url, param, true_payload)
            false_url = self.build_payload_url(url, param, false_payload)
            
            time.sleep(self.delay)
            
            try:
                resp_true = self.session.get(true_url, timeout=self.timeout)
                time.sleep(self.delay)
                resp_false = self.session.get(false_url, timeout=self.timeout)
                
                # 比较响应长度
                len_true = len(resp_true.text)
                len_false = len(resp_false.text)
                
                # 如果长度差异超过 10% 或绝对差值 > 50，认为存在盲注
                if abs(len_true - len_false) > 50:
                    return True, true_payload, true_url, len_true, len_false
                if len_true > 0 and len_false > 0:
                    if abs(len_true - len_false) / max(len_true, len_false) > 0.1:
                        return True, true_payload, true_url, len_true, len_false
                        
            except Exception as e:
                if self.verbose:
                    print(f"  [调试] 布尔盲注测试失败: {e}")
                continue
        
        return False, None, None, None, None

    # ==================== 第4天：时间盲注检测 ====================
    
    def is_vulnerable_time(self, url, param, sleep_seconds=5):
        """
        时间盲注检测
        
        原理：注入 sleep(5) 等延时函数，
        如果响应时间超过 sleep 时间，说明存在时间盲注。
        """
        # 时间盲注 Payload（MySQL）
        time_payloads = [
            f"1 AND SLEEP({sleep_seconds})",
            f"1' AND SLEEP({sleep_seconds})-- ",
            f'1" AND SLEEP({sleep_seconds})-- ',
            f"1' OR SLEEP({sleep_seconds})-- ",
            f"1' AND (SELECT * FROM (SELECT(SLEEP({sleep_seconds})))a)-- ",
            f"1' AND (SELECT SLEEP({sleep_seconds}))-- ",
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
                    print(f"  [调试] 时间盲注测试失败: {e}")
                continue
        
        return False, None, None, None

    # ==================== 主扫描函数 ====================
    
    def scan(self):
        """
        执行完整的 SQL 注入扫描
        
        流程：
        1. 提取 URL 中的查询参数
        2. 对每个参数依次执行三种检测：
           - 报错注入（Error-based）
           - 布尔盲注（Boolean-based）
           - 时间盲注（Time-based）
        3. 输出检测结果
        """
        print(f"\n[+] 开始 SQL 注入检测")
        print(f"[+] 目标: {self.base_url}")
        print(f"[+] 线程数: {self.threads}")
        print("-" * 60)
        
        # ---- 第1步：提取 URL 参数 ----
        params = self.get_url_params(self.base_url)
        if not params:
            print("[!] 未检测到 URL 参数，尝试解析页面表单...")
            forms = self.get_forms(self.base_url)
            if forms:
                print(f"[+] 发现 {len(forms)} 个表单")
                # TODO: 后续支持表单注入
            print("[!] 当前仅支持 URL 参数检测")
            return []
        
        print(f"[+] 发现 {len(params)} 个 URL 参数: {list(params.keys())}")
        
        results = []
        
        # ---- 第2步：对每个参数进行检测 ----
        for param, value in params.items():
            print(f"\n[*] 测试参数: {param} = {value}")
            
            # ---------- 报错注入检测 ----------
            print("  [->] 报错注入检测...", end='', flush=True)
            is_vuln, payload, test_url = self.is_vulnerable_by_error(self.base_url, param)
            if is_vuln:
                print(f" {GREEN}✅ 发现报错注入!{RESET}")
                results.append({
                    'type': 'error-based',
                    'param': param,
                    'payload': payload,
                    'url': test_url,
                    'details': '数据库错误信息被回显'
                })
                continue  # 已发现漏洞，跳过其他检测（可选）
            else:
                print(" ❌ 未发现")

            # ---------- 布尔盲注检测 ----------
            print("  [->] 布尔盲注检测...", end='', flush=True)
            is_vuln, payload, test_url, len_true, len_false = self.is_vulnerable_boolean(self.base_url, param)
            if is_vuln:
                print(f" {GREEN}✅ 发现布尔盲注!{RESET}")
                print(f"      恒真响应长度: {len_true}, 恒假响应长度: {len_false}")
                results.append({
                    'type': 'boolean-based',
                    'param': param,
                    'payload': payload,
                    'url': test_url,
                    'details': f'长度差异: {abs(len_true - len_false)}'
                })
                continue
            else:
                print(" ❌ 未发现")

            # ---------- 时间盲注检测 ----------
            print("  [->] 时间盲注检测...", end='', flush=True)
            is_vuln, payload, test_url, elapsed = self.is_vulnerable_time(self.base_url, param)
            if is_vuln:
                print(f" {GREEN}✅ 发现时间盲注!{RESET}")
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
        print(f"[+] SQL注入检测完成！共发现 {len(results)} 个疑似漏洞")
        
        for r in results:
            print(f"  {GREEN}✅{RESET} [{r['type']}] {r['param']} -> {r['details']}")
        
        return results


# ==================== 独立测试 ====================
if __name__ == "__main__":
    # 测试1：DVWA（本地）
    scanner = SQLiScanner(
        base_url="http://127.0.0.1/vulnerabilities/sqli/?id=1&Submit=Submit",
        verbose=True
    )
    results = scanner.scan()
