#!/usr/bin/env python3
"""
目录/文件扫描模块
使用字典爆破目标网站的隐藏路径

原理：
1. 加载字典文件（或使用内置默认字典）
2. 对每个路径构造完整 URL（如 http://a.com/admin）
3. 发送 HTTP GET 请求，检查响应状态码
4. 200 → 存在且可访问
5. 301/302 → 存在（重定向）
6. 403 → 存在但禁止访问
7. 404 → 不存在
"""

import requests                # 发送 HTTP 请求
import threading               # 提供线程锁
from urllib.parse import urljoin  # URL 拼接
from concurrent.futures import ThreadPoolExecutor, as_completed  # 多线程
import sys
import time

# 控制台颜色（ANSI 转义序列）
# 让不同状态码显示不同颜色，方便快速识别
GREEN = '\033[92m'      # 200 成功 → 绿色
RED = '\033[91m'        # 错误/500 → 红色
YELLOW = '\033[93m'     # 301/302 重定向 → 黄色
BLUE = '\033[94m'       # 401/403 权限类 → 蓝色
RESET = '\033[0m'       # 重置为默认颜色


class DirScanner:
    """
    目录扫描器类
    
    核心功能：
    1. 加载字典（从文件或内置）
    2. 多线程并发扫描
    3. 收集并显示可访问路径
    
    使用示例：
        scanner = DirScanner("http://127.0.0.1", "payloads/dirs.txt", threads=10)
        results = scanner.scan()
        for r in results:
            print(f"{r['status']}  {r['path']}")
    """

    def __init__(self, base_url, wordlist_path, threads=10, timeout=5, verbose=False):
        """
        构造函数：初始化扫描器
        
        参数说明：
            base_url:      目标网站根地址，如 http://127.0.0.1
            wordlist_path: 字典文件路径，如 payloads/dirs.txt
            threads:       线程数，默认 10
            timeout:       每个请求的超时时间（秒），默认 5
            verbose:       是否打印详细输出，默认 False
        """
        # rstrip('/') 去掉末尾斜杠，避免拼接时出现双斜杠
        # 例如 "http://a.com/" + "/admin" → "http://a.com//admin"（错误）
        # 去掉后 "http://a.com" + "/admin" → "http://a.com/admin"（正确）
        self.base_url = base_url.rstrip('/')
        
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        
        # 创建 requests Session
        # 相当于一个"浏览器会话"，复用 TCP 连接，速度更快
        self.session = requests.Session()
        
        # 设置 User-Agent，伪装成真实的浏览器
        # 有些网站会检测 UA，如果是爬虫就拒绝访问
        self.session.headers.update({
            'User-Agent': 'CyberEagle-Scanner/0.2.0 (https://github.com/yukon61/CyberEagle-Scanner)'
        })
        
        # 存储扫描结果
        self.results = []
        
        # 线程锁：防止多个线程同时修改 results 列表导致数据混乱
        # 相当于 C 语言的 pthread_mutex_t
        self.lock = threading.Lock()

    def load_wordlist(self):
        """
        加载字典文件，返回路径列表
        
        流程：
        1. 尝试打开字典文件
        2. 读取每一行，去掉首尾空白
        3. 跳过空行和注释行（以 # 开头）
        4. 如果文件不存在，使用内置默认字典
        
        返回：
            list[str]: 路径列表
        """
        try:
            # with open(...) as f: 自动管理文件生命周期，离开代码块自动关闭文件
            # 相当于 C 语言的 FILE* f = fopen(...); ... fclose(f);
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                # 列表推导式（Python 特色语法）
                # 等价于 C 语言：
                #   for (i=0; i<总行数; i++) {
                #       line = 读取一行;
                #       if (line 不为空 && line 不以 # 开头) {
                #           去掉首尾空格;
                #           放入数组;
                #       }
                #   }
                words = [
                    line.strip()                      # 去掉首尾空格和换行符
                    for line in f                     # 遍历文件的每一行
                    if line.strip() and not line.strip().startswith('#')
                    # 条件1：去掉空格后还有内容（非空行）
                    # 条件2：不以 # 开头（# 开头视为注释，跳过）
                ]
            return words
            
        except FileNotFoundError:
            # 文件不存在 → 使用内置字典，并打印提示
            print(f"[!] 字典文件 '{self.wordlist_path}' 不存在，使用内置默认字典（100条）")
            return self._get_default_wordlist()

    def _get_default_wordlist(self):
        """
        内置默认字典（当外部字典文件不存在时使用）
        
        包含约 100 条常用路径：
        - 后台目录: admin, login, dashboard
        - 配置文件: .env, .git, config.php
        - 备份文件: backup.zip, backup.sql
        - 敏感路径: logs, tmp, upload
        - 开发路径: dev, test, stage
        - 框架目录: vendor, node_modules, themes
        """
        return [
            # ---- 常见后台目录 ----
            'admin', 'login', 'wp-admin', 'administrator', 'manage', 'manager',
            'dashboard', 'panel', 'control', 'system', 'backend', 'cms',
            
            # ---- API 相关 ----
            'api', 'v1', 'v2', 'v3', 'version', 'test', 'tests', 'testing',
            
            # ---- 开发环境 ----
            'dev', 'development', 'stage', 'staging', 'prod', 'production',
            
            # ---- 常见文件 ----
            'index.php', 'index.html', 'index.htm', 'default.php', 'default.html',
            'robots.txt', 'sitemap.xml', 'sitemap.txt', 'crossdomain.xml',
            'phpinfo.php', 'php.ini', '.htaccess', '.htpasswd', 'web.config',
            
            # ---- 备份文件 ----
            'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'dump.sql',
            'www.zip', 'site.zip', 'web.tar.gz', 'old.zip',
            
            # ---- 配置文件 ----
            '.env', '.env.example', '.git', '.gitignore', '.svn', '.DS_Store',
            'config.php', 'config.ini', 'settings.php', 'conf.php',
            
            # ---- 敏感路径 ----
            'logs', 'log', 'logs/access.log', 'log/error.log',
            'tmp', 'temp', 'cache', 'sessions',
            'upload', 'uploads', 'files', 'downloads', 'download',
            
            # ---- 静态资源 ----
            'images', 'img', 'css', 'js', 'assets', 'static', 'media',
            
            # ---- 框架/第三方库 ----
            'vendor', 'node_modules', 'bower_components',
            'themes', 'plugins', 'modules', 'includes', 'inc',
            'app', 'src', 'lib', 'libs', 'core', 'common',
            
            # ---- 错误页面 ----
            'error', '404', '403', '500',
            
            # ---- 后台登录 ----
            'admin/login.php', 'admin/index.php', 'admin/dashboard.php',
            'wp-login.php', 'wp-admin/index.php', 'wp-admin/admin-ajax.php',
            
            # ---- 服务端状态 ----
            'server-status', 'server-info', 'phpmyadmin', 'pma', 'myadmin',
            'mysql', 'sql', 'database', 'db',
            
            # ---- 其他 ----
            'api/v1/users', 'api/v1/auth', 'graphql', 'swagger', 'docs',
            '.well-known', 'well-known', 'acme-challenge'
        ]

    def check_path(self, path):
        """
        检测单个路径是否可访问
        
        这个函数会被多个线程并行调用，每个线程负责一个路径。
        
        参数：
            path: 路径字符串，如 "admin"
            
        返回：
            tuple: (path, status_code, content_length, error)
            - path: 路径本身
            - status_code: HTTP 状态码（如 200, 404），None 表示出错
            - content_length: 响应体长度（字节），0 表示出错
            - error: 错误信息字符串，None 表示没有错误
        """
        # 拼接完整 URL
        # urljoin 自动处理斜杠，避免手写出错
        # 例如：base_url="http://a.com", path="/admin" → "http://a.com/admin"
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        
        try:
            # 发送 GET 请求
            # timeout: 如果 5 秒内没收到响应，抛出 Timeout 异常
            # allow_redirects=False: 不自动跟随重定向
            #   我们想要看原始状态码（302 重定向），而不是跳转后的页面（200）
            resp = self.session.get(
                url, 
                timeout=self.timeout, 
                allow_redirects=False
            )
            
            # 返回结果
            # status_code: 200, 301, 302, 403, 404, 500 等
            # len(resp.content): 响应体的字节长度，可用于辅助判断
            return (path, resp.status_code, len(resp.content), None)
            
        except requests.exceptions.Timeout:
            # 超时：对方没响应，可能不存在也可能网络慢
            return (path, None, 0, '超时')
            
        except requests.exceptions.ConnectionError:
            # 连接错误：无法到达目标，比如端口没开
            return (path, None, 0, '连接失败')
            
        except Exception as e:
            # 捕获所有其他异常，防止单个路径崩溃影响整体扫描
            return (path, None, 0, f'错误: {str(e)[:30]}')

    def _should_display(self, status):
        """
        判断是否应该显示该状态码
        
        只显示有分析价值的响应：
        - 200/201/204: 成功访问
        - 301/302/303/307/308: 重定向（说明路径存在）
        - 401: 需要认证（说明路径存在）
        - 403: 禁止访问（说明路径存在）
        - 500: 服务器错误（说明路径存在，但出错了）
        
        不显示 404（不存在）和 其他无意义的状态码
        """
        if status is None:
            return False
        return status in [200, 201, 204, 301, 302, 303, 307, 308, 401, 403, 500]

    def _get_status_color(self, status):
        """
        根据状态码返回对应的 ANSI 颜色代码
        """
        if status is None:
            return RED
        if status == 200:
            return GREEN       # 成功 → 绿色
        if status in [301, 302, 303, 307, 308]:
            return YELLOW      # 重定向 → 黄色
        if status in [401, 403]:
            return BLUE        # 权限类 → 蓝色
        if status >= 500:
            return RED         # 服务器错误 → 红色
        return RESET

    def scan(self):
        """
        执行扫描，返回结果列表
        
        这是核心方法，流程如下：
        1. 加载字典（获得要扫描的所有路径）
        2. 创建线程池（控制并发数）
        3. 提交所有任务到线程池
        4. 等待任务完成，收集结果
        5. 打印扫描结果和统计信息
        
        返回：
            list[dict]: 每个元素包含 path, status, length, url
        """
        # ---- 第1步：加载字典 ----
        wordlist = self.load_wordlist()
        total = len(wordlist)
        
        # 打印扫描配置信息
        print(f"\n[+] 加载字典: {total} 条路径")
        print(f"[+] 目标: {self.base_url}")
        print(f"[+] 线程数: {self.threads}")
        print(f"[+] 超时: {self.timeout}s")
        print("-" * 60)

        results = []     # 存储有效结果
        completed = 0    # 已完成的任务数（用于进度显示）

        # ---- 第2步：创建线程池 ----
        # ThreadPoolExecutor: 创建指定数量的线程，自动管理生命周期
        # with 语句：离开代码块时自动等待所有任务完成并清理
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            
            # ---- 第3步：提交所有任务 ----
            # executor.submit(self.check_path, path): 提交一个任务
            # 返回一个 Future 对象（任务回执）
            # as_completed() 按完成顺序返回 Future，谁先完谁先回
            futures = {executor.submit(self.check_path, path): path for path in wordlist}
            # 这里是字典推导式：
            #   for path in wordlist:
            #       future = executor.submit(self.check_path, path)
            #       futures[future] = path

            # ---- 第4步：收集结果 ----
            for future in as_completed(futures):
                completed += 1
                path, status, length, err = future.result()

                # 每 20 个任务打印一次进度
                if self.verbose or completed % 20 == 0:
                    # \r: 回车符，回到行首覆盖上一行
                    print(f"\r进度: {completed}/{total} ({int(completed/total*100)}%)", end='', flush=True)

                # 如果有错误，根据 verbose 决定是否显示
                if err:
                    if self.verbose:
                        print(f"\n  ❌ {path} -> {err}")
                    continue

                # 如果状态码有分析价值，记录并显示
                if self._should_display(status):
                    color = self._get_status_color(status)
                    status_str = f"{color}{status}{RESET}"
                    
                    if self.verbose:
                        print(f"\n  {status_str}  {path}  (长度: {length})")
                    else:
                        print(f"{status_str}  {path}  (长度: {length})")

                    results.append({
                        'path': path,
                        'status': status,
                        'length': length,
                        'url': urljoin(self.base_url + '/', path.lstrip('/')),
                        'details': f'状态码: {status}',
                        'param': path,
                        'payload': path
                    })

        # ---- 第5步：打印总结 ----
        print("\n" + "-" * 60)
        print(f"[+] 扫描完成！共发现 {len(results)} 个可访问路径")
        return results


# 独立运行测试
if __name__ == "__main__":
    scanner = DirScanner(
        base_url="http://127.0.0.1",
        wordlist_path="payloads/dirs.txt",
        threads=10,
        verbose=True
    )
    results = scanner.scan()
    for r in results:
        print(f"  {r['status']}  {r['path']}")
