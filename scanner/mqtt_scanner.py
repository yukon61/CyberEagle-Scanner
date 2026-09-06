#!/usr/bin/env python3
"""
MQTT 安全检测模块
支持两种检测方式：
1. 匿名访问检测
2. 弱口令爆破
"""

import paho.mqtt.client as mqtt
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'


class MQTTScanner:
    """
    MQTT 安全检测器类
    """

    def __init__(self, host, port=1883, timeout=3):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _try_connect(self, username=None, password=None):
        client = mqtt.Client()
        if username:
            client.username_pw_set(username, password)
        client.connect_timeout = self.timeout
        try:
            client.connect(self.host, self.port, 60)
            client.disconnect()
            return True
        except Exception:
            return False

    def check_anonymous(self):
        print(f"[*] 检测匿名访问: {self.host}:{self.port}")
        try:
            client = mqtt.Client()
            client.connect_timeout = self.timeout
            client.connect(self.host, self.port, 60)
            client.disconnect()
            print(f"  {GREEN}✅ 允许匿名连接{RESET}")
            return True
        except Exception as e:
            print(f"  ❌ 匿名连接失败: {e}")
            return False

    def check_weak_credentials(self, wordlist=None):
        if wordlist is None:
            wordlist = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('root', 'root'),
                ('root', 'password'),
                ('guest', 'guest'),
                ('user', 'user'),
                ('test', 'test'),
                ('mqtt', 'mqtt'),
                ('admin', ''),
                ('root', ''),
                ('', ''),
            ]
        print(f"[*] 弱口令检测（共 {len(wordlist)} 组）")
        found = []
        for username, password in wordlist:
            try:
                client = mqtt.Client()
                client.username_pw_set(username, password)
                client.connect_timeout = self.timeout
                client.connect(self.host, self.port, 60)
                client.disconnect()
                print(f"  {GREEN}✅ 发现弱口令: {username}:{password}{RESET}")
                found.append((username, password))
            except Exception:
                continue
        if not found:
            print("  ❌ 未发现弱口令")
        return found

    def scan(self):
        print(f"\n[+] 开始 MQTT 安全扫描")
        print(f"[+] 目标: {self.host}:{self.port}")
        print("-" * 60)

        results = {}
        anonymous = self.check_anonymous()
        results['anonymous'] = anonymous

        if not anonymous:
            weak = self.check_weak_credentials()
            results['weak_credentials'] = weak
        else:
            print("[*] 已发现匿名访问，跳过弱口令检测（匿名风险更高）")
            results['weak_credentials'] = []

        return results


if __name__ == "__main__":
    scanner = MQTTScanner("localhost", 1883)
    results = scanner.scan()
