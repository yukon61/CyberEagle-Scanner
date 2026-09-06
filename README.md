# 🦅 CyberEagle-Scanner

> 轻量级 Web 安全扫描器 · 学习教育目的

一个基于 Python 3 的多线程 Web 漏洞扫描器，支持目录扫描、SQL 注入、XSS、命令注入和 MQTT 安全检测，自动生成 TXT + HTML 报告。

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)


## 📌 已实现功能

| 模块 | 参数 | 说明 |
|------|------|------|
| 📂 **目录扫描** | `--dir` | 基于字典的目录/文件爆破，多线程并发 |
| 🗄️ **SQL注入检测** | `--sqli` | 报错注入、布尔盲注、时间盲注三种检测方式 |
| 🔤 **XSS检测** | `--xss` | 反射型 XSS 检测，内置 22 种 Payload |
| 💻 **命令注入检测** | `--cmd` | 回显检测 + 延时检测（`sleep 5`） |
| 📡 **MQTT安全检测** | `--mqtt` | 匿名访问检测 + 弱口令爆破（新能源/物联网特色） |
| 📄 **报告生成** | 自动 | 生成 `TXT` + `HTML` 格式扫描报告 |


## 📦 安装

### 1. 克隆仓库

```bash
git clone https://github.com/yukon61/CyberEagle-Scanner.git
cd CyberEagle-Scanner
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

> ⚠️ **Kali 2026.2+ 注意事项**：
> 由于 Kali 默认启用 PEP 668 保护，建议使用以下方式安装 MQTT 依赖：
> ```bash
> # 方式一：使用 APT 安装（推荐）
> sudo apt install python3-paho-mqtt -y
> 
> # 方式二：使用虚拟环境
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt
> ```

### 3. 准备字典文件

```bash
# 确保 payloads/dirs.txt 存在
ls payloads/
```


## 🚀 使用方法

### 基础命令

```bash
# 目录扫描
python main.py -u http://127.0.0.1 --dir

# SQL注入检测（需要 Cookie 保持登录态）
python main.py -u "http://127.0.0.1/vulnerabilities/sqli/?id=1" --sqli --cookie "PHPSESSID=xxx; security=low"

# XSS 检测
python main.py -u "http://127.0.0.1/vulnerabilities/xss_r/?name=test" --xss --cookie "PHPSESSID=xxx; security=low"

# 命令注入检测
python main.py -u "http://127.0.0.1/vulnerabilities/exec/?ip=127.0.0.1" --cmd --cookie "PHPSESSID=xxx; security=low"

# MQTT 检测（本地 Mosquitto）
python main.py -u "http://127.0.0.1" --mqtt --mqtt-host localhost

# 一键全开（所有模块）
python main.py -u "http://127.0.0.1" --all -v --cookie "PHPSESSID=xxx; security=low"
```

### 命令行参数完整列表

| 参数 | 说明 |
|------|------|
| `-u, --url` | 目标 URL（必填） |
| `--dir` | 启用目录扫描 |
| `--sqli` | 启用 SQL 注入检测 |
| `--xss` | 启用 XSS 检测 |
| `--cmd` | 启用命令注入检测 |
| `--mqtt` | 启用 MQTT 安全检测 |
| `--mqtt-host` | MQTT Broker 地址（默认从 `-u` 提取主机部分） |
| `--mqtt-port` | MQTT 端口（默认 1883） |
| `--all` | 启用所有检测模块 |
| `-t, --threads` | 线程数（默认 10） |
| `--cookie` | 手动指定 Cookie 字符串（格式：`key1=value1; key2=value2`） |
| `-o, --output` | 报告文件前缀（默认自动生成时间戳） |
| `-v, --verbose` | 显示详细输出（DEBUG 日志） |

### 示例：完整扫描 DVWA

```bash
python main.py -u "http://127.0.0.1" --all -v --cookie "PHPSESSID=ti3e7vf88atue68l6roncrdjl5; security=low"
```


## 📄 扫描报告

扫描完成后会自动生成两份报告：

```
scan_report_20260906_034713.txt   # 文本格式（可读性好）
scan_report_20260906_034713.html  # HTML 格式（适合浏览器查看）
```

### TXT 报告示例

```
============================================================
CyberEagle-Scanner 扫描报告
扫描时间: 2026-09-06 03:47:13
目标 URL: http://127.0.0.1
发现漏洞总数: 3
============================================================

[DIR] 共发现 8 个漏洞
  1. 状态码: 200
     参数: robots.txt
     Payload: /robots.txt

[SQLI] 共发现 1 个漏洞
  1. 数据库错误信息被回显
     参数: id
     Payload: '

[MQTT] 检测结果:
  匿名访问: 开启 (高危)
  弱口令: 未发现
```


## 🗂️ 项目结构

```
CyberEagle-Scanner/
├── main.py                 # 主入口（argparse + 模块调度 + 报告生成）
├── scanner/
│   ├── __init__.py
│   ├── dir_scanner.py      # 目录扫描模块
│   ├── sqli_scanner.py     # SQL注入检测模块（报错/布尔/时间盲注）
│   ├── xss_scanner.py      # XSS检测模块（反射型，22种Payload）
│   ├── cmd_scanner.py      # 命令注入检测模块（回显/延时）
│   └── mqtt_scanner.py     # MQTT安全检测模块（匿名/弱口令）
├── payloads/
│   └── dirs.txt            # 目录字典文件
├── requirements.txt        # Python 依赖清单
└── README.md               # 项目文档
```


## 🔧 依赖清单

```
requests>=2.28.0
beautifulsoup4>=4.11.0
paho-mqtt>=1.6.0
tqdm>=4.64.0
```


## 🔒 免责声明

> ⚠️ **本工具仅供学习和授权测试使用。**
> 
> 未经授权对他人系统进行扫描测试属于违法行为。使用者需自行承担一切法律后果。请勿用于非法用途。


## 📚 学习目的

本项目是 Web 安全学习过程中的实践产出，用于巩固以下技能：

- Python 安全脚本编写
- 多线程扫描框架设计
- 常见 Web 漏洞检测原理（SQL注入、XSS、命令注入）
- MQTT 协议与物联网安全基础
- 命令行工具设计与报告生成


## 📌 更新日志

### v0.3.0 (2026-09-06)
- 🎉 新增 MQTT 安全检测模块（匿名访问 + 弱口令爆破）
- 📄 报告生成器兼容字典类型结果（MQTT 模块）
- 🐛 修复 `all_results` 未正确传递的问题
- 📝 更新 README 文档

### v0.2.0 (2026-09-05)
- 🎉 集成四个核心模块：目录扫描、SQL注入、XSS、命令注入
- 🚀 支持 `--all` 一键全开
- 📄 支持 TXT + HTML 双格式报告
- 🧵 多线程并发扫描

### v0.1.0 (2026-08-30)
- 🎉 项目初始化
- 🏗️ 基础框架搭建
- 📝 完善项目文档


## 👤 作者

- **yukon61** - [GitHub](https://github.com/yukon61)


## ⭐ 如果对你有帮助

如果这个项目对你有帮助，欢迎 Star ⭐ 支持！也欢迎提交 Issue 和 PR。
