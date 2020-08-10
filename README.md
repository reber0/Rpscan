<!--
 * @Author: reber
 * @Mail: reber0ask@qq.com
 * @Date: 2020-08-05 11:18:20
 * @LastEditTime : 2020-08-10 10:49:44
 -->
# Rportscan

[![platform](https://img.shields.io/static/v1?label=platform&message=macOS&color=172b43)](https://github.com/reber0/Rpscan/tree/master)
[![python](https://img.shields.io/static/v1?label=python&message=3.7&color=346fb0)](https://www.python.org/)
[![nmap](https://img.shields.io/static/v1?label=nmap&message=7.70&color=deecf5)](https://nmap.org/)
[![masscan](https://img.shields.io/static/v1?label=masscan&message=1.0.5&color=deecf5)](https://github.com/robertdavidgraham/masscan)
[![winpcap](https://img.shields.io/static/v1?label=winpcap&message=4.1.3&color=deecf5)](https://www.winpcap.org/install/default.htm)

### 功能

* 解析目标 ip

* 识别存活主机

* 端口扫描

  * async tcp 扫描存活主机端口

  * nmap 扫描存活主机端口(-sS, 使用sudo)

  * masscan 扫描存活主机端口

  * http 探测常见的 web 端口

* 服务识别

### 安装必要模块
* 安装 masscan [(Download)](https://github.com/robertdavidgraham/masscan)
    * 自带的有 mac 和 win 下编译好的 masscan 1.0.4，其它平台不能用的自行编译安装

* 安装 nmap [(Download)](https://nmap.org/dist/?C=M&O=D)
    * 如果是 win 的话安装 winpcap [(Download)](https://www.winpcap.org/install/default.htm)

* pip3 install -r requirements.txt

### 参数
```
➜  python3 rpscan.py -h                                              
usage: rpscan.py [-h] [-i TARGET] [-iL TARGET_FILENAME] [-c CONFIG_FILE]
                 [-st {tcp,masscan,nmap,http}] [-t THREAD] [-r RATE] [-p PORTS]
                 [-ck] [-a] [-s]

optional arguments:
  -h, --help            show this help message and exit
  -i TARGET             Target(1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-4)
  -iL TARGET_FILENAME   Target file name
  -c CONFIG_FILE        Config file, example: /usr/local/etc/rpscan.cfg
  -st {tcp,masscan,nmap,http}
                        Port scan type, default is masscan
  -t THREAD             The number of threads, default is 30 threads
  -r RATE               Port scan rate, default is 1000
  -p PORTS              Ports to be scanned, example: 22,23,80,3306
  -ck                   Check host is alive before port scan, default is False
  -a                    Full port scan, default is False, scan common ports
  -s                    Whether to get port service, default is False

Examples:
  python3 rpscan.py -i 192.168.1.1/24 -s -ck
  python3 rpscan.py -iL target.txt -st masscan -r 3000 -a -s -ck
```

### 使用
```
➜  python3 rpscan.py -iL target.txt -st tcp -p22,80,3306,3389 -t 1 -s
2020-06-17 00:34:56,891 [port scan] [*] Start async tcp port scan...
2020-06-17 00:34:56,895 [port scan] 192.168.1.1      80     open
2020-06-17 00:35:01,893 [port scan] [*] Get the service of the port...
2020-06-17 00:35:08,127 [port scan] 192.168.1.1      80     open      http
```
