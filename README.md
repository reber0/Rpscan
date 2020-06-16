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

* 服务识别

### 安装必要模块
* 安装 nmap [(Download)](https://nmap.org/dist/?C=M&O=D)

* 如果是 win 的话安装 winpcap [(Download)](https://www.winpcap.org/install/default.htm)

* pip3 install -r requirements.txt

### 参数
```
➜  python3 rpscan.py -h
usage: rpscan.py [-h] [-i TARGET] [-iL TARGET_FILENAME] [-st {tcp,masscan,nmap}] 
                 [-t THREAD] [-r RATE] [-p PORTS] [-c] [-a] [-s]

optional arguments:
  -h, --help            show this help message and exit
  -i TARGET             Target(1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-4)
  -iL TARGET_FILENAME   Target file name
  -st {tcp,masscan,nmap}
                        Port scan type, default is masscan
  -t THREAD             The number of threads, default is 30 threads
  -r RATE               Port scan rate, default is 1000
  -p PORTS              Ports to be scanned, example: 22,23,80,3306
  -c                    Check host is alive before port scan, default is False
  -a                    Full port scan, default is False, scan common ports
  -s                    Whether to get port service, default is False

Examples:
  python3 rpscan.py -i 192.168.1.1/24 -c -s
  python3 rpscan.py -iL target.txt -st masscan -r 3000 -c -a -s
```

### 使用
```
➜  python3 rpscan.py -iL target.txt -st tcp -p22,80,3306,3389 -t 1 -s
2020-06-17 00:34:56,891 [port scan] [*] Start async tcp port scan...
2020-06-17 00:34:56,895 [port scan] 192.168.1.1      80     open
2020-06-17 00:35:01,893 [port scan] [*] Get the service of the port...
2020-06-17 00:35:08,127 [port scan] 192.168.1.1      80     open      http
```

### 引用
将源码放到 src 中，然后将 src 添加到 sys.path

```
[18:02 reber@wyb at ~/Downloads/tmp]
➜  ls
src     test.py
[18:02 reber@wyb at ~/Downloads/tmp]
➜  ls src
Rpscan
```

test.py 内容: 

```
import sys
import pathlib
root_abspath = pathlib.Path(__file__).parent.resolve()
module_path = root_abspath.joinpath("src")

sys.path.append(str(module_path))

from Rpscan import CheckHostLive
chl = CheckHostLive(ip_list=["59.108.123.123"])
live_host = chl.run()
print(live_host)

from Rpscan import PortScan
ps = PortScan(ip_list=['59.108.123.123'], all_ports=False, rate=2000)
port_open_dict = ps.masscan_scan()
port_open_dict = ps.async_tcp_port_scan()
print(port_open_dict)

from pprint import pprint
from Rpscan import NmapGetPortService
ngps = NmapGetPortService(ip_port_dict={'59.108.123.123': [80, 22]}, thread_num=10)
port_service_list = ngps.run()
pprint.pprint(a)
```
