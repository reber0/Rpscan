# Rpscan

### 功能
* 解析目标 ip
* 识别存活主机
* 端口扫描
  * async tcp 扫描存活主机端口
  * masscan 扫描存活主机端口
* 服务识别

### 安装必要模块
* 安装 nmap [(Download)](https://nmap.org/dist/?C=M&O=D)
* 安装 winpcap [(Download)](https://www.winpcap.org/install/default.htm)
* pip3 install -r requirements

### 参数
```
usage: portscan.py [-h] [-i TARGET] [-iL TARGET_FILENAME] [-st {tcp,masscan}]
                   [-t THREAD] [-r RATE] [-c] [-a] [-s]

optional arguments:
  -h, --help           show this help message and exit
  -i TARGET            Target(1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-4)
  -iL TARGET_FILENAME  Target file name
  -st {tcp,masscan}    Port scan type, default is masscan
  -t THREAD            The number of threads, default is 30 threads
  -r RATE              Port scan rate, default is 2000
  -a                   Is full port scanning, default is False
  -s                   Whether to get port service, default is True
  -c                   Check host is alive before port scan, default is True
```

### 使用
```
➜  python3 portscan.py -i 59.108.35.198 -st tcp -s
[16:15:34] [INFO] [*] Check Live Host...
[16:15:34] [INFO] all host: 1, live host: 1
[16:15:34] [INFO] [*] PortScan...
[16:15:34] [INFO] start async tcp port scan...
[16:15:34] [INFO] 59.108.35.198    22     open
[16:15:34] [INFO] 59.108.35.198    80     open
[16:15:39] [INFO] [*] Get the service of the port...
[16:15:45] [INFO] 59.108.35.198    22     open      ssh             OpenSSH                       6.6.1p1 Ubuntu 2ubuntu2.11
[16:15:45] [INFO] 59.108.35.198    80     open      http            Apache httpd                  2.4.7
```
