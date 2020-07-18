#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-05-23 09:52:13
@LastEditTime : 2020-07-19 02:59:44
'''
import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

from libs.util import get_content
from libs.initialize import init_config
from libs.initialize import init_cmd_args
from libs.data import config

from modules.check_live import CheckHostLive
from modules.get_service import NmapGetPortService
from modules.masscan_s import MasscanScan
from modules.async_s import AsyncTcpScan
from modules.nmap_s import NmapScan


def main():
    # 引入配置文件中的配置
    init_config("config.py")

    # 解析命令行参数
    init_cmd_args()

    # 检测存活 ip
    if config.checklive:
        chl = CheckHostLive(ip_list=config.ip_list)
        config.target_host = chl.run()
    else:
        config.target_host = config.ip_list
    if len(config.target_host) < 1:
        exit()

    # print(config.target_host)
    # exit()

    # 端口扫描
    if config.scantype == "masscan":
        m_scan = MasscanScan()
        open_port_dict = m_scan.run()
    elif config.scantype == "nmap":
        n_scan = NmapScan()
        open_port_dict = n_scan.run()
    elif config.scantype == "tcp":
        a_scan = AsyncTcpScan()
        open_port_dict = a_scan.run()

    # 对扫描出来的端口进行服务识别
    if config.get_service and len(open_port_dict) > 0:
        ngps = NmapGetPortService(ip_port_dict=open_port_dict)
        port_service_list = ngps.run()




if __name__ == "__main__":
    main()
