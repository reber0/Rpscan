#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-05-23 09:52:13
@LastEditTime : 2020-07-28 09:32:22
'''
import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

import pathlib
from libs.data import config
from libs.initialize import set_path


def main():
    # 设置路径
    root_abspath = pathlib.Path(__file__).parent.resolve()  #绝对路径
    set_path(root_abspath)

    # 初始化，主要是导入配置文件、解析命令行参数
    from libs.initialize import init_options
    init_options()

    from modules.check_live import CheckHostLive
    from modules.get_service import NmapGetPortService
    from modules.masscan_s import MasscanScan
    from modules.async_s import AsyncTcpScan
    from modules.nmap_s import NmapScan

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
