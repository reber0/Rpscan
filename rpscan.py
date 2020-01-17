#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-05-23 09:52:13
@LastEditTime: 2020-01-18 02:37:12
'''
import sys
sys.dont_write_bytecode = True  # 不生成pyc文件
from libs.util import get_content
from libs.parse import Parser
from libs.parse import ParseTarget
from libs.check_host_live import CheckHostLive
from libs.port_scan import PortScan
from libs.get_service import NmapGetPortService


def main():
    args = Parser().init()
    # print(args)

    pt = ParseTarget()
    if args.get("target"):
        ip_list = pt.parse_target(args.get("target"))
    elif args.get("target_filename"):
        target_list = get_content(args.get("target_filename"))
        ip_list = pt.parse_target(target_list)

    if args.get("checklive"):
        chl = CheckHostLive(ip_list=ip_list)
        live_host = chl.run()
        print("All Host: {}, Live Host: {}".format(
            len(ip_list), len(live_host)))
    else:
        live_host = ip_list

    if len(live_host) < 1:
        exit()

    if args.get("scantype") == "masscan":
        ps = PortScan(ip_list=live_host, all_ports=args.get(
            "is_all_ports"), rate=args.get("rate"))
        port_open_dict = ps.masscan_scan()
    elif args.get("scantype") == "tcp":
        ps = PortScan(ip_list=live_host, all_ports=args.get(
            "is_all_ports"), rate=args.get("rate"))
        port_open_dict = ps.async_tcp_port_scan()

    if args.get("service") and len(port_open_dict) > 0:
        # 对扫描出来的端口进行服务识别后写入数据库
        ngps = NmapGetPortService(
            ip_port_dict=port_open_dict, thread_num=args.get("thread"))
        port_service_list = ngps.run()


if __name__ == "__main__":
    main()
