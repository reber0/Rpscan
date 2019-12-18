#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-05-23 09:52:13
@LastEditTime: 2019-12-13 10:39:40
'''

import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

from libs.check_host_live import CheckHostLive
from libs.port_scan import PortScan
from libs.get_service import NmapGetPortService
from libs.util import ParseTarget

def main(args):
    pt = ParseTarget()
    if args.target:
        ip_list = pt.parse_target(args.target)
    elif args.target_filename:
        target_list = [line.strip() for line in open(args.target_filename).readlines()]
        ip_list = pt.parse_target(target_list)

    if args.checklive:
        chl = CheckHostLive(ip_list=ip_list)
        live_host = chl.run()
        # live_host = chl.live_host
        # print("All Host: {}, Live Host: {}".format(len(ip_list),len(live_host)))
    else:
        live_host = ip_list

    if len(live_host)<1:
        exit()

    if args.scantype == "masscan":
        ps = PortScan(ip_list=live_host, all_ports=args.is_all_ports, rate=args.rate)
        port_open_dict = ps.masscan_scan()
    elif args.scantype == "tcp":
        ps = PortScan(ip_list=live_host, all_ports=args.is_all_ports, rate=args.rate)
        port_open_dict = ps.async_tcp_port_scan()

    if args.service and len(port_open_dict)>0:
        #对扫描出来的端口进行服务识别后写入数据库
        ngps = NmapGetPortService(ip_port_dict=port_open_dict, thread_num=args.thread)
        port_service_list = ngps.run()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(add_help=True)
    # parser.description = "端口扫描及服务识别"
    parser.add_argument("-i", dest="target", type=str, 
                        help="Target(1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-4)")
    parser.add_argument("-iL", dest="target_filename", type=str, 
                        help="Target file name")
    parser.add_argument("-st", dest="scantype", type=str, default="masscan", 
                        choices=["tcp","masscan"], help="Port scan type, default is masscan")
    parser.add_argument("-t", dest="thread", type=int, default=30, 
                        help="The number of threads, default is 30 threads")
    parser.add_argument("-r", dest="rate", type=int, default=1000, 
                        help="Port scan rate, default is 1000")
    parser.add_argument("-c", dest="checklive", default=False, 
                        action="store_true", help="Check host is alive before port scan, default is False")
    parser.add_argument("-a", dest="is_all_ports", default=False, 
                        action="store_true", help="Is full port scanning, default is False")
    parser.add_argument("-s", dest="service", default=False, 
                        action="store_true", help="Whether to get port service, default is False")

    args = parser.parse_args()

    if args.target or args.target_filename:
        main(args)
    else:
        parser.print_help()
