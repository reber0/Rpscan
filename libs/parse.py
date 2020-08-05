#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-09-19 09:52:13
@LastEditTime : 2020-08-05 09:30:32
'''

import argparse
import re
import socket
from IPy import IP

from libs.util import file_is_exist
from libs.data import config

class ParserCmd(object):
    """ParserCmd"""

    def __init__(self):
        super(ParserCmd, self).__init__()
        self.parser = self.my_parser()
        self.args = self.parser.parse_args().__dict__

    def my_parser(self):
        '''使用说明'''
        example = """Examples:
                          \r  python3 {shell_name} -i 192.168.1.1/24 -ck -s
                          \r  python3 {shell_name} -iL target.txt -st masscan -r 3000 -ck -a -s
                          """

        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,  # 使 example 可以换行
            add_help=True,
            # description = "端口扫描",
        )
        parser.epilog = example.format(shell_name=parser.prog)
        parser.add_argument("-i", dest="target", type=str,
                            help="Target(1.1.1.1 or 1.1.1.1/24 or 1.1.1.1-4)")
        parser.add_argument("-iL", dest="target_filename", type=str,
                            help="Target file name")
        parser.add_argument("-c", dest="config_file", type=str, default="config.cfg",
                            help="Config file, example: /usr/local/etc/rpscan.cfg")
        parser.add_argument("-st", dest="scantype", type=str, default="masscan",
                            choices=["tcp", "masscan", "nmap"], help="Port scan type, default is masscan")
        parser.add_argument("-t", dest="thread_num", type=int, default=10,
                            help="The number of threads, default is 30 threads")
        parser.add_argument("-r", dest="rate", type=int, default=1000,
                            help="Port scan rate, default is 1000")
        parser.add_argument("-p", dest="ports", type=str,
                            help="Ports to be scanned, example: 22,23,80,3306")
        parser.add_argument("-ck", dest="is_check_live", default=False, action="store_true",
                            help="Check host is alive before port scan, default is False")
        parser.add_argument("-a", dest="is_all_ports", default=False, action="store_true",
                            help="Full port scan, default is False, scan common ports")
        parser.add_argument("-s", dest="get_service", default=False, action="store_true",
                            help="Whether to get port service, default is False")
        # args = parser.parse_args()
        # parser.print_help()

        return parser

    @staticmethod
    def init():
        parser = ParserCmd()
        return parser.args


class ParseTarget(object):
    """ParseTarget"""

    def __init__(self):
        super(ParseTarget, self).__init__()
        self.ip_list = list()

    def parse_target(self, targets):
        # ["10.17.1.1/24", "10.17.2.30-55", "10.111.22.12"]

        if isinstance(targets, list):
            for target in targets:
                ips = self.parse_ip(target)
                self.ip_list.extend(ips)
        elif isinstance(targets, str):
            ips = self.parse_ip(targets)
            self.ip_list.extend(ips)

        # ip 排序去重
        ips = [ip for ip in sorted(set(self.ip_list), key=socket.inet_aton)]
        return ips

    def parse_ip(self, target):
        # 1.1.1.1-1.1.1.10
        # 10.17.1.1/24
        # 10.17.2.30-55
        # 10.111.22.12

        ip_list = list()
        # 校验target格式是否正确
        m = re.match(
            r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}(\.\d{1,3}){3}$', target)
        m1 = re.match(
            r'\d{1,3}(\.\d{1,3}){3}/(1[6789]|2[012346789]|3[012])$', target)
        m2 = re.match(r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}$', target)
        m3 = re.match(r'\d{1,3}(\.\d{1,3}){3}$', target)
        if m:
            prev  = target.rsplit('.', 4)[0]
            start = target.rsplit('-', 1)[0].rsplit('.',1)[1]
            end   = target.rsplit('-', 1)[1].rsplit('.',1)[1]
            for x in range(int(start), int(end)+1):
                ip_list.append(prev+"."+str(x))
        elif m1:
            tmp_ip_list = list()
            for x in IP(target, make_net=True):
                tmp_ip_list.append(str(x))
            ip_list = tmp_ip_list[1:]
        elif m2:
            prev = target.rsplit('.', 1)[0]
            st, sp = target.split('.')[-1].split('-')
            for x in range(int(st), int(sp)+1):
                ip_list.append(prev+"."+str(x))
        elif m3:
            ip_list.append(target)
        else:
            error_msg = "IP {} invalid format".format(target)
            raise Exception(error_msg)

        # 校验 ip 是否正确
        func = lambda x:all([int(y)<256 for y in x.split('.')])
        for ip in ip_list:
            if not func(ip):
                error_msg = "IP {} invalid format".format(target)
                raise Exception(error_msg)

        return ip_list


if __name__ == '__main__':
    pt = ParseTarget()
    print(pt.parse_target("123.123.123.123/29"))
    # print(pt.parse_target(["123.123.123.123/30","1.1.1.1-4"]))
