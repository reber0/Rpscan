#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-09-19 09:52:13
@LastEditTime: 2020-01-18 02:31:17
'''

import argparse
import re
import socket
from IPy import IP

from libs.util import file_is_exist
from libs.mylog import MyLog
from config import log_level
logger = MyLog(loglevel=log_level, logger_name="check parames")


class Parser(object):
    """Parser"""

    def __init__(self):
        super(Parser, self).__init__()
        self.host = None
        self.host_file = None
        self.parser = self.my_parser()
        self.args = self.parser.parse_args().__dict__

    def my_parser(self):
        '''使用说明'''
        example = """Examples:
                          \r  python3 {shell_name} -i 192.168.1.1/24 -c -s
                          \r  python3 {shell_name} -iL target.txt -st masscan -r 3000 -c -a -s
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
        parser.add_argument("-st", dest="scantype", type=str, default="masscan",
                            choices=["tcp", "masscan"], help="Port scan type, default is masscan")
        parser.add_argument("-t", dest="thread", type=int, default=30,
                            help="The number of threads, default is 30 threads")
        parser.add_argument("-r", dest="rate", type=int, default=1000,
                            help="Port scan rate, default is 1000")
        parser.add_argument("-c", dest="checklive", default=False, action="store_true",
                            help="Check host is alive before port scan, default is False")
        parser.add_argument("-a", dest="is_all_ports", default=False, action="store_true",
                            help="Is full port scanning, default is False")
        parser.add_argument("-s", dest="service", default=False, action="store_true",
                            help="Whether to get port service, default is False")
        # args = parser.parse_args()
        # parser.print_help()

        return parser

    @staticmethod
    def init():
        parser = Parser()
        if parser.parames_is_right():
            return parser.args
        else:
            exit()

    def parames_is_right(self):
        """
        检测给的参数是否正常、检查目标文件或字典是否存在
        """

        self.host = self.args.get("target")
        self.host_file = self.args.get("target_filename")

        if not (self.host or self.host_file):
            self.parser.print_help()
            logger.error(
                "The arguments -i or -iL is required, please provide target !")
            exit(0)

        if self.host_file:
            return self.check_file_exist(self.host_file)

        return True

    def check_file_exist(self, file_name):
        if not file_is_exist(file_name):
            logger.error("No such file or directory \"{}\"".format(file_name))
            return False
        else:
            return True


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

        return self.ip_list

    def parse_ip(self, target):
        # 10.17.1.1/24 or 10.17.2.30-55 or 10.111.22.12

        ip_list = list()
        # 校验target格式是否正确
        m1 = re.match(
            r'\d{1,3}(\.\d{1,3}){3}/(1[6789]|2[012346789]|30)$', target)
        m2 = re.match(r'\d{1,3}(\.\d{1,3}){3}-\d{1,3}$', target)
        m3 = re.match(r'\d{1,3}(\.\d{1,3}){3}$', target)
        if m1:
            tmp_ip_list = list()
            for x in IP(target, make_net=1):
                tmp_ip_list.append(str(x))
            ip_list = tmp_ip_list[1:-1]
        elif m2:
            prev = ".".join(target.split('.')[:3])
            st, sp = target.split('.')[-1].split('-')
            for x in range(int(st), int(sp)+1):
                ip_list.append(prev+"."+str(x))
        elif m3:
            ip_list.append(target)
        else:
            error_msg = "IP {} invalid format".format(target)
            raise Exception(error_msg)

        ips = [ip for ip in sorted(set(ip_list), key=socket.inet_aton)]
        return ips


if __name__ == '__main__':
    pt = ParseTarget()
    print(pt.parse_target("123.123.123.123/29"))
    # print(pt.parse_target(["123.123.123.123/30","1.1.1.1-4"]))
