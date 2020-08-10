#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-08-07 15:05:57
@LastEditTime : 2020-08-10 11:05:42
'''

import requests
from concurrent.futures import ThreadPoolExecutor

class HttpScan(object):
    """
    如果扫描结果返回很多端口，那可能是因为有设备
    此时使用 http 直接访问常见 web 端口
    """

    def __init__(self, config):
        super(HttpScan, self).__init__()
        self.open_list = dict()
        self.logger = config.logger
        self.thread_num = config.thread_num
        self.timeout = config.timeout
        self.ip_list = config.ip_list
        self.ports = config.ports
        self.init_thread()
        self.flag = True

    def init_thread(self):
        '''设定线程数量'''
        self.ip_port_list = list()
        for port in self.ports:
            for ip in self.ip_list:
                self.ip_port_list.append((ip, int(port)))

        if len(self.ip_port_list) < self.thread_num:
            self.thread_num = len(self.ip_port_list)

    def web_detect(self, ip_port):
        '''端口探测'''
        if self.flag:
            ip, port = ip_port
            try:
                url = "http://{}:{}".format(ip, port)
                resp = requests.get(url=url, timeout=self.timeout, verify=False)
            except Exception as e_msg:
                self.logger.error(e_msg)
            else:
                self.logger.info("{:<17}{:<7}{}".format(ip, port, "open"))

                if ip in self.open_list:
                    self.open_list[ip].append(port)
                else:
                    self.open_list[ip] = [port]

    def run(self):
        self.logger.info("[*] Start http port detect...")

        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                for ip_port in self.ip_port_list:
                    executor.submit(self.web_detect, ip_port)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)

        return self.open_list
