#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-11 16:42:43
@LastEditTime : 2020-06-17 00:26:28
'''

import nmap
from concurrent.futures import ThreadPoolExecutor
from libs.data import config


class NmapScan(object):
    """端口扫描"""

    def __init__(self):
        super(NmapScan, self).__init__()
        self.open_list = dict()
        self.thread_num = config.thread
        self.logger = config.logger
        self.flag = True
        self.init_thread()

    def init_thread(self):
        '''设定线程数量'''
        if len(config.target_host) < self.thread_num:
            self.thread_num = len(config.target_host)

    def nmap_scan(self, ip):
        '''nmap 端口探测'''
        if self.flag:
            try:
                nm_scan = nmap.PortScanner()
                args = "-sS -v -Pn -n -T4 -p{}".format(config.ports)
                nm_scan.scan(ip, arguments=args)
                self.logger.info(nm_scan.command_line())

                port_result = nm_scan[ip]['tcp']
                for port in port_result.keys():
                    state = port_result[port]['state']
                    if state == "open":
                        if ip in self.open_list:
                            self.open_list[ip].append(port)
                        else:
                            self.open_list[ip] = [port]
                        self.logger.info(
                            "{:<17}{:<7}{}".format(ip, port, state))
            except Exception as e:
                raise e
                pass

    def run(self):
        '''Nmap port scan'''
        self.logger.info("[*] Start nmap port scan...")

        try:
            with ThreadPoolExecutor(max_workers=self.thread_num) as executor:
                for ip in config.target_host:
                    executor.submit(self.nmap_scan, ip)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            self.flag = False
            exit(0)

        return self.open_list
