#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime: 2019-12-03 14:08:43
'''

import time
from nmap import nmap
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
lock = Lock()

from libs.mylog import MyLog

logfile = "log/"+str(time.strftime("%Y-%m-%d", time.localtime()))+".log"
logger = MyLog(logfile=logfile, loglevel='INFO', logger_name='get service')

class NmapGetPortService(object):
    """获取端口运行的服务"""
    def __init__(self, ip_port_dict, thread_num=10):
        super(NmapGetPortService, self).__init__()
        self.ip_port_dict = ip_port_dict
        self.thread_num = thread_num
        self.port_service_list = dict()
        self.init_thread()
        logger.info("[*] Get the service of the port...")

    def init_thread(self):
        if len(self.ip_port_dict) < self.thread_num:
            self.thread_num = len(self.ip_port_dict)

    def nmap_get_service(self,ip_port):
        ip,port = ip_port
        try:
            nm = nmap.PortScanner()
            args = '-p T:'+str(port)+' -Pn -sT -sV -n'
            # args = '--allports -Pn -sT -sV -n --version-all --min-parallelism 100'
            nm.scan(ip,arguments=args)
            # logger.info(nm.command_line())

            self.port_service_list[ip] = list()
            port_result = nm[ip]['tcp']
            for port in port_result.keys():
                state = port_result[port]['state']
                name = port_result[port]['name']
                product = port_result[port]['product']
                version = port_result[port]['version']

                result = "{:<17}{:<7}{:<10}{:<16}{:<32}{}".format(ip,port,state,name,product,version)
                lock.acquire()
                logger.info(result)
                lock.release()

                service_result = dict()
                service_result['port'] = port
                service_result['state'] = state
                service_result['name'] = name
                service_result['product'] = product
                service_result['version'] = version
                self.port_service_list[ip].append(service_result)
        except Exception as e:
            # logger.error(e)
            pass

    def run(self):
        try:
            with ThreadPoolExecutor(max_workers = self.thread_num) as executor:
                for ip in self.ip_port_dict.keys():
                    ports = map(lambda x:str(x), self.ip_port_dict[ip])
                    ports = ",".join(ports)
                    executor.submit(self.nmap_get_service, (ip,ports))
        except KeyboardInterrupt:
            logger.error("User aborted.")
            exit(0)

        return self.port_service_list

