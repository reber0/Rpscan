#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-11 16:38:55
@LastEditTime : 2020-08-04 16:40:17
'''

import asyncio

class AsyncTcpScan(object):
    """端口扫描"""

    def __init__(self, config):
        super(AsyncTcpScan, self).__init__()
        self.open_list = dict()
        self.logger = config.logger
        self.timeout = config.timeout
        self.target_host = config.target_host
        self.ports = config.ports
        self.rate = config.rate
        self.os_type = config.os_type

    async def async_port_check(self, semaphore, ip_port):
        '''端口探测'''
        async with semaphore:
            ip, port = ip_port
            conn = asyncio.open_connection(ip, port)
            try:
                _, _ = await asyncio.wait_for(conn, timeout=self.timeout)
                return (ip, port, 'open')
            except Exception as e:
                return (ip, port, 'close')
            finally:
                conn.close()

    def callback(self, future):
        '''回调处理结果'''
        ip, port, status = future.result()
        if status == "open":
            self.logger.info("{:<17}{:<7}{}".format(ip, port, status))
            try:
                if ip in self.open_list:
                    self.open_list[ip].append(port)
                else:
                    self.open_list[ip] = [port]
            except Exception as e:
                self.logger.error(e)
        else:
            # self.logger.debug("{}:{} {}".format(ip,port,status))
            pass

    def run(self):
        '''async tcp port scan'''
        self.logger.debug("[*] Start async tcp port scan...")

        ip_port_list = list()
        for ip in self.target_host:
            for port in self.ports:
                ip_port_list.append((ip, int(port)))

        # print(ip_port_list)

        if self.os_type == 'Windows':
            self.rate = 500
        sem = asyncio.Semaphore(self.rate)  # 限制并发量
        loop = asyncio.get_event_loop()

        tasks = list()
        for ip_port in ip_port_list:
            task = asyncio.ensure_future(self.async_port_check(sem, ip_port))
            task.add_done_callback(self.callback)
            tasks.append(task)

        loop.run_until_complete(asyncio.wait(tasks))

        return self.open_list