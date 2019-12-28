#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:54:23
@LastEditTime: 2019-12-28 18:38:06
'''

import os
import time
import platform
import asyncio
from subprocess import Popen, PIPE, STDOUT

from libs.mylog import MyLog
from config import log_file_path
from config import log_level
log_file = log_file_path.joinpath("{}.log".format(time.strftime("%Y-%m-%d", time.localtime())))
logger = MyLog(loglevel=log_level, logger_name='port scan', logfile=log_file)

from config import masscan_path
from config import wooyun_top100_web_port
from config import common_port

class PortScan(object):
    """端口扫描"""
    def __init__(self, ip_list, all_ports=False, rate=2000):
        super(PortScan, self).__init__()
        self.ip_list = ip_list
        self.rate = rate
        self.all_ports = all_ports
        self.open_list = {}
        self.ports = sorted(list(set(wooyun_top100_web_port+common_port)))
        logger.info("[*] PortScan...")

    async def async_port_check(self, semaphore, ip_port):
        async with semaphore:
            ip,port = ip_port
            conn = asyncio.open_connection(ip, port)
            try:
                reader, writer = await asyncio.wait_for(conn, timeout=5)
                return (ip, port, 'open')
            except Exception as e:
                return (ip, port, 'close')

    def callback(self, future):
        ip,port,status = future.result()
        if status == "open":
            logger.info("{:<17}{:<7}{}".format(ip,port,status))
            try:
                if ip in self.open_list:
                    self.open_list[ip].append(port)
                else:
                    self.open_list[ip] = [port]
            except Exception as e:
                logger.error(e)
        else:
            # print(ip,port,status)
            pass

    def async_tcp_port_scan(self):
        logger.info("start async tcp port scan...")
        ports = [port for port in range(20,65535)] if self.all_ports else self.ports
        ip_port_list = [(ip,int(port)) for port in ports for ip in self.ip_list]

        if platform.system()=='Windows':
            self.rate = 500
        sem = asyncio.Semaphore(self.rate) # 限制并发量
        loop = asyncio.get_event_loop()

        tasks = list()
        for ip_port in ip_port_list:
            task = asyncio.ensure_future(self.async_port_check(sem, ip_port))
            task.add_done_callback(self.callback)
            tasks.append(task)

        loop.run_until_complete(asyncio.wait(tasks))

        return self.open_list

    def masscan_scan(self):
        logger.info("start masscan port scan...")
        ports = "11-65535" if self.all_ports else ",".join(map(str,self.ports))
        timestamp = str(time.time())
        target_file = log_file_path.joinpath("target_{}.log".format(timestamp))
        result_file = log_file_path.joinpath("result_{}.log".format(timestamp))
        with open(target_file,"w") as f:
            f.write("\n".join(self.ip_list))

        if platform.system()=='Linux' or platform.system()=='Darwin':
            masscan = masscan_path.joinpath("masscan")
        if platform.system()=='Windows':
            masscan = masscan_path.joinpath("masscan.exe")
        try:
            command = "{} -sS -v -Pn -n -p{} -iL {} -oL {} --randomize-hosts --rate={}"
            command = command.format(masscan, ports, target_file, result_file, self.rate)
            logger.info(command)
            p = Popen(command, shell=True, stderr=STDOUT) #, preexec_fn=os.setgid, stdout=PIPE,
            # print("状态：", p.poll())
            # print("开启进程的pid", p.pid)
            # print("所属进程组的pid", os.getpgid(p.pid))
            # time.sleep(90)
            p.communicate()
        except KeyboardInterrupt:
            if os.path.exists(target_file):
                os.remove(target_file)
            if os.path.exists(result_file):
                os.remove(result_file)
            time.sleep(11)
            if os.path.exists("paused.conf"):
                os.remove("paused.conf")
            # os.killpg(os.getpgid(p.pid), 9)
            logger.error("User aborted.")
            exit(0)

        try:
            lines = [line.strip() for line in open(result_file).readlines()]
            for line in lines[1:-1]:
                logger.info(line)
                ip = line.split()[3]
                port = int(line.split()[2])
                if ip in self.open_list:
                    self.open_list[ip].append(port)
                else:
                    self.open_list[ip] = [port]
        except Exception as e:
            logger.error(e)
        finally:
            if os.path.exists(target_file):
                os.remove(target_file)
            if os.path.exists(result_file):
                os.remove(result_file)

        return self.open_list


