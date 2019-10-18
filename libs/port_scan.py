#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:54:23
@LastEditTime: 2019-10-16 09:25:09
'''

import os
import time
import platform
import asyncio
from subprocess import Popen, PIPE, STDOUT

from libs.mylog import MyLog
logger = MyLog(logfile='log/port_scan.log', loglevel='INFO', logger_name='port scan')

class PortScan(object):
    """端口扫描"""
    def __init__(self, ip_list, all_ports=False, rate=2000):
        super(PortScan, self).__init__()
        self.ip_list = ip_list
        self.rate = rate
        self.all_ports = all_ports
        self.open_list = {}
        self.common_port = "21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,110,111,135,139,143,161,389,443,445,465,513,873,993,995,1080,1099,1158,1433,1521,1533,1863,2049,2100,2181,3128,3306,3307,3308,3389,3690,5000,5432,5900,6379,7001,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8011,8012,8013,8014,8015,8016,8017,8018,8019,8020,8021,8022,8023,8024,8025,8026,8027,8028,8029,8030,8031,8032,8033,8034,8035,8036,8037,8038,8039,8040,8041,8042,8043,8044,8045,8046,8047,8048,8049,8050,8051,8052,8053,8054,8055,8056,8057,8058,8059,8060,8061,8062,8063,8064,8065,8066,8067,8068,8069,8070,8071,8072,8073,8074,8075,8076,8077,8078,8079,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8168,8888,9000,9080,9090,9200,9300,9418,11211,27017,27018,27019,50060"
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
        ports = [port for port in range(11,65535)] if self.all_ports else self.common_port.split(',')
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
        ports = "11-65535" if self.all_ports else self.common_port
        timestamp = str(time.time())
        target_file = "log/target_{}.log".format(timestamp)
        result_file = "log/result_{}.log".format(timestamp)
        with open(target_file,"w") as f:
            f.write("\n".join(self.ip_list))

        if platform.system()=='Linux' or platform.system()=='Darwin':
            masscan_path = "./masscan/masscan"
        if platform.system()=='Windows':
            masscan_path = ".\\masscan\\masscan.exe"
        try:
            command = "{masscan_path} -sS -v -Pn -n -p{ports} -iL {target_file} -oL {result_file} --randomize-hosts --rate={rate}".format(masscan_path=masscan_path,ports=ports, target_file=target_file, result_file=result_file, rate=self.rate)
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


