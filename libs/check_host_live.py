#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime: 2019-12-16 22:47:19
'''

import os
import sys
import time
import nmap

from libs.mylog import MyLog

logfile = "log/"+str(time.strftime("%Y-%m-%d", time.localtime()))+".log"
logger = MyLog(logfile=logfile, loglevel='INFO', logger_name='check live host')

class CheckHostLive(object):
    """获取存活主机列表"""
    def __init__(self, ip_list):
        super(CheckHostLive, self).__init__()
        self.ip_list = ip_list
        self.live_host = list()
        self.command = None
        self.target_file = None
        self.init()
        logger.info("[*] Check Live Host...")

    def init(self):
        timestamp = str(time.time())
        if sys.platform.startswith('win'):
            self.target_file = "log\\\\tmp_{}.log".format(timestamp)
        else:
            self.target_file = "/tmp/tmp_{}.log".format(timestamp)
        self.command = "-v -sn -PS -n --min-hostgroup 500 --min-parallelism 1000 -iL {}".format(self.target_file)

        with open(self.target_file,"w") as f:
            f.write("\n".join(self.ip_list))

    def run(self):
        try:
            nm = nmap.PortScanner()
            nm.scan(self.command,arguments="")
            # print(nm.command_line())
            for host in nm.all_hosts():
                if nm[host]["status"]["state"] == "up":
                    self.live_host.append(host)
        except KeyboardInterrupt:
            logger.error("User aborted.")
            exit(0)
        except Exception as e:
            logger.error(str(e))
        finally:
            if os.path.exists(self.target_file):
                os.remove(self.target_file)
        logger.info("all host: {}, live host: {}".format(len(self.ip_list),len(self.live_host)))
        return self.live_host

