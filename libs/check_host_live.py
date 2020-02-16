#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime : 2020-01-23 12:42:05
'''

import os
import time
import nmap

try:
    from libs.mylog import MyLog
    from config import nmap_min_hostgroup
    from config import nmap_min_parallelism
    from config import log_file_path
    from config import log_level
except ModuleNotFoundError:
    from Rpscan.libs.mylog import MyLog
    from Rpscan.config import nmap_min_hostgroup
    from Rpscan.config import nmap_min_parallelism
    from Rpscan.config import log_file_path
    from Rpscan.config import log_level


log_file = log_file_path.joinpath("{}.log".format(
    time.strftime("%Y-%m-%d", time.localtime())))
logger = MyLog(loglevel=log_level,
               logger_name='check live host', logfile=log_file)


class CheckHostLive(object):
    """获取存活主机列表"""

    def __init__(self, ip_list):
        super(CheckHostLive, self).__init__()
        self.ip_list = ip_list
        self.live_host = list()
        self.command = None
        self.target_file = None
        self._init()
        logger.info("[*] Check Live Host...")

    def _init(self):
        timestamp = str(time.time())
        self.target_file = log_file_path.joinpath(
            "tmp_{}.log".format(timestamp))

        command = "-v -sn -PS -n --min-hostgroup {} --min-parallelism {} -iL {}"
        self.command = command.format(nmap_min_hostgroup, nmap_min_parallelism ,self.target_file)

        with open(self.target_file, "w") as f_obj:
            f_obj.write("\n".join(self.ip_list))

    def run(self):
        '''检测存活主机'''
        try:
            nm_scan = nmap.PortScanner()
            nm_scan.scan(self.command.replace("\\","/"), arguments="")
            # print(nm_scan.command_line())
            for host in nm_scan.all_hosts():
                if nm_scan[host]["status"]["state"] == "up":
                    self.live_host.append(host)
        except KeyboardInterrupt:
            logger.error("User aborted.")
            exit(0)
        except Exception as e:
            logger.error(str(e))
        finally:
            if os.path.exists(self.target_file):
                os.remove(self.target_file)

        logger.info("all host: {}, live host: {}".format(
            len(self.ip_list), len(self.live_host)))

        return self.live_host
