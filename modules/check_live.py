#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-08-24 17:55:54
@LastEditTime : 2020-07-29 16:02:53
'''

import os
import time
import nmap
import tempfile

from libs.data import config


class CheckHostLive(object):
    """获取存活主机列表"""

    def __init__(self, ip_list=None):
        super(CheckHostLive, self).__init__()
        self.ip_list = ip_list
        self.live_host = list()
        self.logger = config.logger
        self._init()

    def _init(self):
        tmpfd, self.target_file = tempfile.mkstemp(
            prefix='tmp_port_scan_target_', suffix='.txt',text=True)

        self.command = "-v -sn -PS -n --min-hostgroup {} --min-parallelism {} -iL {}".format(
            config.nmap_min_hostgroup, config.nmap_min_parallelism, self.target_file)

        with open(self.target_file, "w") as f_obj:
            f_obj.write("\n".join(self.ip_list))

    def run(self):
        '''检测存活主机'''
        self.logger.info("[*] Check Live Host...")
        try:
            nm_scan = nmap.PortScanner()
            nm_scan.scan(self.command, arguments="")
            # print(nm_scan.command_line())
            for host in nm_scan.all_hosts():
                if nm_scan[host]["status"]["state"] == "up":
                    self.live_host.append(host)
        except KeyboardInterrupt:
            self.logger.error("User aborted.")
            exit(0)
        except Exception as e:
            self.logger.error(str(e))
        finally:
            os.close(tmpfd)
            os.remove(self.target_file)

        self.logger.info("All host: {}, live host: {}".format(len(self.ip_list), len(self.live_host)))

        return self.live_host
