#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-11 16:41:42
@LastEditTime : 2020-08-07 14:37:20
'''

import os
import time
import demjson
import tempfile
from subprocess import Popen, STDOUT, PIPE

from libs.util import file_get_contents

class MasscanScan(object):
    """端口扫描"""

    def __init__(self, config):
        super(MasscanScan, self).__init__()
        self.open_list = dict()
        self.logger = config.logger
        self.os_type = config.os_type
        self.masscan_file = config.masscan_file
        self.ip_list = config.ip_list
        self.is_all_ports = config.is_all_ports
        self.ports = config.ports
        self.rate = config.rate

    def masscan_scan(self, ip_list, ports, masscan_file, rate):
        '''masscan 探测端口'''

        target_file_fp = tempfile.NamedTemporaryFile(
            prefix='tmp_port_scan_target_', suffix='.txt', delete=False)
        result_file_fp = tempfile.NamedTemporaryFile(
            prefix='tmp_port_scan_result_', suffix='.txt', delete=False)

        target_file_fp.write("\n".join(ip_list).encode("utf-8"))
        target_file_fp.close()
        result_file_fp.close()

        try:
            command = "{} -sS -Pn -n -p{} -iL {} -oJ {} --randomize-hosts --rate={}"
            command = command.format(masscan_file, ports, target_file_fp.name, result_file_fp.name, rate)
            self.logger.info(command)
            p = Popen(command, shell=True, stderr=STDOUT) # stdout=PIPE, 
            # print("状态：", p.poll())
            # print("开启进程的pid", p.pid)
            # print("所属进程组的pid", os.getpgid(p.pid))
            # time.sleep(90)
            masscan_output, masscan_err = p.communicate()
        except KeyboardInterrupt:
            os.unlink(target_file_fp.name)
            os.unlink(result_file_fp.name)
            time.sleep(11)
            os.unlink("paused.conf")
            # os.killpg(os.getpgid(p.pid), 9)
            self.logger.error("User aborted.")
            exit(0)
        else:
            try:
                data = file_get_contents(result_file_fp.name)
                if self.os_type == "Windows":
                    data = demjson.decode("["+data+"]")
                    data.pop()
                else:
                    data = demjson.decode(data)

                for result in data:
                    ip = result.get("ip")
                    port = result.get("ports")[0].get("port")
                    status = result.get("ports")[0].get("status")
                    self.logger.info("{:<17}{:<7}{}".format(ip, port, status))

                    if ip in self.open_list:
                        self.open_list[ip].append(port)
                    else:
                        self.open_list[ip] = [port]
            except demjson.JSONDecodeError as e:
                if str(e) == "No value to decode":
                    self.logger.error("没有扫描到端口")
                else:
                    self.logger.error("demjson.JSONDecodeError: {}".format(e))
            except Exception as e:
                self.logger.error(e)
            finally:
                os.unlink(target_file_fp.name)
                os.unlink(result_file_fp.name)

    def run(self):
        self.logger.debug("[*] Start masscan port scan...")

        if not self.is_all_ports:
            self.ports = ",".join(self.ports)
        self.masscan_scan(self.ip_list, self.ports, self.masscan_file, self.rate)

        return self.open_list
