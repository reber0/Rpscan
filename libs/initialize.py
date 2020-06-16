#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-12 13:52:55
@LastEditTime : 2020-06-16 23:49:18
'''

import importlib
from libs.util import get_content
from libs.data import config
from libs.mylog import MyLog
from libs.parse import ParserCmd
from libs.parse import ParseTarget


def init_config(conf_file):
    conf = importlib.import_module(conf_file.split('.')[0])
    for i in dir(conf):
        if i.startswith("__"):
            continue
        x = getattr(conf, i)
        # config[i] = x
        if type(x) in (dict, int, str, float, list):
            config[i] = x

    config.logger = MyLog(loglevel=config.log_level,
                          logger_name='port scan', logfile=config.log_file)


def init_cmd_args():
    # 解析命令行参数
    args = ParserCmd().init()
    config.update(args)

    pt = ParseTarget()
    if config.target:
        config.ip_list = pt.parse_target(config.target)
    elif config.target_filename:
        target_list = get_content(config.target_filename)
        config.ip_list = pt.parse_target(target_list)

    if config.ports:
        config.pop("common_port")
        config.pop("wooyun_top100_web_port")
        if config.scantype == "tcp":
            config.ports = sorted(config.ports.split(","))
    elif config.all_ports:
        if config.scantype == "tcp":
            config.ports = [port for port in range(1, 65535)]
        else:
            config.ports = "1-65535"
    else:
        ports = list(set(config.wooyun_top100_web_port+config.common_port))
        config.ports = ",".join([str(port) for port in ports])
