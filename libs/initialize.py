#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2020-06-12 13:52:55
@LastEditTime : 2020-08-04 11:30:28
'''

import sys
import time
import json
import pathlib
import platform
from loguru import logger
from configparser import ConfigParser

from libs.util import get_content
from libs.util import file_is_exist
from libs.util import cmd_is_exist
from libs.data import config
from libs.parse import ParserCmd
from libs.parse import ParseTarget


def set_path(root_abspath):
    config.root_abspath = root_abspath

    # 设置日志路径
    config.log_file_path = root_abspath.joinpath("log/runtime_{time:YYYY-MM-DD}.log")
    config.err_log_file_path = root_abspath.joinpath("log/err_{time:YYYY-MM-DD}.log")

    # 获取 masscan 路径
    os_type = platform.system()
    config.os_type = os_type
    masscan_path = config.root_abspath.joinpath("masscan")
    if os_type == 'Linux' or os_type == 'Darwin':
        if cmd_is_exist("masscan"):
            masscan = cmd_is_exist("masscan")
        else:
            masscan = str(masscan_path.joinpath("masscan"))
    if os_type == 'Windows':
        if cmd_is_exist("masscan.exe"):
            masscan = cmd_is_exist("masscan.exe")
        else:
            masscan = str(masscan_path.joinpath("masscan.exe"))
    config.masscan = masscan


def parames_is_right():
    """
    检测给的参数是否正常、检查目标文件或字典是否存在
    """

    host = config.get("target")
    host_file = config.get("target_filename")

    if not (host or host_file):
        config.logger.error("The arguments -i or -iL is required, please provide target !")
        exit(0)

    if host_file:
        if not file_is_exist(host_file):
            config.logger.error("No such file or directory \"{}\"".format(host_file))
            exit(0)


def init_options():
    # 初始化日志
    logger.remove()
    logger_format1 = "[<green>{time:HH:mm:ss}</green>] <level>{message}</level>"
    logger_format2 = "<green>{time:YYYY-MM-DD HH:mm:ss,SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    logger.add(sys.stdout, format=logger_format1, level="INFO")
    logger.add(config.log_file_path, format=logger_format2, level="INFO", rotation="00:00", enqueue=True, encoding="utf-8")
    logger.add(config.err_log_file_path, rotation="10 MB", level="ERROR", enqueue=True, encoding="utf-8")
    config.pop("log_file_path")
    config.pop("err_log_file_path")
    config.logger = logger

    # 解析命令行参数
    args = ParserCmd().init()
    config.update(args)
    parames_is_right()

    # 解析配置文件参数
    if not file_is_exist(config.config_file):
        config.logger.error("No such file or directory \"{}\"".format(config.config_file))
        exit(0)
    else:
        cfg = ConfigParser()
        cfg.read(config.config_file)
        for section in cfg.sections():
            for k,v in cfg.items(section):
                config[k] = v.strip()
        config.timeout = cfg.getint("base", "timeout")

    # 解析目标资产
    pt = ParseTarget()
    if config.target:
        config.ip_list = pt.parse_target(config.target)
    elif config.target_filename:
        target_list = get_content(config.target_filename)
        config.ip_list = pt.parse_target(target_list)

    # 解析扫描的端口
    if config.ports:
        config.pop("common_port")
        config.pop("wooyun_top100_web_port")
        config.ports = sorted(config.ports.split(","))
    elif config.all_ports:
        config.pop("common_port")
        config.pop("wooyun_top100_web_port")
        if config.scantype == "tcp":
            config.ports = [port for port in range(1, 65535)]
        else:
            config.ports = "1-65535"
    else:
        ports = json.loads(config.wooyun_top100_web_port)
        ports += json.loads(config.common_port)
        ports = list(set(ports))
        config.pop("common_port")
        config.pop("wooyun_top100_web_port")
        ports = sorted(ports)
        config.ports = list(map(str, ports))
