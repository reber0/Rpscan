#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-12-31 13:03:24
@LastEditTime : 2020-08-03 16:44:42
'''

import os
import platform
from pathlib import Path


def cmd_is_exist(command):
    os_type = platform.system()
    env_path = os.getenv("PATH")

    if os_type == 'Linux' or os_type == 'Darwin':
        for cmdpath in env_path.split(":"):
            if os.path.isdir(cmdpath) and command in os.listdir(cmdpath):
                return cmdpath+"/"+command
    if os_type == 'Windows':
        for cmdpath in env_path.split(";"):
            if os.path.isdir(cmdpath) and command in os.listdir(cmdpath):
                return cmdpath+"\\"+command

def get_content(filename):
    """按行读取内容并组成列表"""
    with open(filename, 'r', encoding='utf-8') as f_obj:
        return [line.strip() for line in f_obj.readlines()]

def file_get_contents(file_name):
    """读取文件内容返回字符串"""
    data = ""
    try:
        f_obj = open(file_name, 'r', encoding='utf-8')
        data = f_obj.read()
    except Exception as e:
        return False
    else:
        return data
    finally:
        if f_obj:
            f_obj.close()

def file_is_exist(filepath):
    '''判断文件是否存在'''
    if filepath:
        path = Path(filepath)
        if path.is_file():
            return True
        else:
            return False

def is_ip_invalid(ip):
    func = lambda _ip:all([int(x)<256 for x in _ip.split('.')])
    return func(ip)
