#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-12-31 13:03:24
@LastEditTime : 2020-06-08 18:59:55
'''

import pathlib


def get_content(filename):
    """按行读取内容并组成列表"""
    with open(filename) as f_obj:
        return [line.strip() for line in f_obj.readlines()]


def file_is_exist(filepath):
    '''判断文件是否存在'''
    if filepath:
        path = pathlib.Path(filepath)
        if path.is_file():
            return True
        else:
            return False

def is_ip_invalid(ip):
    func = lambda _ip:all([int(x)<256 for x in _ip.split('.')])
    return func(ip)
