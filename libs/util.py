#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-12-31 13:03:24
@LastEditTime : 2020-07-28 11:12:19
'''

import pathlib


def get_content(filename):
    """按行读取内容并组成列表"""
    with open(filename) as f_obj:
        return [line.strip() for line in f_obj.readlines()]

def file_get_contents(file_name):
    """读取文件内容返回字符串"""
    data = ""
    try:
        f_obj = open(file_name, 'r')
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
        path = pathlib.Path(filepath)
        if path.is_file():
            return True
        else:
            return False

def is_ip_invalid(ip):
    func = lambda _ip:all([int(x)<256 for x in _ip.split('.')])
    return func(ip)
