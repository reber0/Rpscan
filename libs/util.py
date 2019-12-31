#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-12-31 13:03:24
@LastEditTime: 2019-12-31 13:03:34
'''

import pathlib


def get_content(filename):
    with open(filename) as f:
        return [line.strip() for line in f.readlines()]

def file_is_exist(filepath):
    if filepath:
        path = pathlib.Path(filepath)
        if path.is_file():
            return True
        else:
            return False

