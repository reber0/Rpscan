#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
@Author: reber
@Mail: reber0ask@qq.com
@Date: 2019-12-28 17:01:44
@LastEditTime: 2019-12-28 19:51:00
'''

"""
usage:
    >>> from Rpscan import CheckHostLive
    >>> chl = CheckHostLive(ip_list=["59.108.35.243"])
    >>> live_host = chl.run()
    >>> print(live_host)
    ['59.108.35.243']

    >>> from Rpscan import PortScan
    >>> ps = PortScan(ip_list=['59.108.35.243'], all_ports=False, rate=2000)
    >>> port_open_dict = ps.masscan_scan()
    >>> port_open_dict = ps.async_tcp_port_scan()
    >>> print(port_open_dict)
    {'59.108.35.243': [80, 22]}

    >>> from pprint import pprint
    >>> from Rpscan import NmapGetPortService
    >>> ngps = NmapGetPortService(ip_port_dict={'59.108.35.243': [80, 22]}, thread_num=10)
    >>> port_service_list = ngps.run()
    >>> pprint.pprint(a)
    {'59.108.35.243': [{'name': 'ssh',
                        'port': 22,
                        'product': 'OpenSSH',
                        'state': 'open',
                        'version': '7.4'},
                    {'name': 'http',
                        'port': 80,
                        'product': 'nginx',
                        'state': 'open',
                        'version': ''}]}
"""

import sys
sys.dont_write_bytecode = True  # 不生成pyc文件

from .libs.check_host_live import CheckHostLive
from .libs.port_scan import PortScan
from .libs.get_service import NmapGetPortService

