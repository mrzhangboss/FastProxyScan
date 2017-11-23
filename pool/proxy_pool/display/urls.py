# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/23

"""

from django.conf.urls import url
from .views import index, get_latest, get_ip

urlpatterns = [
    url(r'^$', index, name='index'),
    url(r'^ip/$', get_ip, name='ip'),
    url(r'^api/$', get_latest, name='api')
]