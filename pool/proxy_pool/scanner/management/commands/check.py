# -*- coding:utf-8 -*-
"""

@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/22

"""
import asyncio
import time
import requests
from django.core.management import BaseCommand
from django.db.models import Q
from database.models import IPInfo, Proxy
from scanner.checker import check_proxy


async def check_one_port_part(ips, port, base_ip, check_ip_url):
    result = await check_proxy(ips, port, base_ip, check_ip_url)
    print('port %d get %d result' % (port, len(result)))
    for ip in result:
        ip_info = IPInfo.objects.get(ip=ip)
        Proxy.objects.update_or_create(ip=ip_info, port=port, defaults=result[ip])


async def check_one_port(port, check_ip_url, base_ip, skip=50):
    tasks = []
    query = Proxy.objects.filter(port=port, state=1).filter(Q(is_checked=False) | Q(is_proxy=True))
    total = query.count()
    for i in range(0, total, skip):
        ip_group = query.all()[i:i + skip]
        ips = [x.ip.ip for x in ip_group]
        tasks.append(asyncio.ensure_future(check_one_port_part(ips, port, base_ip, check_ip_url)))
    await asyncio.gather(*tasks)
    print('port', port, 'finished')


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--start', action='store_true')
        parser.add_argument('-c', '--check-ip-url', action='store', dest='check_ip_url', type=str)

    def handle(self, *args, **options):
        if options['start']:
            start = time.time()
            url = options['check_ip_url']
            base_ip = requests.get(url).json()['REMOTE_ADDR']
            ports = Proxy.objects.filter(state=1).filter(Q(is_checked=False) | Q(is_proxy=True)).values(
                'port').distinct()
            loop = asyncio.get_event_loop()
            tasks = []
            for p in ports:
                task = asyncio.ensure_future(check_one_port(p['port'], check_ip_url=url, base_ip=base_ip))
                tasks.append(task)
            loop.run_until_complete(asyncio.wait(tasks))
            seconds = time.time() - start
            proxy_scan_sum = Proxy.objects.filter(state=1).filter(Q(is_checked=False) | Q(is_proxy=True)).count()
            print('Tasks over %d proxy cost %d s' % (proxy_scan_sum, seconds))
