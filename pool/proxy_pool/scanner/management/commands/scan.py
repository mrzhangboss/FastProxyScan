# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/21

"""
import re
import asyncio
import time
from datetime import datetime
from pprint import pprint
from django.core.management import BaseCommand
from database.models import HostInfo, IPInfo, Proxy, PROXY_STATE
from scanner.scanner import PortScanner, BColors

DOMAIN_FMT = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\*$')


def save_result(host, result):
    if not result['scan']:
        print('no proxy scan', host)
        return
    state = {v: k for k, v in PROXY_STATE}
    scan_stats = result['nmap']['scanstats']
    defaults = {'mode': 2} if DOMAIN_FMT.search(host.strip()) else None
    host_info, created = HostInfo.objects.update_or_create(host=host, defaults=defaults)
    if created:
        print(BColors.BOLD, 'add domain', host_info.host, BColors.END)
    host_speed = (int(scan_stats['end']) - int(scan_stats['start'])) * 100
    ip_speed = host_speed // int(scan_stats['totalhosts'])
    host_port_sum = 0
    for ip in result['scan']:
        ip_port_sum = len(result['scan'][ip]['tcp']) if result['scan'][ip].get('tcp') else 0
        host_port_sum += ip_port_sum
        ip_info, created = IPInfo.objects.update_or_create(ip=ip, defaults={
            'speed': ip_speed,
            'port_sum': ip_port_sum
        })
        if created:
            print('insert one ip', ip)
        if ip_port_sum > 0:
            for port in result['scan'][ip]['tcp']:
                p = result['scan'][ip]['tcp'][port]
                proxy, created = Proxy.objects.update_or_create(host=host_info,
                                                                ip=ip_info,
                                                                port=port,
                                                                defaults={
                                                                    'state': state[p['state']]
                                                                })
                if created:
                    print('insert proxy', ip, ':', port)
    host_info.port_sum = host_port_sum
    host_info.speed = host_speed
    host_info.save()


async def host_scan(semaphore, host, exclude=None):
    async with semaphore:
        scanner = PortScanner(host, exclude=exclude)
        scanner.scan()
        print(host, 'begin scan', datetime.now())
        while scanner.is_running:
            await asyncio.sleep(0.5)
        print(BColors.OK_GREEN, host, 'scan over', datetime.now(), BColors.END)
        save_result(host, scanner.result)


def get_host_domain(ip):
    domain = ip[::-1].split('.', 1)[1][::-1] + '.*'
    assert DOMAIN_FMT.search(domain.strip())
    return domain


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--start', action='store_true')
        parser.add_argument('-m', '--max-size', action='store', dest='max_size', default=20, type=int)
        parser.add_argument('-b', '--bigger', action='store', dest='bigger', default=20, type=int, help='if ip port sum bigger than it, will scan it domain')

    def handle(self, *args, **options):
        start = time.time()
        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(options['max_size'])
        bigger = options['bigger']
        if options['start']:
            tasks = []
            for host_info in HostInfo.objects.filter(is_deleted=False, mode=0).order_by(
                    '-port_sum').all():  # for ip scan
                tasks.append(asyncio.ensure_future(host_scan(semaphore, host_info.host)))
                if host_info.port_sum > bigger:
                    domain = get_host_domain(host_info.host)
                    tasks.append(asyncio.ensure_future(host_scan(semaphore, domain, exclude=host_info.host)))

            for host_info in HostInfo.objects.filter(is_deleted=False, mode=1).all():  # for domain scan
                tasks.append(asyncio.ensure_future(host_scan(semaphore, host_info.host)))
        loop.run_until_complete(asyncio.wait(tasks))
        print(BColors.OK_GREEN, len(tasks), 'tasks over', datetime.now(), 'cost ', time.time() - start, 's')
