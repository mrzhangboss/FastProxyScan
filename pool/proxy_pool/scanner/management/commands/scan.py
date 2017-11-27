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


def save_result(host, result, bigger):
    defaults = {'mode': 2, 'is_deleted': True} if DOMAIN_FMT.search(host.strip()) else None
    host_info, created = HostInfo.objects.get_or_create(host=host, defaults=defaults)
    if created:  # set deleted is True, not scan next time
        print(BColors.BOLD, 'add domain', host_info.host, BColors.END)
    if not result['scan']:  # delete host when it no port open
        print('no proxy scan', host)
        host_info.is_deleted = True
        host_info.save()
        return
    state = {v: k for k, v in PROXY_STATE}
    scan_stats = result['nmap']['scanstats']
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
            if ip_port_sum >= bigger:
                new_host, created = HostInfo.objects.update_or_create(host=ip_info.ip,
                                                                      defaults={'port_sum': ip_port_sum})
                if created:
                    print('insert one host: %s port sum bigger than' % ip_info.ip, bigger)

            for port in result['scan'][ip]['tcp']:
                p = result['scan'][ip]['tcp'][port]
                proxy, created = Proxy.objects.update_or_create(
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


async def host_scan(semaphore, host, port=None, bigger=15, exclude=None, timeout=360, sleep_time=0.5, origin=None):
    async with semaphore:
        scanner = PortScanner(host, port=port, exclude=exclude, host_timeout=timeout)
        scanner.scan()
        print(host, 'begin scan', datetime.now())
        while scanner.is_running:
            await asyncio.sleep(sleep_time)
        print(BColors.OK_GREEN, host, 'scan over', datetime.now(), BColors.END)
        save_result(origin if origin else host, scanner.result, bigger)


def get_host_domain(ip):
    domain = ip[::-1].split('.', 1)[1][::-1] + '.*'
    domain = domain.strip()
    assert DOMAIN_FMT.search(domain)
    return domain


def get_domain_ips(ip):
    domain = get_host_domain(ip)[:-2]
    return (y for y in ('%s.%d' % (domain, x) for x in range(256)) if y != ip)


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--start', action='store_true')
        parser.add_argument('--force-run', action='store_true', dest='force', help="force run domain scan")
        parser.add_argument('-m', '--max-size', action='store', dest='max_size', default=20, type=int)
        parser.add_argument('-b', '--bigger', action='store', dest='bigger', default=15, type=int,
                            help='if ip port sum bigger than it, will scan it domain')

    def handle(self, *args, **options):
        start = time.time()
        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(options['max_size'])
        bigger = options['bigger']
        is_force_run = options['force']
        if options['start']:
            tasks = []
            for host_info in HostInfo.objects.filter(is_deleted=False, mode=0).order_by(
                    '-port_sum').all():  # for ip scan
                tasks.append(asyncio.ensure_future(host_scan(semaphore, host_info.host, bigger=bigger)))
                # continue
                if host_info.port_sum > bigger:
                    domain = get_host_domain(host_info.host)
                    if not HostInfo.objects.filter(host=domain).exists() or is_force_run:
                        ips = get_domain_ips(host_info.host)
                        # if bigger than bigger // 2 , we add it to our host to scan
                        for ip in ips:
                            tasks.append(
                                asyncio.ensure_future(host_scan(semaphore, ip, bigger=bigger // 2, origin=domain)))

            for host_info in HostInfo.objects.filter(is_deleted=False, mode=1).all():  # for domain scan
                tasks.append(asyncio.ensure_future(host_scan(semaphore, host_info.host, bigger=bigger)))
        loop.run_until_complete(asyncio.wait(tasks))
        print(BColors.OK_GREEN, len(tasks), 'tasks over', datetime.now(), 'cost ', time.time() - start, 's')
