# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/21

"""
import os
import re
import random
import asyncio
import requests
import time
from datetime import timedelta
from os import path
from pprint import pprint
from django.utils.timezone import datetime
from django.core.management import BaseCommand
from django.db.models import Q
from database.models import HostInfo, IPInfo, Proxy, PROXY_STATE
from scanner.scanner import PortScanner, BColors
from scanner.apnic_parse import get_ip_dress

DOMAIN_FMT = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\*$')


def save_proxy(host, result):
    # set deleted is True, not scan next time
    host_info, created = HostInfo.objects.update_or_create(host=host, defaults={'is_deleted': True})
    if created:
        print(BColors.BOLD, 'add host', host_info.host, BColors.END)
    if not result['scan']:
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


async def port_scan(semaphore, host, port=None, timeout=60, sleep_time=0.5):
    async with semaphore:
        scanner = PortScanner(host, port=port, host_timeout=timeout)
        scanner.scan()
        print(host, 'begin scan', datetime.now())
        while scanner.is_running:
            await asyncio.sleep(sleep_time)
        print(BColors.OK_GREEN, host, 'scan over', datetime.now(), BColors.END)
        save_proxy(host, scanner.result)


def save_host(host, result):
    defaults = {'mode': 2, 'is_deleted': True}
    host_info, created = HostInfo.objects.get_or_create(host=host, defaults=defaults)
    if created:  # set deleted is True, not scan next time
        print(BColors.BOLD, 'add domain', host_info.host, BColors.END)
    if not result['scan']:  # delete host when it no port open
        print('no vps scan', host)
        return
    scan_stats = result['nmap']['scanstats']
    host_speed = (int(scan_stats['end']) - int(scan_stats['start'])) * 100
    ip_speed = host_speed // int(scan_stats['totalhosts'])
    host_port_sum = 0
    for ip in result['scan']:
        ip_port_sum = len(result['scan'][ip]['tcp']) if result['scan'][ip].get('tcp') else 0
        host_port_sum += ip_port_sum
        host_info, created = HostInfo.objects.get_or_create(host=ip, defaults={
            'speed': ip_speed,
            'port_sum': ip_port_sum
        })
        if created:
            print('insert one host', ip)
    host_info.port_sum = host_port_sum
    host_info.speed = host_speed
    host_info.save()


async def ip_scan(semaphore, host, timeout=1, sleep_time=0.5):
    async with semaphore:
        scanner = PortScanner(host, host_timeout=timeout)
        scanner.scan_ip()
        print(host, 'begin scan host', datetime.now())
        while scanner.is_running:
            await asyncio.sleep(sleep_time)
        print(BColors.OK_GREEN, host, 'scan over', datetime.now(), BColors.END)
        save_host(host, scanner.result)


def get_host_domain(ip):
    domain = ip[::-1].split('.', 1)[1][::-1] + '.*'
    domain = domain.strip()
    assert DOMAIN_FMT.search(domain)
    return domain


def get_domain_ips(ip):
    domain = get_host_domain(ip)[:-2]
    return (y for y in ('%s.%d' % (domain, x) for x in range(256)) if y != ip)


def pre_delete(day):
    now = datetime.now()
    expires_date = now - timedelta(days=day)
    # delete host is_deleted = True
    host_query = HostInfo.objects.filter(insert_at__lte=expires_date, is_deleted=True)
    print('delete %d host' % host_query.count())
    host_query.delete()

    # delete proxy
    proxy_query = Proxy.objects.filter(is_checked=True, is_proxy=False, insert_at__lte=expires_date)
    print('delete %d proxy' % proxy_query.count())
    proxy_query.delete()


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--proxy', action='store_true', help='run nmap scan vps port scan')
        parser.add_argument('--vps', action='store_true', help='run nmap scan vps ip')
        parser.add_argument('-m', '--max-size', action='store', dest='max_size', default=50, type=int,
                            help='the bigger number the highe speed')
        parser.add_argument('-t', '--task-sum', action='store', dest='sum', default=200, type=int,
                            help='vps scan task sun')
        parser.add_argument('--expires', '-e', action='store', dest='expires', default=2, type=int,
                            help='day of the expires of host and proxy')

    def handle(self, *args, **options):
        start = time.time()
        loop = asyncio.get_event_loop()
        semaphore = asyncio.Semaphore(options['max_size'])
        if options['proxy']:
            tasks = []
            for host_info in HostInfo.objects.exclude(
                            Q(mode=2) | Q(is_deleted=True)).all():  # for not domain ip like 127.0.0.*
                tasks.append(asyncio.ensure_future(port_scan(semaphore, host_info.host)))

            loop.run_until_complete(asyncio.wait(tasks))
            print(BColors.OK_GREEN, len(tasks), 'tasks over', datetime.now(), 'cost ', time.time() - start, 's')

        if options['vps']:
            fn = 'delegated-apnic-latest.txt'
            url = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
            if not path.exists(fn):
                with open(fn, 'wb') as f:
                    f.write(requests.get(url).content)
            pre_delete(options['expires'])
            tasks = []
            tasks_sum = options['sum']
            ip_group = get_ip_dress(filename=fn)
            random.shuffle(ip_group)
            for domain in ip_group:
                if not HostInfo.objects.filter(host=domain).exists():
                    tasks.append(asyncio.ensure_future(ip_scan(semaphore, domain, sleep_time=1)))
                    if len(tasks) > tasks_sum:
                        break
            if not tasks:
                print(BColors.WARNING, len(tasks), 'no host scan, please check expires args', datetime.now())
                return
            loop.run_until_complete(asyncio.wait(tasks))
            print(BColors.OK_GREEN, len(tasks), 'tasks over', datetime.now(), 'cost ', time.time() - start, 's')
