# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/21

"""
import time
from queue import Queue
from django.core.management import BaseCommand
from database.models import HostInfo, IPInfo, Proxy, PROXY_STATE
from scanner.scanner import PortScanner


def save_result(host, result):
    if not result['scan']:
        print('no proxy scan', host)
    state = {v: k for k, v in PROXY_STATE}
    scan_stats = result['nmap']['scanstats']
    host_info = HostInfo.objects.get(host=host)
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


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--start', action='store_true')
        parser.add_argument('-m', '--max-size', action='store', dest='max_size', default=20, type=int)

    def handle(self, *args, **options):
        start = 0
        tasks = Queue(options['max_size'])
        if options['start']:
            while True:
                if not tasks.full():
                    hosts = HostInfo.objects.filter(is_deleted=False).values('host').all()[start:start + 1]
                    start += 1
                    if hosts:
                        scanner = PortScanner(hosts[0]['host'])
                        scanner.scan()
                        tasks.put(scanner)
                        print('add a host to queue', scanner._host)
                    elif tasks.empty():
                        print('all scan over')
                        break
                if tasks.full():
                    while True:
                        scanner = tasks.get()
                        if scanner.is_running:
                            tasks.put(scanner)
                        else:
                            save_result(scanner._host, scanner.result)
                            break
                        time.sleep(0.5)
