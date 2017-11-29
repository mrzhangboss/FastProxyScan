# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/21

"""
import re
import requests
from django.core.management.base import BaseCommand, CommandError
from database.models import HostInfo


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--kuaidaili', action='store_true')
        parser.add_argument('--xici', action='store_true')
        parser.add_argument('--yun', action='store_true')
        parser.add_argument('-m', '--max-page', action='store', dest='max_page', default=10, type=int,
                            help='scan max page of proxy web')

    def handle(self, *args, **options):
        if options['kuaidaili']:
            insert = 0
            for i in range(1, options['max_page']):
                hosts = re.findall('<td data-title="IP">(.*)</td>',
                                   requests.get('http://www.kuaidaili.com/free/inha/%d/' % i).text)
                ins = 0
                for host in hosts:
                    _, created = HostInfo.objects.update_or_create(host=host)
                    if created:
                        ins += 1
                self.stdout.write(self.style.SUCCESS('page %d insert %d' % (i, ins)))
                insert += ins
            self.stdout.write(self.style.SUCCESS('total insert %d' % insert))

        if options['xici']:
            url = "http://www.xicidaili.com/"
            headers = {
                'accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                'accept-encoding': "gzip, deflate",
                'accept-language': "zh-CN,zh;q=0.9",
                'cache-control': "no-cache",
                'connection': "keep-alive",
                'host': "www.xicidaili.com",
                'pragma': "no-cache",
                'upgrade-insecure-requests': "1",
                'user-agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
                'postman-token': "18ba45aa-2fa1-1482-0310-05258cd5f0a3"
            }

            response = requests.request("GET", url, headers=headers)
            hosts = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', response.text)
            ins = 0
            for host in hosts:
                _, created = HostInfo.objects.update_or_create(host=host)
                if created:
                    ins += 1
            self.stdout.write(self.style.SUCCESS('xici get %d insert %d' % (len(hosts), ins)))

        if options['yun']:
            total = 0
            for j in range(1, 8):
                url = 'http://www.ip3366.net/free/?stype=1&page=%d' % j
                response = requests.get(url)
                hosts = re.findall('(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', response.text)
                ins = 0
                for host in hosts:
                    _, created = HostInfo.objects.update_or_create(host=host)
                    if created:
                        ins += 1
                self.stdout.write(self.style.SUCCESS('yun get %d insert %d' % (len(hosts), ins)))
                total += ins
            self.stdout.write(self.style.SUCCESS('yun total insert %d' % total))



