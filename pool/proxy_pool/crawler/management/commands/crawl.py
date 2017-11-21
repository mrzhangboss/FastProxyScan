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

    def handle(self, *args, **options):
        if options['kuaidaili']:
            insert = 0
            for i in range(1, 100):
                hosts = re.findall('<td data-title="IP">(.*)</td>',
                                   requests.get('http://www.kuaidaili.com/free/inha/%d/' % i).text)
                ins = 0
                for host in hosts:
                    _, created = HostInfo.objects.update_or_create(host=host)
                    if created:
                        ins += 1
                self.stdout.write(self.style.SUCCESS('insert %d' % ins))
                insert += ins
            self.stdout.write(self.style.SUCCESS('total insert %d' % insert))