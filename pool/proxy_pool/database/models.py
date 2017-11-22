"""
speed # second * 100

"""
from django.db import models

# Create your models here.
HOST_INFO_MODE = [
    (0, 'IP'),
    (1, 'HOST'),
    (2, 'IP+*'),
]


class HostInfo(models.Model):
    host = models.CharField(max_length=256, unique=True)
    port_sum = models.IntegerField(default=0)
    mode = models.IntegerField(default=0, choices=HOST_INFO_MODE)
    speed = models.IntegerField(default=0)
    is_deleted = models.BooleanField(default=False)
    insert_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.host

    __unicode__ = __str__


class IPInfo(models.Model):
    ip = models.CharField(max_length=16, unique=True)
    port_sum = models.IntegerField(default=0)
    speed = models.IntegerField(default=0)
    is_deleted = models.BooleanField(default=False)
    country = models.CharField(max_length=128, null=True, blank=True)
    province = models.CharField(max_length=128, null=True, blank=True)
    city = models.CharField(max_length=128, null=True, blank=True)
    district = models.CharField(max_length=128, null=True, blank=True)
    operator = models.CharField(max_length=128, null=True, blank=True)
    insert_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip

    __unicode__ = __str__


PROXY_STATE = [
    (0, 'default'),
    (1, 'open'),
    (2, 'closed'),
    (3, 'filtered'),
    (4, 'unfiltered'),
    (5, 'open|filtered'),
    (6, 'closed|filtered'),
]

PROXY_CHECK_STATE = [
    (0, 'Default'),
    (1, 'TransparentProxy'),
    (2, 'AnonymousProxy'),
    (3, 'HighAnonymousProxy'),
    (4, 'NeedAuthProxy'),
    (5, 'MitmProxy')
]

PROXY_PROTOCOL = [
    (0, 'default'),
    (1, 'http'),
    (2, 'https'),
    (3, 'http+https'),
    (4, 'socks'),
]


class Proxy(models.Model):
    host = models.ForeignKey(HostInfo, on_delete=models.CASCADE, related_name='proxies')
    ip = models.ForeignKey(IPInfo, on_delete=models.CASCADE, related_name='proxies')
    port = models.IntegerField()
    state = models.IntegerField(default=0, choices=PROXY_STATE)
    is_checked = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)
    checked_state = models.IntegerField(default=0, choices=PROXY_CHECK_STATE)
    protocol = models.IntegerField(default=0, choices=PROXY_PROTOCOL)
    speed = models.IntegerField(default=0)
    insert_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ip.ip + ':' + str(self.port)

    __unicode__ = __str__
