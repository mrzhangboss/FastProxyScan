from django.contrib import admin
from .models import HostInfo, IPInfo, Proxy


# Register your models here.

@admin.register(HostInfo)
class HostInfoAdmin(admin.ModelAdmin):
    list_display = ('host', 'port_sum', 'speed', 'insert_at', 'update_at')
    list_filter = ('mode', 'is_deleted', 'insert_at', 'update_at')
    search_fields = ('host',)


@admin.register(IPInfo)
class IPInfoAdmin(admin.ModelAdmin):
    list_display = ('ip', 'port_sum', 'speed', 'country', 'province', 'city', 'district', 'insert_at', 'update_at')
    list_filter = ('country', 'province', 'insert_at', 'update_at')
    search_fields = ('ip', 'country', 'province', 'city', 'distict')


@admin.register(Proxy)
class ProxyAdmin(admin.ModelAdmin):
    readonly_fields = ['host', 'ip']
    list_display = (
        '__str__', 'state', 'is_checked', 'is_proxy', 'checked_state', 'protocol', 'speed', 'insert_at',
        'update_at')
    list_filter = ('state', 'checked_state', 'is_checked', 'is_proxy', 'checked_state', 'protocol', 'insert_at', 'update_at')
