from math import ceil
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.cache import cache_page
from django.utils.timezone import localtime
from database.models import Proxy, PROXY_STATE, PROXY_PROTOCOL, PROXY_CHECK_STATE

proxy_state = dict(PROXY_STATE)
proxy_protocol = dict(PROXY_PROTOCOL)
proxy_check_state = dict(PROXY_CHECK_STATE)


def get_latest_proxies(begin, end):
    proxies = []
    # filter need auth proxy
    for p in Proxy.objects.filter(is_proxy=True, state=1).exclude(checked_state=4).order_by('-update_at').all()[begin:end]:
        proxy = {
            'ip': p.ip.ip,
            'port': p.port,
            'protocol': proxy_protocol[p.protocol],
            'speed': p.speed / 100.0,
            'checked_state': proxy_check_state[p.checked_state],
            'insert_at': localtime(p.insert_at).strftime('%Y-%m-%d %H-%M'),
            'update_at': localtime(p.update_at).strftime('%Y-%m-%d %H-%M')
        }
        proxies.append(proxy)
    return proxies


# Create your views here.
def index(request):
    page = int(request.GET.get('page', 0))
    total = Proxy.objects.filter(is_proxy=True, state=1).exclude(checked_state=4).count()
    total_page = ceil(total / 10.0)
    pages = ({'page': x, 'text': x + 1} for x in range(max(0, page - 10), min(total_page, page + 10)))

    proxies = get_latest_proxies(page * 10, page * 10 + 10)

    return render(request, 'display/index.html',
                  {'proxies': proxies, 'total_page': total_page, 'total': total, 'page': page, 'pages': pages})


def get_ip(request):
    ip_info = {
        'REMOTE_ADDR': request.META.get('REMOTE_ADDR'),
        'HTTP_VIA': request.META.get('HTTP_VIA'),
        'HTTP_X_FORWARDED_FOR': request.META.get('HTTP_X_FORWARDED_FOR')
    }
    return JsonResponse(ip_info)


@cache_page(20 * 15)
def get_latest(request):
    return JsonResponse({'data': get_latest_proxies(0, 100)})
