# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/21

"""
import logging
import time
import json
import warnings
import asyncio
from pprint import pprint
from aiohttp import ClientSession, TCPConnector
from aiohttp.client_exceptions import ClientConnectionError, ClientHttpProxyError, ClientResponseError
from .scanner import PortScanner

BASE_TIMEOUT = 5
FAST_SCAN_TIMEOUT = 10
SEMAPHORE = asyncio.Semaphore(1000)


class HTTPError:
    Timeout = 0
    ProxyError = 1
    CertificateError = 2


class ProxyState:
    default = 0
    open = 1
    closed = 2
    filtered = 3
    unfiltered = 4
    open_filtered = 5
    closed_filtered = 6


class ProxyCheckedState:
    Default = 0
    TransparentProxy = 1
    AnonymousProxy = 2
    HighAnonymousProxy = 3
    NeedAuthProxy = 4
    MitmProxy = 5


class ProxyProtocol:
    default = 0
    http = 1
    https = 2
    http_https = 3
    socks = 4


async def _request(url, method, proxy, timeout, verify_ssl):
    async with SEMAPHORE:
        async with ClientSession(connector=TCPConnector(verify_ssl=verify_ssl)) as session:
            async with getattr(session, method.lower())(url, proxy=proxy, timeout=timeout) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    return content
                if proxy:
                    raise ClientHttpProxyError(history='%d get' % resp.status, request_info=url)
                else:
                    raise ClientConnectionError('%d get' % resp.status)


async def request(url, method='head', proxy=None, timeout=BASE_TIMEOUT, verify_ssl=True):
    try:
        start = time.time()
        rt = await _request(url, method, proxy, timeout, verify_ssl)
        speed = (time.time() - start) * 100
        # print(rt)
    except asyncio.TimeoutError as e:
        logging.debug("{} :{}".format(str(type(e)), e))
        return HTTPError.Timeout
    except (ClientHttpProxyError, ClientConnectionError, ClientResponseError) as e:
        if str(e).find('CERTIFICATE_VERIFY_FAILED') > 0:
            return HTTPError.CertificateError
        logging.debug("{} :{}".format(str(type(e)), e))
        return HTTPError.ProxyError
    else:
        return rt, speed


async def check_proxy_type(check_ip_url, proxy_url, base_ip, timeout=60):
    res = await request(url=check_ip_url, method='get', proxy=proxy_url, timeout=timeout)
    if isinstance(res, int):
        logging.debug('checked', proxy_url, 'meet error', 'return Default')
        return ProxyCheckedState.Default
    else:
        header, _ = res
        try:
            data = json.loads(header.decode())
            via, x_for = data['HTTP_VIA'], data['HTTP_X_FORWARDED_FOR']
        except KeyError as e:
            # if return json but not like
            # {'HTTP_VIA': '', 'HTTP_X_FORWARDED_FOR': '', 'REMOTE_ADDR': '111.111.1111.111'}
            # return Default
            return ProxyCheckedState.Default
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return ProxyCheckedState.NeedAuthProxy
        else:
            if via and x_for and x_for == base_ip:
                return ProxyCheckedState.TransparentProxy
            if via and x_for and x_for != base_ip:
                return ProxyCheckedState.AnonymousProxy
            if not via and not x_for:
                return ProxyCheckedState.HighAnonymousProxy
            warnings.warn("%s: can't check type" % check_ip_url)
            return ProxyCheckedState.Default


async def check_proxy(ips, port, base_ip, check_ip_url):
    """

    :param ips:
    :param port:
    :param base_ip:
    :param check_ip_url: a web can return request header { REMOTE_ADDR, HTTP_VIA, HTTP_X_FORWARDED_FOR}
    :return:
    """
    result = {}
    scanner = PortScanner(ips, port=port)
    scanner.scan()
    while scanner.is_running:
        await asyncio.sleep(1)
    scan_result = scanner.result['scan']
    for ip in ips:
        result[ip] = dict(is_checked=True)
        ip_scan = scan_result.get(ip)
        if not ip_scan or (ip_scan and ip_scan.get('tcp') is None):
            result[ip]['state'] = ProxyState.closed
        else:
            tcp = ip_scan['tcp']
            result[ip]['state'] = getattr(ProxyState, tcp[port]['state'].replace('|', '_'))
            if tcp[port]['state'] == 'open':
                proxy_url = 'http://%s:%d' % (ip, port)
                res = await request(url='http://www.baidu.com', proxy=proxy_url)
                logging.debug('http response is %s' % str(res))
                if isinstance(res, int):
                    # TODO: check http is block but https is OK
                    result[ip]['is_proxy'] = False
                    continue
                _, speed = res
                result[ip]['speed'] = speed  # use http request speed
                # Check https

                res = await request(url='https://www.baidu.com', proxy=proxy_url)
                if isinstance(res, int):
                    if res == HTTPError.CertificateError:  # middle man attack proxy
                        res = await request(url='https://www.baidu.com', proxy=proxy_url, verify_ssl=False)
                        if not isinstance(res, int):
                            result[ip]['checked_state'] = ProxyCheckedState.MitmProxy
                            result[ip]['protocol'] = ProxyProtocol.http_https
                        else:  # may be need auth
                            result[ip]['checked_state'] = ProxyCheckedState.NeedAuthProxy
                            result[ip]['protocol'] = ProxyProtocol.http_https
                    elif res == HTTPError.Timeout:
                        result[ip]['protocol'] = ProxyProtocol.http_https
                        result[ip]['checked_state'] = await check_proxy_type(check_ip_url, proxy_url, base_ip,
                                                                             FAST_SCAN_TIMEOUT)
                    else:
                        result[ip]['protocol'] = ProxyProtocol.http
                        result[ip]['checked_state'] = await check_proxy_type(check_ip_url, proxy_url, base_ip,
                                                                             FAST_SCAN_TIMEOUT)
                else:
                    result[ip]['protocol'] = ProxyProtocol.http_https
                    result[ip]['checked_state'] = await check_proxy_type(check_ip_url, proxy_url, base_ip)

                # if not set real state , set is_proxy = False
                result[ip]['is_proxy'] = result[ip]['checked_state'] != ProxyCheckedState.Default
    # pprint(result)
    return result


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(check_proxy(['180.169.57.100:3389'],
                                        80, '182.96.183.104', 'http://115.159.146.115/ip'))
