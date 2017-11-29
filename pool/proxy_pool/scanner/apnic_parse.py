# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/29

"""


def parse_nmap_host(line):
    """

    :param line: like  'apnic|CN|ipv4|1.0.1.0|256|20110414|allocated'
                        1.0.1.0 mean ip begin , 256 mean sum total sum
    :return: return domain like 127.0.0.* or 127.0.0.1-128
    """
    l = line.split('|')
    ip, s = l[3], int(l[4])
    a, b, c, d = (int(x) for x in ip.split('.'))
    fmt = '%d.%d.%d.*'
    if s < 256:
        return ['%d.%d.%d.%d-%d' % (a, b, c, d, d + s)]
    if 256 <= s < 256 * 256:
        assert d == 0
        return (fmt % (a, b, x + c) for x in range(s // 256))
    if 256 * 256 <= s < 256 * 256 * 256:
        assert c == 0 and d == 0
        return (fmt % (a, b + y, x) for x in range(256) for y in range(s // 256 // 256))
    if 256 * 256 * 256 <= s < 256 * 256 * 256 * 256:
        assert b == 0 and c == 0 and d == 0
        return (fmt % (a + z, y, x) for x in range(256) for y in range(256) for z in range(s // 256 // 256 // 256))


def get_ip_dress(filename, country='CN'):
    w = open(filename).read()
    starts = 'apnic|%s|ipv4|' % country.upper()
    ip_group = (x for x in w.split('\n') if x.startswith(starts))
    result = []
    for i in ip_group:
        result.extend(parse_nmap_host(i))
    return result


if __name__ == '__main__':
    from pprint import pprint

    pprint(len(get_ip_dress('../delegated-apnic-latest.txt')))
