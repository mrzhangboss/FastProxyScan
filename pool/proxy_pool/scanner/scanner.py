# -*- coding:utf-8 -*-
"""
@author: zhanglun <zhanglun.me@gmail.com>
@github:  mrzhangboss
@date: 2017/11/19

"""
import os
import logging
from subprocess import PIPE
from collections import Iterable
from xml.etree import ElementTree as ET
from datetime import datetime
import psutil


class BColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class PortScanner:
    def __init__(self, host, port=None, exclude=None, host_timeout=360):
        self._host = host
        self._process = None
        self._port = port
        self._stdout = None
        self._exclude = exclude
        self._host_timeout = host_timeout
        assert self._exclude is None or (self._exclude and isinstance(self._exclude, Iterable))

    def check_finished(self):
        p = self._process
        logging.debug('{}: check {} process'.format(datetime.now(), p.pid))
        if p and p.is_running() and p.status() == 'zombie':
            self._stdout = p.stdout.read()
            p.wait()
        return p.is_running()

    @property
    def is_running(self):
        return self.check_finished()

    def scan(self):
        not_root = os.getuid() != 0
        if not_root:
            print(BColors.FAIL + "You are not root.Please check if you have sudo premission" + BColors.ENDC)
        exclude = ['--exclude', *self._exclude] if self._exclude else []
        commands = ['sudo'] * not_root + ['nmap', '-oX', '-', '-sS', '-T4',
                                          '-p %s' % str(self._port) if self._port else '-F',
                                          '--host-timeout',  str(self._host_timeout),
                                          *exclude, self._host]
        self._process = psutil.Popen(commands, stdout=PIPE)

    @property
    def result(self):
        """


        :return:

        xml like
        <?xml version="1.0" encoding="utf-8"?>
        <?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>

        <!-- Nmap 6.40 scan initiated Sun Nov 19 22:51:07 2017 as: nmap -oX - -p 1-100 -sS 124.89.33.59 -->
        <nmaprun scanner="nmap" args="nmap -oX - -p 1-100 -sS 124.89.33.59" start="1511103067" startstr="Sun Nov 19 22:51:07 2017" version="6.40" xmloutputversion="1.04">
          <scaninfo type="syn" protocol="tcp" numservices="100" services="1-100"/>
          <verbose level="0"/>
          <debugging level="0"/>
          <host starttime="1511103067" endtime="1511103072">
            <status state="up" reason="echo-reply" reason_ttl="53"/>
            <address addr="124.89.33.59" addrtype="ipv4"/>
            <hostnames></hostnames>
            <ports>
              <extraports state="closed" count="95">
                <extrareasons reason="resets" count="95"/>
              </extraports>
              <port protocol="tcp" portid="21">
                <state state="open" reason="syn-ack" reason_ttl="53"/>
                <service name="ftp" method="table" conf="3"/>
              </port>
              <port protocol="tcp" portid="22">
                <state state="open" reason="syn-ack" reason_ttl="52"/>
                <service name="ssh" method="table" conf="3"/>
              </port>
              <port protocol="tcp" portid="23">
                <state state="open" reason="syn-ack" reason_ttl="52"/>
                <service name="telnet" method="table" conf="3"/>
              </port>
              <port protocol="tcp" portid="53">
                <state state="open" reason="syn-ack" reason_ttl="53"/>
                <service name="domain" method="table" conf="3"/>
              </port>
              <port protocol="tcp" portid="80">
                <state state="filtered" reason="no-response" reason_ttl="0"/>
                <service name="http" method="table" conf="3"/>
              </port>
            </ports>
            <times srtt="42026" rttvar="15997" to="106014"/>
          </host>
          <runstats>
            <finished time="1511103072" timestr="Sun Nov 19 22:51:12 2017" elapsed="4.97" summary="Nmap done at Sun Nov 19 22:51:12 2017; 1 IP address (1 host up) scanned in 4.97 seconds" exit="success"/>
            <hosts up="1" down="0" total="1"/>
          </runstats>
        </nmaprun>


        """

        if self.is_running:
            return {}
        if hasattr(self, '_scan_result'):
            return self._scan_result
        scan_result = {}

        dom = ET.fromstring(self._stdout)
        scan_result['nmap'] = {
            'command_line': dom.get('args'),
            'scaninfo': {},
            'scanstats': {
                'start': dom.get('start'),
                'timestr': dom.find("runstats/finished").get('timestr'),
                'end': dom.find("runstats/finished").get('time'),
                'elapsed': dom.find("runstats/finished").get('elapsed'),
                'uphosts': dom.find("runstats/hosts").get('up'),
                'downhosts': dom.find("runstats/hosts").get('down'),
                'totalhosts': dom.find("runstats/hosts").get('total')}
        }

        # nmap command line

        # info about scan
        for dsci in dom.findall('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.get('protocol')] = {
                'method': dsci.get('type'),
                'services': dsci.get('services')
            }

        scan_result['scan'] = {}

        for dhost in dom.findall('host'):
            # host ip, mac and other addresses
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall('address'):
                addtype = address.get('addrtype')
                address_block[addtype] = address.get('addr')
                if addtype == 'ipv4':
                    host = address_block[addtype]
                elif addtype == 'mac' and address.get('vendor') is not None:
                    vendor_block[address_block[addtype]] = address.get('vendor')

            if host is None:
                host = dhost.find('address').get('addr')

            hostnames = []
            if len(dhost.findall('hostnames/hostname')) > 0:
                for dhostname in dhost.findall('hostnames/hostname'):
                    hostnames.append({
                        'name': dhostname.get('name'),
                        'type': dhostname.get('type'),
                    })
            else:
                hostnames.append({
                    'name': '',
                    'type': '',
                })

            scan_result['scan'][host] = dict({'hostnames': hostnames})

            scan_result['scan'][host]['addresses'] = address_block
            scan_result['scan'][host]['vendor'] = vendor_block

            for dstatus in dhost.findall('status'):
                # status : up...
                scan_result['scan'][host]['status'] = {'state': dstatus.get('state'),
                                                       'reason': dstatus.get('reason')}
            for dstatus in dhost.findall('uptime'):
                # uptime : seconds, lastboot
                scan_result['scan'][host]['uptime'] = {'seconds': dstatus.get('seconds'),
                                                       'lastboot': dstatus.get('lastboot')}
            for dport in dhost.findall('ports/port'):
                # protocol
                proto = dport.get('protocol')
                # port number converted as integer
                port = int(dport.get('portid'))
                # state of the port
                state = dport.find('state').get('state')
                # reason
                reason = dport.find('state').get('reason')
                # name, product, version, extra info and conf if any
                name = product = version = extrainfo = conf = cpe = ''
                for dname in dport.findall('service'):
                    name = dname.get('name')
                    if dname.get('product'):
                        product = dname.get('product')
                    if dname.get('version'):
                        version = dname.get('version')
                    if dname.get('extrainfo'):
                        extrainfo = dname.get('extrainfo')
                    if dname.get('conf'):
                        conf = dname.get('conf')

                    for dcpe in dname.findall('cpe'):
                        cpe = dcpe.text
                # store everything
                if proto not in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}

                scan_result['scan'][host][proto][port] = {'state': state,
                                                          'reason': reason,
                                                          'name': name,
                                                          'product': product,
                                                          'version': version,
                                                          'extrainfo': extrainfo,
                                                          'conf': conf,
                                                          'cpe': cpe}
                script_id = ''
                script_out = ''
                # get script output if any
                for dscript in dport.findall('script'):
                    script_id = dscript.get('id')
                    script_out = dscript.get('output')
                    if 'script' not in list(scan_result['scan'][host][proto][port].keys()):
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out

            # <hostscript>
            #  <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
            #  <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
            #  <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
            # </hostscript>
            for dhostscript in dhost.findall('hostscript'):
                for dname in dhostscript.findall('script'):
                    hsid = dname.get('id')
                    hsoutput = dname.get('output')

                    if 'hostscript' not in list(scan_result['scan'][host].keys()):
                        scan_result['scan'][host]['hostscript'] = []

                    scan_result['scan'][host]['hostscript'].append(
                        {
                            'id': hsid,
                            'output': hsoutput
                        }
                    )

            # <osmatch name="Juniper SA4000 SSL VPN gateway (IVE OS 7.0)" accuracy="98" line="36241">
            # <osclass type="firewall" vendor="Juniper" osfamily="IVE OS" osgen="7.X"
            # accuracy="98"><cpe>cpe:/h:juniper:sa4000</cpe><cpe>cpe:/o:juniper:ive_os:7</cpe></osclass>
            # </osmatch>
            # <osmatch name="Cymphonix EX550 firewall" accuracy="98" line="17929">
            # <osclass type="firewall" vendor="Cymphonix" osfamily="embedded"
            # accuracy="98"><cpe>cpe:/h:cymphonix:ex550</cpe></osclass>
            # </osmatch>
            for dos in dhost.findall('os'):
                osmatch = []
                portused = []
                for dportused in dos.findall('portused'):
                    # <portused state="open" proto="tcp" portid="443"/>
                    state = dportused.get('state')
                    proto = dportused.get('proto')
                    portid = dportused.get('portid')
                    portused.append({
                        'state': state,
                        'proto': proto,
                        'portid': portid,
                    })

                scan_result['scan'][host]['portused'] = portused

                for dosmatch in dos.findall('osmatch'):
                    # <osmatch name="Linux 3.7 - 3.15" accuracy="100" line="52790">
                    name = dosmatch.get('name')
                    accuracy = dosmatch.get('accuracy')
                    line = dosmatch.get('line')

                    osclass = []
                    for dosclass in dosmatch.findall('osclass'):
                        # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                        ostype = dosclass.get('type')
                        vendor = dosclass.get('vendor')
                        osfamily = dosclass.get('osfamily')
                        osgen = dosclass.get('osgen')
                        accuracy = dosclass.get('accuracy')

                        cpe = []
                        for dcpe in dosclass.findall('cpe'):
                            cpe.append(dcpe.text)

                        osclass.append({
                            'type': ostype,
                            'vendor': vendor,
                            'osfamily': osfamily,
                            'osgen': osgen,
                            'accuracy': accuracy,
                            'cpe': cpe,
                        })

                    osmatch.append({
                        'name': name,
                        'accuracy': accuracy,
                        'line': line,
                        'osclass': osclass
                    })
                else:
                    scan_result['scan'][host]['osmatch'] = osmatch

            for dport in dhost.findall('osfingerprint'):
                # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
                fingerprint = dport.get('fingerprint')

                scan_result['scan'][host]['fingerprint'] = fingerprint

        self._scan_result = scan_result  # store for later use
        return scan_result


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    import time

    scanner = PortScanner('124.89.33.59', None, ('192.168.1.1'))
    scanner.scan()
    for i in range(1000):
        if scanner.is_running:
            time.sleep(2)
            print(time.time())
        else:
            from pprint import pprint

            # logging.debug(scanner._stdout)
            pprint(scanner.result)
            break
