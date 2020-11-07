#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import string
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import BitField, ShortField, IntField, bind_layers

QUERY_PROTOCOL = 250
KVSQUERY_PROTOCOL = 252
TCP_PROTOCOL = 6

class KVSQuery(Packet):
    name = "KVSQuery"
    fields_desc= [BitField("protocol", 0, 8),
                BitField("queryType", 0, 2),
                BitField("isNull", 0, 1),
                BitField("padding", 0, 5),
                IntField("key",0),
                IntField("value", 0)]

bind_layers(IP, KVSQuery, proto = KVSQUERY_PROTOCOL)
bind_layers(KVSQuery, TCP, protocol = TCP_PROTOCOL)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def randStr(N=10):
    return ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(N))


def main():
    # if len(sys.argv)<3:
    #     print 'pass 2 arguments: <destination> "<message>"'
    #     exit(1)

    if len(sys.argv) < 2:
        print 'pass 1 argument:"<ops>"'
        exit(1)

    # Specific IP for Switch 1 entrance
    addr = '10.0.1.1'
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))

    if sys.argv[1] == "get":
        if len(sys.argv) < 3:
            print 'pass 1 more argument:"<key>"'
            exit(1)
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / KVSQuery(protocol=TCP_PROTOCOL, queryType=0, key=int(sys.argv[2])) / TCP(dport=1234, sport=random.randint(49152,65535)) / "get"
    elif sys.argv[1] == "put":
        if len(sys.argv) < 4:
            print 'pass 2 more arguments:"<key>" "<value>"'
            exit(1)
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / KVSQuery(protocol=TCP_PROTOCOL, queryType=1, key=int(sys.argv[2]), value=int(sys.argv[3])) / TCP(dport=1234, sport=random.randint(49152,65535)) / "put"
    elif sys.arvg[1] == "range":
        if len(sys.argv) < 4:
            print 'pass 2 more arguments:"<key1>" "<key2>"'
            exit(1)
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr, proto=KVSQUERY_PROTOCOL) / KVSQuery(protocol=TCP_PROTOCOL, queryType=2, key=int(sys.argv[2]), value=int(sys.argv[3])) / TCP(dport=1234, sport=random.randint(49152,65535)) / "range"

        # pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        # pkt = pkt / IP(dst=addr, proto=QUERY_PROTOCOL) / Query(protocol=TCP_PROTOCOL) / TCP(dport=1234, sport=random.randint(49152,65535)) / "query"
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
