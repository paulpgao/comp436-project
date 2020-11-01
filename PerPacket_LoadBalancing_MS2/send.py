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
TCP_PROTOCOL = 6

# Special query header packet
class Query(Packet):
    name = "Query"
    fields_desc=[BitField("protocol", 0, 8),
                 IntField("s2PacketCount", 0),
                 IntField("s3PacketCount", 0),
                 IntField("s2BytesCount", 0),
                 IntField("s3BytesCount", 0)]

bind_layers(IP, Query, proto = QUERY_PROTOCOL)
bind_layers(Query, TCP, protocol = TCP_PROTOCOL)

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
        print 'pass 1 argument:"<message>"'
        exit(1)

    # Specific IP for Switch 1 entrance
    addr = '10.0.0.1'
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))

    # Create 100 random flows
    flows = random.sample(range(49152, 65535), 100)

    # For each flow, send 10-20 packets with random length message
    for flow in flows:
        for i in range(random.randint(10, 20)):
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
            pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=flow, seq=i) / randStr(random.randint(1, 100))
            sendp(pkt, iface=iface, verbose=False)
        time.sleep(1)
        # Send query packet after each flow run
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt /IP(dst=addr) / Query(protocol=QUERY_PROTOCOL) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[1]
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(2)


if __name__ == '__main__':
    main()
