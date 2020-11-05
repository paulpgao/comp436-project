#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR
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
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]

# # Counts the number of inversions inside list A
# def count_inversions(A):
#     count = 0
#     for i in range(0, len(A) - 1):
#         for j in range(i, len(A)):
#             if A[i] > A[j]:
#                 count += 1
#     return count


def handle_pkt(pkt):
    if KVSQuery in pkt:
        if pkt[KVSQuery].queryType == 0:
            print pkt[KVSQuery].value
        elif pkt[KVSQuery].queryType == 1:
            print 'Value stored.'
    elif TCP in pkt and pkt[TCP].dport == 1234:
        print ('here')



def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
