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
RESPONSE_PROTOCOL = 253

class KVSQuery(Packet):
    name = "KVSQuery"
    fields_desc= [BitField("protocol", 0, 8),
                IntField("key", 0),
                IntField("key2", 0),
                IntField("value", 0),
                IntField("clientID", 0),
                BitField("switchID", 0, 2),                
                BitField("pingPong", 0, 2),
                BitField("queryType", 0, 2),
                BitField("padding", 0, 2),
                BitField("readWriteAccess", 0, 8)]

class Response(Packet):
    name = "Response"
    fields_desc= [IntField("value", 0),
                BitField("isNull", 0, 1),
                BitField("nextType", 0, 1),
                BitField("padding", 0, 6)]

bind_layers(IP, KVSQuery, proto = KVSQUERY_PROTOCOL)
bind_layers(KVSQuery, Response, protocol = RESPONSE_PROTOCOL)
bind_layers(Response, Response, nextType = 0)
bind_layers(Response, TCP, nextType = 1)

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

def get_packet_layers(packet):
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break

        yield layer
        counter += 1

count = 0
def handle_pkt(pkt):
    global count
    print pkt[KVSQuery].padding
    print pkt[KVSQuery].switchID
    if KVSQuery in pkt and pkt[KVSQuery].padding == 1:
        count += 1
        # print count
        # print pkt[KVSQuery].pingPong
        # print pkt[KVSQuery].switchID
        if pkt[KVSQuery].readWriteAccess == 1:
            print "Client " + str(pkt[KVSQuery].clientID) + "has no read access at key " + str(pkt[KVSQuery].key)
            return
        if pkt[KVSQuery].readWriteAccess == 2:
            print "Client " + str(pkt[KVSQuery].clientID) + "has no write access at key " + str(pkt[KVSQuery].key)
            return

        if pkt[KVSQuery].pingPong == 2:
            print "Pong received by Switch " + str(pkt[KVSQuery].switchID)
            print "------------------------"
            return
        if pkt[KVSQuery].pingPong == 3:
            print "Pings/pongs are not within bound. Failure: Switch " + str(pkt[KVSQuery].switchID)
            print "------------------------"
            return

        if pkt[KVSQuery].queryType == 0:
            if pkt[Response].isNull == 0:
                print "NULL" # Replace with large number
            else:
                print pkt[Response].value
        elif pkt[KVSQuery].queryType == 1:
            print 'Value stored.'
        elif pkt[KVSQuery].queryType == 2:
            #print pkt[KVSQuery].switchID
            for layer in reversed(list(get_packet_layers(pkt))):
                if layer.name == "Response" and layer.nextType == 0:
                    if layer.isNull == 0:
                        print "NULL"
                    else:
                        print layer.value
            #print pkt.summary()
        print "------------------------"




def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
