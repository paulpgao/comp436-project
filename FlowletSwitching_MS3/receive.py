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


sequences = []
total_packets = 0
total_bytes = 0
total_S2_packet_count = 0
total_S3_packet_count = 0
total_S2_bytes = 0
total_S3_bytes = 0
total_inversions = 0
query_count = 0

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

# Counts the number of inversions inside list A
def count_inversions(A):
    count = 0
    for i in range(0, len(A) - 1):
        for j in range(i, len(A)):
            if A[i] > A[j]:
                count += 1
    return count


def handle_pkt(pkt):
    global sequences
    global total_packets
    global total_bytes
    global total_S2_packet_count
    global total_S3_packet_count
    global total_S2_bytes
    global total_S3_bytes
    global total_inversions
    global query_count
    if Query in pkt:
        # pkt.show()
        total_packets += pkt[Query].s2PacketCount + pkt[Query].s3PacketCount
        total_bytes += pkt[Query].s2BytesCount + pkt[Query].s3BytesCount
        total_S2_packet_count += pkt[Query].s2PacketCount
        total_S3_packet_count += pkt[Query].s3PacketCount
        total_S2_bytes += pkt[Query].s2BytesCount
        total_S3_bytes += pkt[Query].s3BytesCount
        total_inversions += count_inversions(sequences)
        query_count += 1
        print (pkt[Query].s2PacketCount)
        print (pkt[Query].s3PacketCount)
        print ("Total Packets: " + str(total_packets))
        print ("Total Bytes: " + str(total_bytes))
        print ("S2 path packet count: " + str(total_S2_packet_count))
        print ("S3 path packet count: " + str(total_S3_packet_count))
        print ("S2 path bytes count: " + str(total_S2_bytes))
        print ("S3 path bytes count: " + str(total_S3_bytes))
        # print ("Packet order: " + str(sequences))
        print ("Total number of inversions: " + str(total_inversions))
        print ("Average number of inversions: " + str(total_inversions * 1.0 / query_count))
        sequences = []
    if TCP in pkt and pkt[TCP].dport == 1234:
        sequences.append(pkt[TCP].seq)




def main():
    global sequences
    global total_packets
    global total_bytes
    global total_S2_packet_count
    global total_S3_packet_count
    global total_S2_bytes
    global total_S3_bytes
    global total_inversions
    global query_count

    sequences = []
    total_packets = 0
    total_bytes = 0
    total_S2_packet_count = 0
    total_S3_packet_count = 0
    total_S2_bytes = 0
    total_S3_bytes = 0
    total_inversions = 0
    query_count = 0

    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
