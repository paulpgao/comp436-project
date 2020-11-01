/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_QUERY = 250;
const bit<8> TYPE_TCP = 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> ByteCounter_t;
typedef bit<32> PacketCounter_t;
typedef bit<80> PacketByteCounter_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header query_t {
    bit<8> protocol;
    bit<32> s2PacketCount;
    bit<32> s3PacketCount;
    bit<32> s2BytesCount;
    bit<32> s3BytesCount;
}


struct metadata {
    bit<16> ecmp_select;
    bit<32> flow_idx;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    query_t      query;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ether;
    }

    state parse_ether{
    	packet.extract(hdr.ethernet);
    	transition select (hdr.ethernet.etherType){
    		TYPE_IPV4: parse_ipv4;
    		default: accept;
    	}
    }

    state parse_ipv4{
    	packet.extract(hdr.ipv4);
    	transition select (hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_QUERY: parse_query;
            default: accept;
        }
    }

    state parse_query{
        packet.extract(hdr.query);
        transition select (hdr.query.protocol) {
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp{
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register <bit<32>>(2) s2counts;
    register <bit<32>>(2) s3counts;

    // Timestamps for each of the 100 flows
    register <bit<48>>(100) timestamps;
    register <bit<16>>(100) flowletIDs;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        bit<16> flowlet_base = 0;
        bit<32> flowlet_count = 100;
        // Hash 5-tuple to 0-99 index for each flow.
        hash(meta.flow_idx,
        HashAlgorithm.crc16,
        flowlet_base,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort },
        flowlet_count);

        // Read past timestamp and flowlet IDs for this flow.
        bit<48> last_timestamp = 0;
        bit<16> flowlet_id = 0;
        timestamps.read(last_timestamp, meta.flow_idx);
        flowletIDs.read(flowlet_id, meta.flow_idx);

        // Increment flowlet ID if difference in timestamp is > 90ms
        if (standard_metadata.ingress_global_timestamp - last_timestamp > 120000) {
            flowlet_id = flowlet_id + 1;
        }

        // Hash new 6-tuple (with flowletID) into 0 or 1 for the path choice.
        // Stores ecmp_select
        hash(meta.ecmp_select,
        HashAlgorithm.crc16,
        ecmp_base,
        { hdr.ipv4.srcAddr,
          hdr.ipv4.dstAddr,
              hdr.ipv4.protocol,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort, 
              flowlet_id},
        ecmp_count);

        // Update registers with new values for this flow.
        timestamps.write(meta.flow_idx, standard_metadata.ingress_global_timestamp);
        flowletIDs.write(meta.flow_idx, flowlet_id);

        // Sets srcPort to the egress port wherein apply stores statistics.
        hdr.tcp.srcPort = meta.ecmp_select + 2;
    }

    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ecmp_group {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_ecmp_select;
        }
        size = 1024;
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }
    
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            ecmp_group.apply();
            ecmp_nhop.apply();

            // Accumulate packet and byte counts during TCP protocol.
            if (hdr.ipv4.protocol == TYPE_TCP) {
                bit<32> tempPacketCount = 0;
                bit<32> tempBytesCount = 0;
                if (hdr.tcp.srcPort == 2) {
                    // Reads current packet and byte counts from registers
                    s2counts.read(tempPacketCount, 0);
                    s2counts.read(tempBytesCount, 1);
                    // Increments packet count by 1, and byte count by packet size
                    tempPacketCount = tempPacketCount + 1;
                    tempBytesCount = tempBytesCount + standard_metadata.packet_length;
                    // Writes and updates registers
                    s2counts.write(0, tempPacketCount);
                    s2counts.write(1, tempBytesCount);
                }
                if (hdr.tcp.srcPort == 3) {
                    // Reads current packet and byte counts from registers
                    s3counts.read(tempPacketCount, 0);
                    s3counts.read(tempBytesCount, 1);
                    // Increments packet count by 1, and byte count by packet size
                    tempPacketCount = tempPacketCount + 1;
                    tempBytesCount = tempBytesCount + standard_metadata.packet_length;
                    // Writes and updates registers
                    s3counts.write(0, tempPacketCount);
                    s3counts.write(1, tempBytesCount);
                }
            }
            else if (hdr.ipv4.protocol == TYPE_QUERY) { // Query packet is sent
                // Reads register counts and sets them into custom header for receiver.
                s2counts.read(hdr.query.s2PacketCount, 0);
                s2counts.read(hdr.query.s2BytesCount, 1);
                s3counts.read(hdr.query.s3PacketCount, 0);
                s3counts.read(hdr.query.s3BytesCount, 1);

                // Clears registers for next usage
                s2counts.write(0, 0);
                s2counts.write(1, 0);
                s3counts.write(0, 0);
                s3counts.write(1, 0);
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.query);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
