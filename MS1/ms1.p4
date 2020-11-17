/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_KVSQUERY = 252;
const bit<8> TYPE_TCP = 6;
const bit<16> TYPE_RESPONSE = 0x1234;


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

header kvsQuery_t {
    bit<8> protocol;
    bit<32> key;
    bit<32> key2;
    bit<32> value;
    bit<32> versionNum;
    bit<2> switchID;
    bit<2> pingPong;
    bit<2> queryType;
    bit<2> padding;
}

header response_t {
    bit<32> value;
    bit<1> isNull;
    bit<1> nextType;
    bit<6> padding;
}

struct metadata {
    bit<16> ecmp_select;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    response_t[1025]     response;
    tcp_t        tcp;
    kvsQuery_t   kvsQuery;
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
    		TYPE_RESPONSE: parse_response;
    		default: accept;
    	}
    }

    state parse_response {
        packet.extract(hdr.response.next); 
        transition select(hdr.response.last.nextType) {
            1: parse_ipv4; // last header in the header stack
            0: parse_response; // parse the next header
            default: accept;
        }
    }

    state parse_ipv4{
    	packet.extract(hdr.ipv4);
    	transition select (hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_KVSQUERY: parse_kvsQuery;
            default: accept;
        }
    }

    state parse_kvsQuery{
        packet.extract(hdr.kvsQuery);
        transition select (hdr.kvsQuery.protocol) {
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

    register <bit<32>>(6150) database;
    register <bit<1>>(1025) isFilled;
    register <bit<32>>(1025) latestVersion;

    // Setting the egress port and IP destination.
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        hdr.ipv4.dstAddr = nhop_ipv4;
        standard_metadata.egress_spec = port;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action get() {
        bit<32> versionNum = hdr.kvsQuery.versionNum;
        // database.read(hdr.kvsQuery.value, hdr.kvsQuery.key);
        // isFilled.read(hdr.kvsQuery.isNull, hdr.kvsQuery.key);{
        database.read(hdr.response[0].value, hdr.kvsQuery.key + 1025 * versionNum);
        isFilled.read(hdr.response[0].isNull, hdr.kvsQuery.key);
        bit<32> latest = 0;
        latestVersion.read(latest, hdr.kvsQuery.key);
        if (hdr.kvsQuery.versionNum > 5 || hdr.kvsQuery.versionNum > latest - 1) {
            hdr.response[0].isNull = 0;
        }
    }

    action put() {
        bit<32> versionNum = 0;
        latestVersion.read(versionNum, hdr.kvsQuery.key);
        database.write(hdr.kvsQuery.key + 1025 * versionNum, hdr.kvsQuery.value);
        latestVersion.write(hdr.kvsQuery.key, versionNum + 1);
        isFilled.write(hdr.kvsQuery.key, 1);
    }

    action rangeGet() {
        bit<32> versionNum = hdr.kvsQuery.versionNum;
        hdr.response.push_front(1);
        hdr.response[0].setValid();
        database.read(hdr.response[0].value, hdr.kvsQuery.key + 1025 * versionNum);
        isFilled.read(hdr.response[0].isNull, hdr.kvsQuery.key);
        hdr.kvsQuery.key = hdr.kvsQuery.key + 1;
        // hdr.kvsQuery.index = hdr.kvsQuery.index + 1;
    }
    
    table Forwarding {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop;
            set_nhop;
        }
    }

    // 0: GET
    // 1: PUT
    // 2: RANGE
    // 3: SELECT
    table Ops {
        key = {
            hdr.kvsQuery.queryType: exact;
        }
        actions = {
            drop;
            get;
            put;
            rangeGet;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
    	if (hdr.response[0].isValid()) {
            Forwarding.apply();
            Ops.apply();
            hdr.kvsQuery.padding = 1;
            // Cap the version number to 5
            if (hdr.kvsQuery.queryType == 1) {
                bit<32> versionNum = 0;
                latestVersion.read(versionNum, hdr.kvsQuery.key);
                if (versionNum > 5) {
                    latestVersion.write(hdr.kvsQuery.key, 5);
                }
            }
            // Recirculate for range requests
            if (hdr.kvsQuery.queryType == 2) {
            	if (hdr.kvsQuery.key < hdr.kvsQuery.key2){
            		// clone(CloneType.I2E, 1);
            		recirculate(meta);
            	}
            }

            // if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL) {
            //     // Normal packet
            //     // Forwarding.apply();
            //     // Ops.apply();
            //     // hdr.kvsQuery.padding = 1;
            //     if (hdr.kvsQuery.queryType == 2) {
            //         recirculate(meta);
            //     }
            // } else if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_RECIRC) {
            //     // Recirculated packet
            //     // hdr.ipv4.ttl = 2;
            //     Forwarding.apply();
            //     Ops.apply();
            //     if (hdr.kvsQuery.key < hdr.kvsQuery.key2) {
            //         
            //         clone(CloneType.I2E, 1);
            //         recirculate(meta);
            //     }
            // }
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
        packet.emit(hdr.ethernet);
        packet.emit(hdr.response);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.kvsQuery);
        packet.emit(hdr.tcp);
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
