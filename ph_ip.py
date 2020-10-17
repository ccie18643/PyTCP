#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_ip.py - packet handler libary for IP protocol

"""

import socket
import struct


"""

   IP protocol header

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |   DSCP    |ECN|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Options                    ~    Padding    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

IP_HEADER_LEN = 20

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


IP_PROTO_TABLE = {
    IP_PROTO_ICMP: "ICMP",
    IP_PROTO_TCP: "TCP",
    IP_PROTO_UDP: "UDP",
}


DSCP_CS0 = 0b000000
DSCP_CS1 = 0b001000
DSCP_AF11 = 0b001010
DSCP_AF12 = 0b001100
DSCP_AF13 = 0b001110
DSCP_CS2 = 0b010000
DSCP_AF21 = 0b010010
DSCP_AF22 = 0b010100
DSCP_AF23 = 0b010110
DSCP_CS3 = 0b011000
DSCP_AF31 = 0b011010
DSCP_AF32 = 0b011100
DSCP_AF33 = 0b011110
DSCP_CS4 = 0b100000
DSCP_AF41 = 0b100010
DSCP_AF42 = 0b100100
DSCP_AF43 = 0b100110
DSCP_CS5 = 0b101000
DSCP_EF = 0b101110
DSCP_CS6 = 0b110000
DSCP_CS7 = 0b111000

DSCP_TABLE = {
    DSCP_CS0: "CS0",
    DSCP_CS1: "CS1",
    DSCP_AF11: "AF11",
    DSCP_AF12: "AF12",
    DSCP_AF13: "AF13",
    DSCP_CS2: "CS2",
    DSCP_AF21: "AF21",
    DSCP_AF22: "AF22",
    DSCP_AF23: "AF23",
    DSCP_CS3: "CS3",
    DSCP_AF31: "AF31",
    DSCP_AF32: "AF32",
    DSCP_AF33: "AF33",
    DSCP_CS4: "CS4",
    DSCP_AF41: "AF41",
    DSCP_AF42: "AF42",
    DSCP_AF43: "AF43",
    DSCP_CS5: "CS5",
    DSCP_EF: "EF",
    DSCP_CS6: "CS6",
    DSCP_CS7: "CS7",
}

ECN_TABLE = {
    0b00: "Non-ECT",
    0b10: "ECT(0)",
    0b01: "ECT(1)",
    0b11: "CE",
}


class IpPacket:
    """ Base class fo IP packet """

    def validate_cksum(self):
        """ Validate checksum for received header """

        cksum_data = list(struct.unpack(f"! {self.hdr_hlen >> 1}H", self.raw_header + self.raw_options))
        cksum_data[5] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF == self.hdr_cksum

    @property
    def ip_pseudo_header(self):
        """ Returns IP pseudo header that is used by TCP to compute its checksum """

        return struct.unpack(
            "! HH HH HH",
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(self.hdr_src),
                socket.inet_aton(self.hdr_dst),
                0,
                self.hdr_proto,
                self.hdr_plen - self.hdr_hlen,
            ),
        )

    @property
    def log(self):
        """ Short packet log string """

        return f"IP {self.hdr_src} > {self.hdr_dst}, proto {self.hdr_proto} ({IP_PROTO_TABLE.get(self.hdr_proto, '???')})"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"IP       SRC {self.hdr_src}  DST {self.hdr_dst}  VER {self.hdr_ver}  CKSUM {self.hdr_cksum} ({'OK' if self.validate_cksum() else 'BAD'})\n"
            + f"         DSCP {self.hdr_dscp:0>6b} ({DSCP_TABLE.get(self.hdr_dscp, 'ERR')})  ECN {self.hdr_ecn:0>2b} ({ECN_TABLE[self.hdr_ecn]})  "
            + f"HLEN {self.hdr_hlen}  PLEN {self.hdr_plen}\n         TTL {self.hdr_ttl}  ID {self.hdr_id}  FRAG FLAGS |{'DF|' if self.hdr_frag_df else '  |'}"
            + f"{'MF' if self.hdr_frag_mf else '  |'} OFFSET {self.hdr_frag_offset}  PROTO {self.hdr_proto} ({IP_PROTO_TABLE.get(self.hdr_proto, '???')})"
        )


class IpPacketRx(IpPacket):
    """ IP packet parse class """

    def __init__(self, raw_packet):
        """ Class constructor """

        self.raw_packet = raw_packet

        self.hdr_ver = self.raw_header[0] >> 4
        self.hdr_hlen = (self.raw_header[0] & 0b00001111) << 2
        self.hdr_dscp = (self.raw_header[1] & 0b11111100) >> 2
        self.hdr_ecn = self.raw_header[1] & 0b00000011
        self.hdr_plen = struct.unpack("!H", self.raw_header[2:4])[0]
        self.hdr_id = struct.unpack("!H", self.raw_header[4:6])[0]
        self.hdr_frag_df = bool(struct.unpack("!H", self.raw_header[6:8])[0] & 0b0100000000000000)
        self.hdr_frag_mf = bool(struct.unpack("!H", self.raw_header[6:8])[0] & 0b0010000000000000)
        self.hdr_frag_offset = struct.unpack("!H", self.raw_header[6:8])[0] & 0b0001111111111111
        self.hdr_ttl = self.raw_header[8]
        self.hdr_proto = self.raw_header[9]
        self.hdr_cksum = struct.unpack("!H", self.raw_header[10:12])[0]
        self.hdr_src = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[12:16])[0])
        self.hdr_dst = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[16:20])[0])

    @property
    def raw_header(self):
        """ Get packet header in raw format """

        return self.raw_packet[:IP_HEADER_LEN]

    @property
    def raw_options(self):
        """ Get packet header options in raw format """

        return self.raw_packet[IP_HEADER_LEN:(self.raw_packet[0] & 0b00001111) << 2]

    @property
    def raw_data(self):
        """ Get packet header in raw format """

        return self.raw_packet[(self.raw_packet[0] & 0b00001111) << 2:struct.unpack("!H", self.raw_header[2:4])[0]]


class IpPacketTx(IpPacket):
    """ IP packet creation class """

    def __init__(self, hdr_src, hdr_dst, hdr_proto, hdr_ttl=64, raw_options=b"", raw_data=b""):
        """ Class constructor """

        self.hdr_ver = 4
        self.hdr_hlen = None
        self.hdr_dscp = 0
        self.hdr_ecn = 0
        self.hdr_plen = None
        self.hdr_id = 0
        self.hdr_frag_df = False
        self.hdr_frag_mf = False
        self.hdr_frag_offset = 0
        self.hdr_ttl = hdr_ttl
        self.hdr_proto = hdr_proto
        self.hdr_cksum = None
        self.hdr_src = hdr_src
        self.hdr_dst = hdr_dst

        self.raw_options = raw_options
        self.raw_data = raw_data

    @property
    def raw_header(self):
        """ Get packet header in raw form """

        return struct.pack(
            "! BBH HH BBH 4s 4s",
            self.hdr_ver << 4 | self.hdr_hlen >> 2,
            self.hdr_dscp << 2 | self.hdr_ecn,
            self.hdr_plen,
            self.hdr_id,
            self.hdr_frag_df << 14 | self.hdr_frag_mf << 13 | self.hdr_frag_offset,
            self.hdr_ttl,
            self.hdr_proto,
            self.hdr_cksum,
            socket.inet_aton(self.hdr_src),
            socket.inet_aton(self.hdr_dst),
        )

    @property
    def raw_packet(self):
        """ Get packet in raw form """

        self.hdr_hlen = IP_HEADER_LEN + len(self.raw_options)
        self.hdr_plen = IP_HEADER_LEN + len(self.raw_options) + len(self.raw_data)

        self.hdr_cksum = 0
        cksum = sum(list(struct.unpack(f"! {self.hdr_hlen >> 1}H", self.raw_header + self.raw_options)))
        self.hdr_cksum = ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

        return self.raw_header + self.raw_options + self.raw_data
