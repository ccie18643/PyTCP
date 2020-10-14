#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack simulation version 0.1 - 2020, Sebastian Majewski
ph_ip.py - packet handler libary for IP protocol

"""

import socket
import struct
import array


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

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17


IP_PROTO_TABLE = {
    IP_PROTO_ICMP: "ICMP",
    IP_PROTO_TCP: "TCP",
    IP_PROTO_UDP: "UDP",
}

DSCP_TABLE = {
    0b000000: "CS0",
    0b001000: "CS1",
    0b010000: "CS2",
    0b011000: "CS3",
    0b100000: "CS4",
    0b101000: "CS5",
    0b110000: "CS6",
    0b111000: "CS7",
    0b001010: "AF11",
    0b001100: "AF12",
    0b001100: "AF13",
    0b010010: "AF11",
    0b010100: "AF12",
    0b010100: "AF13",
    0b011010: "AF11",
    0b011100: "AF12",
    0b011100: "AF13",
    0b100010: "AF11",
    0b100100: "AF12",
    0b100100: "AF13",
    0b101110: "EF",
}

ECN_TABLE = {
    0b00: "Non-ECT",
    0b10: "ECT(0)",
    0b01: "ECT(1)",
    0b11: "CE",
}


class IpPacket:
    """ IP packet support class """

    def __init__(self, raw_packet=None):
        """ Read raw header data or create blank header """

        if raw_packet:

            self.raw_header = raw_packet[:20]
            self.raw_options = raw_packet[20 : (raw_packet[0] & 0b00001111) << 2]
            self.raw_data = raw_packet[(raw_packet[0] & 0b00001111) << 2 : struct.unpack("!H", self.raw_header[2:4])[0]]

            self.ver = self.raw_header[0] >> 4
            self.hlen = (self.raw_header[0] & 0b00001111) << 2
            self.dscp = (self.raw_header[1] & 0b11111100) >> 2
            self.ecn = self.raw_header[1] & 0b00000011
            self.plen = struct.unpack("!H", self.raw_header[2:4])[0]
            self.id = struct.unpack("!H", self.raw_header[4:6])[0]
            self.frag_df = bool(struct.unpack("!H", self.raw_header[6:8])[0] & 0b0100000000000000)
            self.frag_mf = bool(struct.unpack("!H", self.raw_header[6:8])[0] & 0b0010000000000000)
            self.frag_offset = struct.unpack("!H", self.raw_header[6:8])[0] & 0b0001111111111111
            self.ttl = self.raw_header[8]
            self.proto = self.raw_header[9]
            self.cksum = struct.unpack("!H", self.raw_header[10:12])[0]
            self.src = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[12:16])[0])
            self.dst = socket.inet_ntoa(struct.unpack("!4s", self.raw_header[16:20])[0])

        else:
            self.ver = 4
            self.hlen = 20
            self.dscp = 0
            self.ecn = 0
            self.plen = None
            self.id = 0
            self.frag_df = False
            self.frag_mf = False
            self.frag_offset = 0
            self.ttl = 64
            self.proto = None
            self.cksum = 0
            self.src = None
            self.dst = None

    @property
    def raw_packet(self):
        """ Get raw ip header data """

        return (
            struct.pack(
                "! BBH HH BBH 4s 4s",
                self.ver << 4 | self.hlen >> 2,
                self.dscp << 2 | self.ecn,
                self.plen,
                self.id,
                self.frag_df << 14 | self.frag_mf << 13 | self.frag_offset,
                self.ttl,
                self.proto,
                self.compute_cksum(),
                socket.inet_aton(self.src),
                socket.inet_aton(self.dst),
            )
            + self.raw_options + self.raw_data
        )

    def compute_cksum(self):
        """ Compute the checksum for IP header """

        cksum_header = list(
            struct.unpack(
                f"! {self.hlen >> 1}H",
                struct.pack(
                    "! BBH HH BBH 4s 4s",
                    self.ver << 4 | self.hlen >> 2,
                    self.dscp << 2 | self.ecn,
                    self.plen,
                    self.id,
                    self.frag_df << 14 | self.frag_mf << 13 | self.frag_offset,
                    self.ttl,
                    self.proto,
                    0,
                    socket.inet_aton(self.src),
                    socket.inet_aton(self.dst),
                ) + self.raw_options,
            )
        )

        cksum = sum(cksum_header)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    @property
    def ip_pseudo_header(self):
        """ Returns IP pseudo header that is used by TCP to compute its checksum """

        return struct.unpack(
            "! HH HH HH",
            struct.pack(
                "! 4s 4s BBH",
                socket.inet_aton(self.src),
                socket.inet_aton(self.dst),
                0,
                self.proto,
                self.plength - self.hlen,
            ),
        )

    @property
    def log(self):
        """ Short packet log string """

        return f"IP {self.src} > {self.dst}, proto {self.proto} ({IP_PROTO_TABLE.get(self.proto, '???')})"

    @property
    def dump(self):
        """ Verbose packet debug string """

        return (
            "--------------------------------------------------------------------------------\n"
            + f"IP       SRC {self.src}  DST {self.dst}  VER {self.ver}  CKSUM {self.cksum} ({'OK' if self.compute_cksum() == self.cksum else 'BAD'})\n"
            + f"         DSCP {self.dscp:0>6b} ({DSCP_TABLE.get(self.dscp, 'ERR')})  ECN {self.ecn:0>2b} ({ECN_TABLE[self.ecn]})  "
            + f"HLEN {self.hlen}  PLEN {self.plen}\n         TTL {self.ttl}  ID {self.id}  FRAG FLAGS |{'DF|' if self.frag_df else '  |'}"
            + f"{'MF' if self.frag_mf else '  |'} OFFSET {self.frag_offset}  PROTO {self.proto} ({IP_PROTO_TABLE.get(self.proto, '???')})"
        )
