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


IP_PROTO_TABLE = {IP_PROTO_ICMP: "ICMP", IP_PROTO_TCP: "TCP", IP_PROTO_UDP: "UDP"}


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

ECN_TABLE = {0b00: "Non-ECT", 0b10: "ECT(0)", 0b01: "ECT(1)", 0b11: "CE"}


class IpPacket:
    """ IP packet support class """

    protocol = "IP"

    def __init__(
        self,
        parent_packet=None,
        hdr_src=None,
        hdr_dst=None,
        hdr_ttl=64,
        hdr_dscp=0,
        hdr_ecn=0,
        hdr_id=0,
        hdr_frag_df=False,
        hdr_frag_mf=False,
        hdr_frag_offset=0,
        hdr_options=[],
        child_packet=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:IP_HEADER_LEN]
            raw_options = raw_packet[IP_HEADER_LEN : (raw_packet[0] & 0b00001111) << 2]

            self.raw_data = raw_packet[(raw_packet[0] & 0b00001111) << 2 : struct.unpack("!H", raw_header[2:4])[0]]

            self.hdr_ver = raw_header[0] >> 4
            self.hdr_hlen = (raw_header[0] & 0b00001111) << 2
            self.hdr_dscp = (raw_header[1] & 0b11111100) >> 2
            self.hdr_ecn = raw_header[1] & 0b00000011
            self.hdr_plen = struct.unpack("!H", raw_header[2:4])[0]
            self.hdr_id = struct.unpack("!H", raw_header[4:6])[0]
            self.hdr_frag_df = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0100000000000000)
            self.hdr_frag_mf = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0010000000000000)
            self.hdr_frag_offset = struct.unpack("!H", raw_header[6:8])[0] & 0b0001111111111111
            self.hdr_ttl = raw_header[8]
            self.hdr_proto = raw_header[9]
            self.hdr_cksum = struct.unpack("!H", raw_header[10:12])[0]
            self.hdr_src = socket.inet_ntoa(struct.unpack("!4s", raw_header[12:16])[0])
            self.hdr_dst = socket.inet_ntoa(struct.unpack("!4s", raw_header[16:20])[0])

            self.hdr_options = []

            i = 0

            while i < len(raw_options):
                if raw_options[i] == IP_OPT_EOL:
                    self.hdr_options.append(IpOptEol(raw_options[i : i + IP_OPT_EOL_LEN]))
                    break

                elif raw_options[i] == IP_OPT_NOP:
                    self.hdr_options.append(IpOptNop(raw_options[i : i + IP_OPT_NOP_LEN]))
                    i += IP_OPT_NOP_LEN

                else:
                    self.hdr_options.append(IpOptUnk(raw_options[i : i + raw_options[i + 1]]))
                    i += self.raw_options[i + 1]

        # Packet building
        else:
            self.hdr_ver = 4
            self.hdr_hlen = None
            self.hdr_dscp = hdr_dscp
            self.hdr_ecn = hdr_ecn
            self.hdr_plen = None
            self.hdr_id = hdr_id
            self.hdr_frag_df = hdr_frag_df
            self.hdr_frag_mf = hdr_frag_mf
            self.hdr_frag_offset = hdr_frag_offset
            self.hdr_ttl = hdr_ttl
            self.hdr_cksum = 0
            self.hdr_src = hdr_src
            self.hdr_dst = hdr_dst

            self.hdr_options = hdr_options

            self.hdr_hlen = IP_HEADER_LEN + len(self.raw_options)

            assert self.hdr_hlen % 4 == 0, "IP header len is not multiplcation of 4 bytes, check options"

            assert child_packet.protocol in {"ICMP", "UDP", "TCP"}, f"Not supported protocol: {child_packet.protocol}"

            if child_packet.protocol == "ICMP":
                self.hdr_proto = IP_PROTO_ICMP
                self.raw_data = child_packet.get_raw_packet()
                self.hdr_plen = self.hdr_hlen + len(self.raw_data)

            if child_packet.protocol == "UDP":
                self.hdr_proto = IP_PROTO_UDP
                self.hdr_plen = self.hdr_hlen + child_packet.hdr_len
                self.raw_data = child_packet.get_raw_packet(self.ip_pseudo_header)

            if child_packet.protocol == "TCP":
                self.hdr_proto = IP_PROTO_TCP
                self.hdr_plen = self.hdr_hlen + child_packet.hdr_hlen + len(child_packet.raw_data)
                self.raw_data = child_packet.get_raw_packet(self.ip_pseudo_header)

    def __str__(self):
        """ Short packet log string """

        return f"IP {self.hdr_src} > {self.hdr_dst}, proto {self.hdr_proto} ({IP_PROTO_TABLE.get(self.hdr_proto, '???')})"

    def __compute_cksum(self):
        """ Compute checksum of IP header """

        cksum_data = self.raw_header + self.raw_options
        cksum_data = list(struct.unpack(f"! {len(cksum_data) >> 1}H", cksum_data))
        cksum_data[5] = 0
        cksum = sum(cksum_data)
        return ~((cksum & 0xFFFF) + (cksum >> 16)) & 0xFFFF

    @property
    def raw_header(self):
        """ Packet header in raw form """

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
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.hdr_options:
            raw_options += option.raw_option

        return raw_options

    @property
    def raw_packet(self):
        """ Packet in raw form """

        return self.raw_header + self.raw_options + self.raw_data

    @property
    def ip_pseudo_header(self):
        """ Returns IP pseudo header that is used by TCP to compute its checksum """

        return struct.pack("! 4s 4s BBH", socket.inet_aton(self.hdr_src), socket.inet_aton(self.hdr_dst), 0, self.hdr_proto, self.hdr_plen - self.hdr_hlen)

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.hdr_cksum = self.__compute_cksum()

        return self.raw_packet

    def get_option(self, name):
        """ Find specific option by its name """

        for option in self.hdr_options:
            if option.name == name:
                return option


"""

   IP options

"""


IP_OPT_EOL = 0
IP_OPT_EOL_LEN = 1
IP_OPT_NOP = 1
IP_OPT_NOP_LEN = 1


class IpOptEol:
    """ IP option End of Option List """

    name = "EOL"

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_kind = raw_option[0]
        else:
            self.opt_kind = IP_OPT_EOL

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "eol"


class IpOptNop:
    """ IP option No Operation """

    name = "NOP"

    def __init__(self, raw_option=None):
        if raw_option:
            self.opt_kind = raw_option[0]
        else:
            self.opt_kind = IP_OPT_NOP

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "nop"


class IpOptUnk:
    """ IP option not supported by this stack """

    name = "UNKNOWN"

    def __init__(self, raw_option=None):
        self.opt_kind = raw_option[0]
        self.opt_len = raw_option[1]
        self.raw_data = raw_option[2 : self.opt_len - 2]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_kind, self.opt_len) + self.raw_data

    def __str__(self):
        return "unk"
