#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_ipv4.py - protocol support libary for IPv4

"""

import socket
import struct

import inet_cksum

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

IPV4_HEADER_LEN = 20

IPV4_PROTO_ICMP = 1
IPV4_PROTO_TCP = 6
IPV4_PROTO_UDP = 17


IPV4_PROTO_TABLE = {IPV4_PROTO_ICMP: "ICMP", IPV4_PROTO_TCP: "TCP", IPV4_PROTO_UDP: "UDP"}


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
        ipv4_src=None,
        ipv4_dst=None,
        ipv4_ttl=64,
        ipv4_dscp=0,
        ipv4_ecn=0,
        ipv4_packet_id=0,
        ipv4_frag_df=False,
        ipv4_frag_mf=False,
        ipv4_frag_offset=0,
        ipv4_options=[],
        child_packet=None,
        ipv4_proto=None,
        raw_data=b"",
        tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:IPV4_HEADER_LEN]
            raw_options = raw_packet[IPV4_HEADER_LEN : (raw_packet[0] & 0b00001111) << 2]

            self.raw_data = raw_packet[(raw_packet[0] & 0b00001111) << 2 : struct.unpack("!H", raw_header[2:4])[0]]

            self.ipv4_ver = raw_header[0] >> 4
            self.ipv4_hlen = (raw_header[0] & 0b00001111) << 2
            self.ipv4_dscp = (raw_header[1] & 0b11111100) >> 2
            self.ipv4_ecn = raw_header[1] & 0b00000011
            self.ipv4_plen = struct.unpack("!H", raw_header[2:4])[0]
            self.ipv4_packet_id = struct.unpack("!H", raw_header[4:6])[0]
            self.ipv4_frag_df = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0100000000000000)
            self.ipv4_frag_mf = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0010000000000000)
            self.ipv4_frag_offset = (struct.unpack("!H", raw_header[6:8])[0] & 0b0001111111111111) << 3
            self.ipv4_ttl = raw_header[8]
            self.ipv4_proto = raw_header[9]
            self.ipv4_cksum = struct.unpack("!H", raw_header[10:12])[0]
            self.ipv4_src = socket.inet_ntoa(struct.unpack("!4s", raw_header[12:16])[0])
            self.ipv4_dst = socket.inet_ntoa(struct.unpack("!4s", raw_header[16:20])[0])

            self.ipv4_options = []

            opt_cls = {}

            i = 0

            while i < len(raw_options):

                if raw_options[i] == IPV4_OPT_EOL:
                    self.ipv4_options.append(IpOptEol())
                    break

                if raw_options[i] == IPV4_OPT_NOP:
                    self.ipv4_options.append(IpOptNop())
                    i += IPV4_OPT_NOP_LEN
                    continue

                self.ipv4_options.append(opt_cls.get(raw_options[i], IpOptUnk)(raw_options[i : i + raw_options[i + 1]]))
                i += self.raw_options[i + 1]

        # Packet building
        else:
            if tracker:
                self.tracker = tracker
            else:
                self.tracker = child_packet.tracker

            self.ipv4_ver = 4
            self.ipv4_hlen = None
            self.ipv4_dscp = ipv4_dscp
            self.ipv4_ecn = ipv4_ecn
            self.ipv4_plen = None
            self.ipv4_packet_id = ipv4_packet_id
            self.ipv4_frag_df = ipv4_frag_df
            self.ipv4_frag_mf = ipv4_frag_mf
            self.ipv4_frag_offset = ipv4_frag_offset
            self.ipv4_ttl = ipv4_ttl
            self.ipv4_cksum = 0
            self.ipv4_src = ipv4_src
            self.ipv4_dst = ipv4_dst

            self.ipv4_options = ipv4_options

            self.ipv4_hlen = IPV4_HEADER_LEN + len(self.raw_options)

            assert self.ipv4_hlen % 4 == 0, "IP header len is not multiplcation of 4 bytes, check options"

            if child_packet:
                assert child_packet.protocol in {"ICMP", "UDP", "TCP"}, f"Not supported protocol: {child_packet.protocol}"

                if child_packet.protocol == "ICMP":
                    self.ipv4_proto = IPV4_PROTO_ICMP
                    self.raw_data = child_packet.get_raw_packet()
                    self.ipv4_plen = self.ipv4_hlen + len(self.raw_data)

                if child_packet.protocol == "UDP":
                    self.ipv4_proto = IPV4_PROTO_UDP
                    self.ipv4_plen = self.ipv4_hlen + child_packet.udp_len
                    self.raw_data = child_packet.get_raw_packet(self.ipv4_pseudo_header)

                if child_packet.protocol == "TCP":
                    self.ipv4_proto = IPV4_PROTO_TCP
                    self.ipv4_plen = self.ipv4_hlen + child_packet.tcp_hlen + len(child_packet.raw_data)
                    self.raw_data = child_packet.get_raw_packet(self.ipv4_pseudo_header)

            else:
                self.ipv4_proto = ipv4_proto
                self.raw_data = raw_data
                self.ipv4_plen = self.ipv4_hlen + len(self.raw_data)

    def __str__(self):
        """ Short packet log string """

        return (
            f"IP {self.ipv4_src} > {self.ipv4_dst}, proto {self.ipv4_proto} ({IPV4_PROTO_TABLE.get(self.ipv4_proto, '???')}), id {self.ipv4_packet_id}"
            + f"{', DF' if self.ipv4_frag_df else ''}{', MF' if self.ipv4_frag_mf else ''}, offset {self.ipv4_frag_offset}, plen {self.ipv4_plen}"
        )

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw form """

        return struct.pack(
            "! BBH HH BBH 4s 4s",
            self.ipv4_ver << 4 | self.ipv4_hlen >> 2,
            self.ipv4_dscp << 2 | self.ipv4_ecn,
            self.ipv4_plen,
            self.ipv4_packet_id,
            self.ipv4_frag_df << 14 | self.ipv4_frag_mf << 13 | self.ipv4_frag_offset >> 3,
            self.ipv4_ttl,
            self.ipv4_proto,
            self.ipv4_cksum,
            socket.inet_aton(self.ipv4_src),
            socket.inet_aton(self.ipv4_dst),
        )

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.ipv4_options:
            raw_options += option.raw_option

        return raw_options

    @property
    def raw_packet(self):
        """ Packet in raw form """

        return self.raw_header + self.raw_options + self.raw_data

    @property
    def ipv4_pseudo_header(self):
        """ Returns IP pseudo header that is used by TCP to compute its checksum """

        return struct.pack("! 4s 4s BBH", socket.inet_aton(self.ipv4_src), socket.inet_aton(self.ipv4_dst), 0, self.ipv4_proto, self.ipv4_plen - self.ipv4_hlen)

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.ipv4_cksum = inet_cksum.compute_cksum(self.raw_header + self.raw_options)

        return self.raw_packet

    def get_option(self, name):
        """ Find specific option by its name """

        for option in self.ipv4_options:
            if option.name == name:
                return option

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(self.raw_header + self.raw_options))


"""

   IP options

"""

# IP option - End of Option Linst

IPV4_OPT_EOL = 0
IPV4_OPT_EOL_LEN = 1


class IpOptEol:
    """ IP option - End of Option List """

    def __init__(self, raw_option=None):
        self.opt_kind = IPV4_OPT_EOL

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "eol"


# IP option - No Operation (1)

IPV4_OPT_NOP = 1
IPV4_OPT_NOP_LEN = 1


class IpOptNop:
    """ IP option - No Operation """

    def __init__(self, raw_option=None):
        self.opt_kind = IPV4_OPT_NOP

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "nop"


# IP option not supported by this stack


class IpOptUnk:
    """ IP option not supported by this stack """

    def __init__(self, raw_option=None):
        self.opt_kind = raw_option[0]
        self.opt_len = raw_option[1]
        self.opt_data = raw_option[2 : self.opt_len - 2]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_kind, self.opt_len) + self.opt_data

    def __str__(self):
        return "unk"
