#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
ps_ipv6.py - protocol support libary for IPv6

"""

import struct

from ipaddress import IPv6Address


"""

   IPv6 protocol header

   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +                                                               +
   >                                                               >
   +                         Source Address                        +
   >                                                               >
   +                                                               +
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               >
   +                                                               +
   >                                                               >
   +                      Destination Address                      +
   >                                                               >
   +                                                               +
   >                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""

IPV6_HEADER_LEN = 40

IPV6_NEXT_HEADER_TCP = 6
IPV6_NEXT_HEADER_UDP = 17
IPV6_NEXT_HEADER_ICMPV6 = 58

IPV6_NEXT_HEADER_TABLE = {IPV6_NEXT_HEADER_TCP: "TCP", IPV6_NEXT_HEADER_UDP: "UDP", IPV6_NEXT_HEADER_ICMPV6: "ICMPv6"}

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


class IPv6Packet:
    """ IPv6 packet support class """

    protocol = "IPv6"

    def __init__(
        self,
        parent_packet=None,
        ipv6_src=None,
        ipv6_dst=None,
        ipv6_hop=64,
        ipv6_dscp=0,
        ipv6_ecn=0,
        ipv6_flow=0,
        ipv6_next=None,
        child_packet=None,
        raw_data=b"",
        tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:IPV6_HEADER_LEN]

            self.raw_data = raw_packet[IPV6_HEADER_LEN : struct.unpack("!H", raw_header[4:6])[0]]

            self.ipv6_ver = raw_header[0] >> 4
            self.ipv6_dscp = ((raw_header[0] & 0b00001111) << 2) | ((raw_header[1] & 0b11000000) >> 6)
            self.ipv6_ecn = (raw_header[1] & 0b00110000) >> 4
            self.ipv6_flow = ((raw_header[1] & 0b00001111) << 16) | (raw_header[2] << 8) | raw_header[3]
            self.ipv6_dlen = struct.unpack("!H", raw_header[4:6])[0]
            self.ipv6_next = raw_header[6]
            self.ipv6_hop = raw_header[7]
            self.ipv6_src = IPv6Address(raw_header[8:24])
            self.ipv6_dst = IPv6Address(raw_header[24:40])

        # Packet building
        else:
            if tracker:
                self.tracker = tracker
            else:
                self.tracker = child_packet.tracker

            self.ipv6_ver = 6
            self.ipv6_dscp = ipv6_dscp
            self.ipv6_ecn = ipv6_ecn
            self.ipv6_flow = ipv6_flow
            self.ipv6_next = ipv6_next
            self.ipv6_hop = ipv6_hop
            self.ipv6_src = IPv6Address(ipv6_src)
            self.ipv6_dst = IPv6Address(ipv6_dst)

            if child_packet:
                assert child_packet.protocol in {"ICMPv6", "UDP", "TCP"}, f"Not supported protocol: {child_packet.protocol}"

                if child_packet.protocol == "ICMPv6":
                    self.ipv6_next = IPV6_NEXT_HEADER_ICMPV6
                    self.raw_data = child_packet.get_raw_packet()
                    self.ipv6_dlen = len(self.raw_data)

                if child_packet.protocol == "UDP":
                    self.ipv6_proto = IPV6_NEXT_HEADER_UDP
                    self.ipv6_dlen = child_packet.udp_plen
                    self.raw_data = child_packet.get_raw_packet(self.ipv6_pseudo_header)

                if child_packet.protocol == "TCP":
                    self.ipv6_proto = IPV6_NEXT_HEADER_TCP
                    self.ipv6_dlen = child_packet.tcp_hlen + len(child_packet.raw_data)
                    self.raw_data = child_packet.get_raw_packet(self.ipv6_pseudo_header)

            else:
                self.ipv6_next = ipv6_next
                self.raw_data = raw_data
                self.ipv6_dlen = len(self.raw_data)

    def __str__(self):
        """ Short packet log string """

        return (
            f"IP {self.ipv6_src} > {self.ipv6_dst}, next {self.ipv6_next} ({IPV6_NEXT_HEADER_TABLE.get(self.ipv6_proto, '???')}), flow {self.ipv6_flow}"
            + f"dlen {self.ipv6_dlen}, hop {self.ipv6_hop}"
        )

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw form """

        return struct.pack(
            "! BBBB HBB 16s 16s",
            self.ipv6_ver << 4 | self.ipv6_dscp >> 4,
            self.ipv6_dscp << 6 | self.ipv4_ecn << 4 | ((self.ipv6_flow & 0b000011110000000000000000) >> 16),
            (self.ipv6_flow & 0b000000001111111100000000) >> 8,
            self.ipv6_flow & 0b000000000000000011111111,
            struct.pack("!H", self.ipv6_dlen),
            self.ipv6_next,
            self.ipv6_hop,
            self.ipv6_src.packed,
            self.ipv6_dst.packed,
        )

    @property
    def raw_packet(self):
        """ Packet in raw form """

        return self.raw_header + self.raw_data

    @property
    def ipv6_pseudo_header(self):
        """ Returns IPv6 pseudo header that is used by TCP to compute its checksum """

        # *** in the UDP/TCP length field need to account for IPv6 optional headers, current implementation assumes TCP/UDP is put right after IPv6 header ***
        return struct.pack("! 16s 16s L BBBB", self.ipv6_src.packed, self.ipv6_dst.packed, self.ipv6_dlen, 0, 0, 0, self.ipv6_next)

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet
