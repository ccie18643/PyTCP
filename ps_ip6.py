#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# ps_ip6.py - protocol support libary for IPv6
#


import struct

import loguru

import config
from ipv6_address import IPv6Address

# IPv6 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version| Traffic Class |           Flow Label                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Payload Length        |  Next Header  |   Hop Limit   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                         Source Address                        +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                      Destination Address                      +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP6_HEADER_LEN = 40

IP6_NEXT_HEADER_TCP = 6
IP6_NEXT_HEADER_UDP = 17
IP6_NEXT_HEADER_ICMP6 = 58

IP6_NEXT_HEADER_TABLE = {IP6_NEXT_HEADER_TCP: "TCP", IP6_NEXT_HEADER_UDP: "UDP", IP6_NEXT_HEADER_ICMP6: "ICMPv6"}

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


class Ip6Packet:
    """ IPv6 packet support class """

    protocol = "IPv6"

    def __init__(
        self,
        parent_packet=None,
        ip6_src=None,
        ip6_dst=None,
        ip6_hop=config.ip6_default_hop,
        ip6_dscp=0,
        ip6_ecn=0,
        ip6_flow=0,
        ip6_next=None,
        child_packet=None,
        raw_data=b"",
        tracker=None,
    ):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="ps_ip6.")
        self.sanity_check_failed = False

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data

            if not self.__pre_parse_sanity_check(raw_packet):
                self.sanity_check_failed = True
                return

            raw_header = raw_packet[:IP6_HEADER_LEN]

            self.raw_data = raw_packet[IP6_HEADER_LEN : IP6_HEADER_LEN + struct.unpack("!H", raw_header[4:6])[0]]

            self.ip6_ver = raw_header[0] >> 4
            self.ip6_dscp = ((raw_header[0] & 0b00001111) << 2) | ((raw_header[1] & 0b11000000) >> 6)
            self.ip6_ecn = (raw_header[1] & 0b00110000) >> 4
            self.ip6_flow = ((raw_header[1] & 0b00001111) << 16) | (raw_header[2] << 8) | raw_header[3]
            self.ip6_dlen = struct.unpack("!H", raw_header[4:6])[0]
            self.ip6_next = raw_header[6]
            self.ip6_hop = raw_header[7]
            self.ip6_src = IPv6Address(raw_header[8:24])
            self.ip6_dst = IPv6Address(raw_header[24:40])

            if not self.__post_parse_sanity_check():
                self.sanity_check_failed = True

        # Packet building
        else:
            if tracker:
                self.tracker = tracker
            else:
                self.tracker = child_packet.tracker

            self.ip6_ver = 6
            self.ip6_dscp = ip6_dscp
            self.ip6_ecn = ip6_ecn
            self.ip6_flow = ip6_flow
            self.ip6_next = ip6_next
            self.ip6_hop = ip6_hop
            self.ip6_src = IPv6Address(ip6_src)
            self.ip6_dst = IPv6Address(ip6_dst)

            if child_packet:
                assert child_packet.protocol in {"ICMPv6", "UDP", "TCP"}, f"Not supported protocol: {child_packet.protocol}"

                if child_packet.protocol == "ICMPv6":
                    self.ip6_next = IP6_NEXT_HEADER_ICMP6

                if child_packet.protocol == "UDP":
                    self.ip6_next = IP6_NEXT_HEADER_UDP

                if child_packet.protocol == "TCP":
                    self.ip6_next = IP6_NEXT_HEADER_TCP

                self.ip6_dlen = len(child_packet.raw_packet)
                self.raw_data = child_packet.get_raw_packet(self.ip_pseudo_header)

            else:
                self.ip6_next = ip6_next
                self.ip6_dlen = len(raw_data)
                self.raw_data = raw_data

    def __str__(self):
        """ Short packet log string """

        return (
            f"IPv6 {self.ip6_src} > {self.ip6_dst}, next {self.ip6_next} ({IP6_NEXT_HEADER_TABLE.get(self.ip6_next, '???')}), flow {self.ip6_flow}"
            + f", dlen {self.ip6_dlen}, hop {self.ip6_hop}"
        )

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw form """

        return struct.pack(
            "! BBBB HBB 16s 16s",
            self.ip6_ver << 4 | self.ip6_dscp >> 4,
            self.ip6_dscp << 6 | self.ip6_ecn << 4 | ((self.ip6_flow & 0b000011110000000000000000) >> 16),
            (self.ip6_flow & 0b000000001111111100000000) >> 8,
            self.ip6_flow & 0b000000000000000011111111,
            self.ip6_dlen,
            self.ip6_next,
            self.ip6_hop,
            self.ip6_src.packed,
            self.ip6_dst.packed,
        )

    @property
    def raw_packet(self):
        """ Packet in raw form """

        return self.raw_header + self.raw_data

    @property
    def ip_pseudo_header(self):
        """ Returns IPv6 pseudo header that is used by TCP to compute its checksum """

        # *** in the UDP/TCP length field need to account for IPv6 optional headers, current implementation assumes TCP/UDP is put right after IPv6 header ***
        return struct.pack("! 16s 16s L BBBB", self.ip6_src.packed, self.ip6_dst.packed, self.ip6_dlen, 0, 0, 0, self.ip6_next)

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        return self.raw_packet

    def __pre_parse_sanity_check(self, raw_packet):
        """ Preliminary sanity check to be run on raw IPv6 packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return True

        if len(raw_packet) < 40:
            self.logger.critical(f"{self.tracker} - IPv6 sanity check fail - wrong packet length (I)")
            return False

        if struct.unpack("!H", raw_packet[4:6])[0] != len(raw_packet) - 40:
            self.logger.critical(f"{self.tracker} - IPv6 sanity check fail - wrong packet length (II)")
            return False

        return True

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed IPv6 packet """

        if not config.post_parse_sanity_check:
            return True

        # ip6_ver not set to 6
        if not self.ip6_ver == 6:
            self.logger.critical(f"{self.tracker} - IP sanity check fail - value of ip6_ver is not 6")
            return False

        # ip6_hop set to 0
        if self.ip6_hop == 0:
            self.logger.critical(f"{self.tracker} - IP sanity check fail - value of ip6_hop is 0")
            return False

        # ip6_src address is multicast
        if self.ip6_src.is_multicast:
            self.logger.critical(f"{self.tracker} - IP sanity check fail - ip6_src address is multicast")
            return False

        return True
