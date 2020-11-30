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
# ps_ip4.py - protocol support libary for IPv4
#


import struct
from ipaddress import IPv4Address

import inet_cksum
import stack

# IPv4 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |   DSCP    |ECN|          Total Length         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment Offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to Live |    Protocol   |         Header Checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP4_HEADER_LEN = 20

IP4_PROTO_ICMP4 = 1
IP4_PROTO_TCP = 6
IP4_PROTO_UDP = 17


IP4_PROTO_TABLE = {IP4_PROTO_ICMP4: "ICMPv4", IP4_PROTO_TCP: "TCP", IP4_PROTO_UDP: "UDP"}


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


class Ip4Packet:
    """ IPv4 packet support class """

    protocol = "IPv4"

    def __init__(
        self,
        parent_packet=None,
        ip4_src=None,
        ip4_dst=None,
        ip4_ttl=64,
        ip4_dscp=0,
        ip4_ecn=0,
        ip4_packet_id=0,
        ip4_frag_df=False,
        ip4_frag_mf=False,
        ip4_frag_offset=0,
        ip4_options=None,
        child_packet=None,
        ip4_proto=None,
        raw_data=b"",
        tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data
            raw_header = raw_packet[:IP4_HEADER_LEN]
            raw_options = raw_packet[IP4_HEADER_LEN : (raw_packet[0] & 0b00001111) << 2]

            self.raw_data = raw_packet[(raw_packet[0] & 0b00001111) << 2 : struct.unpack("!H", raw_header[2:4])[0]]

            self.ip4_ver = raw_header[0] >> 4
            self.ip4_hlen = (raw_header[0] & 0b00001111) << 2
            self.ip4_dscp = (raw_header[1] & 0b11111100) >> 2
            self.ip4_ecn = raw_header[1] & 0b00000011
            self.ip4_plen = struct.unpack("!H", raw_header[2:4])[0]
            self.ip4_packet_id = struct.unpack("!H", raw_header[4:6])[0]
            self.ip4_frag_df = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0100000000000000)
            self.ip4_frag_mf = bool(struct.unpack("!H", raw_header[6:8])[0] & 0b0010000000000000)
            self.ip4_frag_offset = (struct.unpack("!H", raw_header[6:8])[0] & 0b0001111111111111) << 3
            self.ip4_ttl = raw_header[8]
            self.ip4_proto = raw_header[9]
            self.ip4_cksum = struct.unpack("!H", raw_header[10:12])[0]
            self.ip4_src = IPv4Address(raw_header[12:16])
            self.ip4_dst = IPv4Address(raw_header[16:20])

            self.ip4_options = []

            opt_cls = {}

            i = 0

            while i < len(raw_options):

                if raw_options[i] == IP4_OPT_EOL:
                    self.ip4_options.append(IpOptEol())
                    break

                if raw_options[i] == IP4_OPT_NOP:
                    self.ip4_options.append(IpOptNop())
                    i += IP4_OPT_NOP_LEN
                    continue

                self.ip4_options.append(opt_cls.get(raw_options[i], IpOptUnk)(raw_options[i : i + raw_options[i + 1]]))
                i += self.raw_options[i + 1]

        # Packet building
        else:
            if tracker:
                self.tracker = tracker
            else:
                self.tracker = child_packet.tracker

            self.ip4_ver = 4
            self.ip4_hlen = None
            self.ip4_dscp = ip4_dscp
            self.ip4_ecn = ip4_ecn
            self.ip4_plen = None
            self.ip4_packet_id = ip4_packet_id
            self.ip4_frag_df = ip4_frag_df
            self.ip4_frag_mf = ip4_frag_mf
            self.ip4_frag_offset = ip4_frag_offset
            self.ip4_ttl = ip4_ttl
            self.ip4_cksum = 0
            self.ip4_src = IPv4Address(ip4_src)
            self.ip4_dst = IPv4Address(ip4_dst)

            self.ip4_options = [] if ip4_options is None else ip4_options

            self.ip4_hlen = IP4_HEADER_LEN + len(self.raw_options)

            assert self.ip4_hlen % 4 == 0, "IP header len is not multiplcation of 4 bytes, check options"

            if child_packet:
                assert child_packet.protocol in {"ICMPv4", "UDP", "TCP"}, f"Not supported protocol: {child_packet.protocol}"

                if child_packet.protocol == "ICMPv4":
                    self.ip4_proto = IP4_PROTO_ICMP4
                    self.raw_data = child_packet.get_raw_packet()
                    self.ip4_plen = self.ip4_hlen + len(self.raw_data)

                if child_packet.protocol == "UDP":
                    self.ip4_proto = IP4_PROTO_UDP
                    self.ip4_plen = self.ip4_hlen + child_packet.udp_plen
                    self.raw_data = child_packet.get_raw_packet(self.ip_pseudo_header)

                if child_packet.protocol == "TCP":
                    self.ip4_proto = IP4_PROTO_TCP
                    self.ip4_plen = self.ip4_hlen + child_packet.tcp_hlen + len(child_packet.raw_data)
                    self.raw_data = child_packet.get_raw_packet(self.ip_pseudo_header)

            else:
                self.ip4_proto = ip4_proto
                self.raw_data = raw_data
                self.ip4_plen = self.ip4_hlen + len(self.raw_data)

    def __str__(self):
        """ Short packet log string """

        return (
            f"IPv4 {self.ip4_src} > {self.ip4_dst}, proto {self.ip4_proto} ({IP4_PROTO_TABLE.get(self.ip4_proto, '???')}), id {self.ip4_packet_id}"
            + f"{', DF' if self.ip4_frag_df else ''}{', MF' if self.ip4_frag_mf else ''}, offset {self.ip4_frag_offset}, plen {self.ip4_plen}"
            + f", ttl {self.ip4_ttl}"
        )

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_header(self):
        """ Packet header in raw form """

        return struct.pack(
            "! BBH HH BBH 4s 4s",
            self.ip4_ver << 4 | self.ip4_hlen >> 2,
            self.ip4_dscp << 2 | self.ip4_ecn,
            self.ip4_plen,
            self.ip4_packet_id,
            self.ip4_frag_df << 14 | self.ip4_frag_mf << 13 | self.ip4_frag_offset >> 3,
            self.ip4_ttl,
            self.ip4_proto,
            self.ip4_cksum,
            self.ip4_src.packed,
            self.ip4_dst.packed,
        )

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.ip4_options:
            raw_options += option.raw_option

        return raw_options

    @property
    def raw_packet(self):
        """ Packet in raw form """

        return self.raw_header + self.raw_options + self.raw_data

    @property
    def ip_pseudo_header(self):
        """ Returns IPv4 pseudo header that is used by TCP and UDP to compute their checksums """

        return struct.pack("! 4s 4s BBH", self.ip4_src.packed, self.ip4_dst.packed, 0, self.ip4_proto, self.ip4_plen - self.ip4_hlen)

    def get_raw_packet(self):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.ip4_cksum = inet_cksum.compute_cksum(self.raw_header + self.raw_options)

        return self.raw_packet

    def get_option(self, name):
        """ Find specific option by its name """

        for option in self.ip4_options:
            if option.name == name:
                return option
        return None

    def validate_cksum(self):
        """ Validate packet checksum """

        return not bool(inet_cksum.compute_cksum(self.raw_header + self.raw_options))


#
#   IPv4 options
#


# IPv4 option - End of Option Linst

IP4_OPT_EOL = 0
IP4_OPT_EOL_LEN = 1


class IpOptEol:
    """ IP option - End of Option List """

    def __init__(self):
        self.opt_kind = IP4_OPT_EOL

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "eol"


# IPv4 option - No Operation (1)

IP4_OPT_NOP = 1
IP4_OPT_NOP_LEN = 1


class IpOptNop:
    """ IP option - No Operation """

    def __init__(self):
        self.opt_kind = IP4_OPT_NOP

    @property
    def raw_option(self):
        return struct.pack("!B", self.opt_kind)

    def __str__(self):
        return "nop"


# IPv4 option not supported by this stack


class IpOptUnk:
    """ IP option not supported by this stack """

    def __init__(self, raw_option):
        self.opt_kind = raw_option[0]
        self.opt_len = raw_option[1]
        self.opt_data = raw_option[2 : self.opt_len]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_kind, self.opt_len) + self.opt_data

    def __str__(self):
        return f"unk-{self.opt_kind}-{self.opt_len}"


#
#   IPv4 sanity check functions
#


def preliminary_sanity_check(raw_packet, tracker, logger):
    """ Preliminary sanity check to be run on raw IPv4 packet prior to packet parsing """

    if not stack.preliminary_packet_sanity_check:
        return True

    if len(raw_packet) < 20:
        logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong packet length (I)")
        return False

    hlen = (raw_packet[0] & 0b00001111) << 2
    plen = struct.unpack("!H", raw_packet[2:4])[0]
    if not (20 <= hlen <= plen == len(raw_packet)):
        logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong packet length (II)")
        return False

    if inet_cksum.compute_cksum(raw_packet[0:hlen]):
        logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong checksum")
        return False

    index = 20
    while index < hlen:
        if raw_packet[index] == IP4_OPT_EOL:
            break
        if raw_packet[index] == IP4_OPT_NOP:
            index += 1
            if index > hlen:
                logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong option length (I)")
                return False
            continue
        if index + 1 > hlen:
            logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong option length (II)")
            return False
        if raw_packet[index + 1] == 0:
            logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong option length (III)")
            return False
        index += raw_packet[index + 1]
        if index > hlen:
            logger.critical(f"{tracker} - IPv4 Sanity check fail - wrong option length (IV)")
            return False

    return True
