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
# fpa/ip4.py - Fast Packet Assembler support class for IPv4 protocol
#


import struct

import config
from misc.ip_helper import inet_cksum
from misc.ipv4_address import IPv4Address
from misc.tracker import Tracker

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


HEADER_LEN = 20

PROTO_ICMP4 = 1
PROTO_TCP = 6
PROTO_UDP = 17


PROTO_TABLE = {PROTO_ICMP4: "ICMPv4", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}


class Assembler:
    """ IPv4 packet assembler support class """

    protocol = "IP4"

    def __init__(
        self,
        child_packet,
        src,
        dst,
        ttl=config.ip4_default_ttl,
        dscp=0,
        ecn=0,
        id=0,
        flag_df=False,
        options=None,
    ):
        """ Class constructor """

        assert child_packet.protocol in {"ICMP4", "UDP", "TCP"}, f"Not supported protocol: {child_packet.protocol}"
        self._child_packet = child_packet

        self.tracker = self._child_packet.tracker

        self.ver = 4
        self.dscp = dscp
        self.ecn = ecn
        self.id = id
        self.flag_df = flag_df
        self.flag_mf = False
        self.offset = 0
        self.ttl = ttl
        self.src = IPv4Address(src)
        self.dst = IPv4Address(dst)

        self.options = [] if options is None else options

        self.hlen = HEADER_LEN + len(self.raw_options)
        self.plen = len(self)

        if self._child_packet.protocol == "ICMP4":
            self.proto = PROTO_ICMP4

        if self._child_packet.protocol == "UDP":
            self.proto = PROTO_UDP

        if self._child_packet.protocol == "TCP":
            self.proto = PROTO_TCP

    def __str__(self):
        """ Packet log string """

        return (
            f"IPv4 {self.src} > {self.dst}, proto {self.proto} ({PROTO_TABLE.get(self.proto, '???')}), id {self.id}"
            + f"{', DF' if self.flag_df else ''}{', MF' if self.flag_mf else ''}, offset {self.offset}, plen {self.plen}"
            + f", ttl {self.ttl}"
        )

    def __len__(self):
        """ Length of the packet """

        return HEADER_LEN + sum([len(_) for _ in self.options]) + len(self._child_packet)

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    @property
    def dlen(self):
        """ Calculate data length """

        return self.plen - self.hlen

    @property
    def pshdr_sum(self):
        """ Create IPv4 pseudo header used by TCP and UDP to compute their checksums """

        pseudo_header = struct.pack("! 4s 4s BBH", self.src.packed, self.dst.packed, 0, self.proto, self.plen - self.hlen)
        return sum(struct.unpack("! 3L", pseudo_header))

    def assemble(self, frame, hptr):
        """ Assemble packet into the raw form """

        struct.pack_into(
            f"! BBH HH BBH 4s 4s {len(self.raw_options)}s",
            frame,
            hptr,
            self.ver << 4 | self.hlen >> 2,
            self.dscp << 2 | self.ecn,
            self.plen,
            self.id,
            self.flag_df << 14 | self.flag_mf << 13 | self.offset >> 3,
            self.ttl,
            self.proto,
            0,
            self.src.packed,
            self.dst.packed,
            self.raw_options,
        )

        struct.pack_into("! H", frame, hptr + 10, inet_cksum(frame, hptr, self.hlen))

        self._child_packet.assemble(frame, hptr + self.hlen, self.pshdr_sum)


class FragAssembler:
    """ IPv4 packet fragment assembler support class """

    protocol = "IP4"

    def __init__(
        self,
        data,
        proto,
        src,
        dst,
        ttl=config.ip4_default_ttl,
        dscp=0,
        ecn=0,
        id=0,
        flag_mf=False,
        offset=0,
        options=None,
    ):
        """ Class constructor """

        self.tracker = Tracker("TX")

        self.ver = 4
        self.dscp = dscp
        self.ecn = ecn
        self.id = id
        self.flag_df = False
        self.flag_mf = flag_mf
        self.offset = offset
        self.ttl = ttl
        self.src = IPv4Address(src)
        self.dst = IPv4Address(dst)

        self.options = [] if options is None else options
        self.data = data
        self.proto = proto

        self.hlen = HEADER_LEN + len(self.raw_options)
        self.plen = len(self)

    def __str__(self):
        """ Packet log string """

        return (
            f"IPv4 frag {self.src} > {self.dst}, proto {self.proto} ({PROTO_TABLE.get(self.proto, '???')}), id {self.id}"
            + f"{', DF' if self.flag_df else ''}{', MF' if self.flag_mf else ''}, offset {self.offset}, plen {self.plen}"
            + f", ttl {self.ttl}"
        )

    def __len__(self):
        """ Length of the packet """

        return HEADER_LEN + sum([len(_) for _ in self.options]) + len(self.data)

    @property
    def raw_options(self):
        """ Packet options in raw format """

        raw_options = b""

        for option in self.options:
            raw_options += option.raw_option

        return raw_options

    @property
    def pshdr_sum(self):
        """ Create IPv4 pseudo header used by TCP and UDP to compute their checksums """

        pseudo_header = struct.pack("! 4s 4s BBH", self.src.packed, self.dst.packed, 0, self.proto, self.plen - self.hlen)
        return sum(struct.unpack("! 3L", pseudo_header))

    def assemble(self, frame, hptr):
        """ Assemble packet into the raw form """

        struct.pack_into(
            f"! BBH HH BBH 4s 4s {len(self.raw_options)}s {len(self.data)}s",
            frame,
            hptr,
            self.ver << 4 | self.hlen >> 2,
            self.dscp << 2 | self.ecn,
            self.plen,
            self.id,
            self.flag_df << 14 | self.flag_mf << 13 | self.offset >> 3,
            self.ttl,
            self.proto,
            0,
            self.src.packed,
            self.dst.packed,
            self.raw_options,
            self.data,
        )

        struct.pack_into("! H", frame, hptr + 10, inet_cksum(frame, hptr, self.hlen))


#
#   IPv4 options
#


# IPv4 option - End of Option Linst

OPT_EOL = 0
OPT_EOL_LEN = 1


class OptEol:
    """ IP option - End of Option List """

    @property
    def raw_option(self):
        return struct.pack("!B", OPT_EOL)

    def __str__(self):
        return "eol"

    def __len__(self):
        return OPT_EOL_LEN


# IPv4 option - No Operation (1)

OPT_NOP = 1
OPT_NOP_LEN = 1


class OptNop:
    """ IP option - No Operation """

    @property
    def raw_option(self):
        return struct.pack("!B", OPT_NOP)

    def __str__(self):
        return "nop"

    def __len__(self):
        return OPT_NOP_LEN
