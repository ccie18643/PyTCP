#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
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


#
# ip4/ps.py - protocol support for IPv4
#


# IPv4 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |   DSCP    |ECN|          Packet length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to live |    Protocol   |         Header checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


HEADER_LEN = 20

PROTO_ICMP4 = 1
PROTO_TCP = 6
PROTO_UDP = 17

PROTO_TABLE = {PROTO_ICMP4: "ICMPv4", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}


def __str__(self) -> str:
    """Packet log string"""

    return (
        f"IPv4 {self.src} > {self.dst}, proto {self.proto} ({PROTO_TABLE.get(self.proto, '???')}), id {self.id}"
        + f"{', DF' if self.flag_df else ''}{', MF' if self.flag_mf else ''}, offset {self.offset}, plen {self.plen}"
        + f", ttl {self.ttl}"
    )


#
#   IPv4 options
#


# IPv4 option - End of Option Linst

OPT_EOL = 0
OPT_EOL_LEN = 1


class OptEol:
    """IPv4 option - End of Option List"""

    def __str__(self) -> str:
        """Option log string"""

        return "eol"

    def __len__(self) -> int:
        """Option length"""

        return OPT_EOL_LEN


# IPv4 option - No Operation (1)

OPT_NOP = 1
OPT_NOP_LEN = 1


class OptNop:
    """IPv4 option - No Operation"""

    def __str__(self) -> str:
        """Option log string"""

        return "nop"

    def __len__(self) -> int:
        """Option length"""

        return OPT_NOP_LEN


# IPv4 option not supported by this stack


class OptUnk:
    """IPv4 option not supported by this stack"""

    def __init__(self) -> None:
        """Class constructor"""

        self.kind = -1
        self.len = -1

    def __str__(self) -> str:
        """Option log string"""

        return f"unk-{self.kind}-{self.len}"
