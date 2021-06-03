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
# icmp6/ps.py - protocol support for ICMPv6
#

from lib.ip6_address import Ip6Network
from lib.mac_address import MacAddress

# Destination Unreachable message (1/[0-6])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Packet Too Big message (2/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             MTU                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Time Exceeded (3/[0-1])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Unused                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Parameter Problem message (4/[0-2])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Pointer                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Echo Request message (128/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Reply message (129/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# MLDv2 - Multicast Listener Query message (130/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Maximum Response Code      |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               *
# |                                                               |
# +                       Multicast Address                       *
# |                                                               |
# +                                                               *
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Router Solicitation message (133/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Reserved                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Router Advertisement message (134/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Hop Limit   |M|O|H|PRF|P|0|0|        Router Lifetime        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Reachable Time                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Retrans Timer                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Neighbor Solicitation message (135/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Neighbor Advertisement message (136/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |R|S|O|                     Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# MLDv2 - Multicast Listener Report message (143/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |Nr of Mcast Address Records (M)|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [1]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [2]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [M]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Each Multicast Address Record has the following internal format:

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Multicast Address                       +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                         Auxiliary Data                        ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6_HEADER_LEN = 4

ICMP6_UNREACHABLE = 1
ICMP6_UNREACHABLE_LEN = 8
ICMP6_UNREACHABLE__NO_ROUTE = 0
ICMP6_UNREACHABLE__PROHIBITED = 1
ICMP6_UNREACHABLE__SCOPE = 2
ICMP6_UNREACHABLE__ADDRESS = 3
ICMP6_UNREACHABLE__PORT = 4
ICMP6_UNREACHABLE__FAILED_POLICY = 5
ICMP6_UNREACHABLE__REJECT_ROUTE = 6
ICMP6_PACKET_TOO_BIG = 2
ICMP6_PACKET_TOO_BIG_LEN = 8
ICMP6_TIME_EXCEEDED = 3
ICMP6_TIME_EXCEEDED_LEN = 8
ICMP6_PARAMETER_PROBLEM = 4
ICMP6_PARAMETER_PROBLEM_LEN = 8
ICMP6_ECHOR_REQUEST = 128
ICMP6_ECHOR_REQUEST_LEN = 8
ICMP6_ECHOR_REPLY = 129
ICMP6_ECHOR_REPLY_LEN = 8
ICMP6_MLD2_QUERY = 130
ICMP6_MLD2_QUERY_LEN = 28
ICMP6_ROUTER_SOLICITATION = 133
ICMP6_ROUTER_SOLICITATION_LEN = 8
ICMP6_ROUTER_ADVERTISEMENT = 134
ICMP6_ROUTER_ADVERTISEMENT_LEN = 16
ICMP6_NEIGHBOR_SOLICITATION = 135
ICMP6_NEIGHBOR_SOLICITATION_LEN = 24
ICMP6_NEIGHBOR_ADVERTISEMENT = 136
ICMP6_NEIGHBOR_ADVERTISEMENT_LEN = 24
ICMP6_MLD2_REPORT = 143
ICMP6_MLD2_REPORT_LEN = 8


ICMP6_MART_MODE_IS_INCLUDE = 1
ICMP6_MART_MODE_IS_EXCLUDE = 2
ICMP6_MART_CHANGE_TO_INCLUDE = 3
ICMP6_MART_CHANGE_TO_EXCLUDE = 4
ICMP6_MART_ALLOW_NEW_SOURCES = 5
ICMP6_MART_BLOCK_OLD_SOURCES = 6


def __str__(self) -> str:
    """Packet log string"""

    log = f"ICMPv6 type {self.type}, code {self.code}"

    if self.type == ICMP6_UNREACHABLE:
        pass

    elif self.type == ICMP6_ECHOR_REQUEST:
        log += f", id {self.ec_id}, seq {self.ec_seq}"

    elif self.type == ICMP6_ECHOR_REPLY:
        log += f", id {self.ec_id}, seq {self.ec_seq}"

    elif self.type == ICMP6_ROUTER_SOLICITATION:
        assert self.nd_options is not None
        for nd_option in self.nd_options:
            log += ", " + str(nd_option)

    elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
        assert self.nd_options is not None
        log += f", hop {self.ra_hop}"
        log += f", flags {'M' if self.ra_flag_m else '-'}{'O' if self.ra_flag_o else '-'}"
        log += f", rlft {self.ra_router_lifetime}, reacht {self.ra_reachable_time}, retrt {self.ra_retrans_timer}"
        for nd_option in self.nd_options:
            log += ", " + str(nd_option)

    elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
        assert self.nd_options is not None
        log += f", target {self.ns_target_address}"
        for nd_option in self.nd_options:
            log += ", " + str(nd_option)

    elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
        assert self.nd_options is not None
        log += f", target {self.na_target_address}"
        log += f", flags {'R' if self.na_flag_r else '-'}{'S' if self.na_flag_s else '-'}{'O' if self.na_flag_o else '-'}"
        for nd_option in self.nd_options:
            log += ", " + str(nd_option)

    elif self.type == ICMP6_MLD2_REPORT:
        pass

    return log


#
#   ICMPv6 Neighbor Discovery options
#


# ICMPv6 ND option - Source Link Layer Address (1)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_SLLA = 1
ICMP6_ND_OPT_SLLA_LEN = 8


class Icmp6NdOptSLLA:
    """ICMPv6 ND option - Source Link Layer Address (1)"""

    def __init__(self) -> None:
        """Class constructor"""

        self.slla = MacAddress("00:00:00:00:00:00")

    def __str__(self) -> str:
        """Option log string"""

        return f"slla {self.slla}"

    def __len__(self) -> int:
        """Option length"""

        return ICMP6_ND_OPT_SLLA_LEN


# ICMPv6 ND option - Target Link Layer Address (2)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_TLLA = 2
ICMP6_ND_OPT_TLLA_LEN = 8


class Icmp6NdOptTLLA:
    """ICMPv6 ND option - Target Link Layer Address (2)"""

    def __init__(self) -> None:
        """Class constructor"""

        self.tlla = MacAddress("00:00:00:00:00:00")

    def __str__(self) -> str:
        """Option log string"""

        return f"tlla {self.tlla}"

    def __len__(self) -> int:
        """Option length"""

        return ICMP6_ND_OPT_TLLA_LEN


# ICMPv6 ND option - Prefix Information (3)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |    Length     | Prefix Length |L|A|R|   Res1  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Valid Lifetime                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Preferred Lifetime                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved2                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            Prefix                             +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_PI = 3
ICMP6_ND_OPT_PI_LEN = 32


class Icmp6NdOptPI:
    """ICMPv6 ND option - Prefix Information (3)"""

    def __init__(self) -> None:
        """Class constructor"""

        self.prefix = Ip6Network("::/128")

    def __str__(self) -> str:
        """Option log string"""

        return f"prefix_info {self.prefix}"

    def __len__(self) -> int:
        """Option length"""

        return ICMP6_ND_OPT_PI_LEN


# ICMPv6 ND unknown option


class Icmp6NdOptUnk:
    """ICMPv6 ND  option not supported by this stack"""

    def __init__(self) -> None:
        """Class constructor"""

        self.code = -1
        self.len = -1

    def __str__(self) -> str:
        """Option log string"""

        return f"unk-{self.code}-{self.len}"
