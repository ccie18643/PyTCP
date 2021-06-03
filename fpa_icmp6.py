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
# fpa_icmp6.py - Fast Packet Assembler support class for ICMPv6 protocol
#


import struct

from ip_helper import inet_cksum
from ipv6_address import IPv6Address, IPv6Network
from tracker import Tracker

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
ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REQUEST_LEN = 8
ICMP6_ECHO_REPLY = 129
ICMP6_ECHO_REPLY_LEN = 8
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


class Icmp6Packet:
    """ICMPv6 packet support class"""

    protocol = "ICMP6"

    def __init__(
        self,
        type,
        code=0,
        un_data=b"",
        ec_id=None,
        ec_seq=None,
        ec_data=b"",
        ra_hop=None,
        ra_flag_m=False,
        ra_flag_o=False,
        ra_router_lifetime=None,
        ra_reachable_time=None,
        ra_retrans_timer=None,
        ns_target_address=None,
        na_flag_r=False,
        na_flag_s=False,
        na_flag_o=False,
        na_target_address=None,
        nd_options=None,
        mlr2_multicast_address_record=None,
        echo_tracker=None,
    ):
        """Class constructor"""

        self.tracker = Tracker("TX", echo_tracker)

        self.type = type
        self.code = code

        self.nd_options = [] if nd_options is None else nd_options

        if self.type == ICMP6_UNREACHABLE:
            self.un_reserved = 0
            self.un_data = un_data[:520]

        elif self.type == ICMP6_ECHO_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == ICMP6_ECHO_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == ICMP6_ROUTER_SOLICITATION:
            self.rs_reserved = 0

        elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
            self.ra_hop = ra_hop
            self.ra_flag_m = ra_flag_m
            self.ra_flag_o = ra_flag_o
            self.ra_router_lifetime = ra_router_lifetime
            self.ra_reachable_time = ra_reachable_time
            self.ra_retrans_timer = ra_retrans_timer

        elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
            self.ns_reserved = 0
            self.ns_target_address = ns_target_address

        elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            self.na_flag_r = na_flag_r
            self.na_flag_s = na_flag_s
            self.na_flag_o = na_flag_o
            self.na_reserved = 0
            self.na_target_address = na_target_address

        elif self.type == ICMP6_MLD2_REPORT:
            self.mlr2_reserved = 0
            self.mlr2_multicast_address_record = [] if mlr2_multicast_address_record is None else mlr2_multicast_address_record
            self.mlr2_number_of_multicast_address_records = len(self.mlr2_multicast_address_record)

    def __str__(self):
        """Packet log string"""

        log = f"ICMPv6 type {self.type}, code {self.code}"

        if self.type == ICMP6_UNREACHABLE:
            pass

        elif self.type == ICMP6_ECHO_REQUEST:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP6_ECHO_REPLY:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP6_ROUTER_SOLICITATION:
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
            log += f", hop {self.ra_hop}"
            log += f"flags {'M' if self.ra_flag_m else '-'}{'O' if self.ra_flag_o else '-'}"
            log += f"rlft {self.ra_router_lifetime}, reacht {self.ra_reachable_time}, retrt {self.ra_retrans_timer}"
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
            log += f", target {self.ns_target_address}"
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            log += f", target {self.na_target_address}"
            log += f", flags {'R' if self.na_flag_r else '-'}{'S' if self.na_flag_s else '-'}{'O' if self.na_flag_o else '-'}"
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_MLD2_REPORT:
            pass

        return log

    def __len__(self):
        """Length of the packet"""

        if self.type == ICMP6_UNREACHABLE:
            return ICMP6_UNREACHABLE_LEN + len(self.un_data)

        if self.type == ICMP6_ECHO_REQUEST:
            return ICMP6_ECHO_REQUEST_LEN + len(self.ec_data)

        if self.type == ICMP6_ECHO_REPLY:
            return ICMP6_ECHO_REPLY_LEN + len(self.ec_data)

        if self.type == ICMP6_ROUTER_SOLICITATION:
            return ICMP6_ROUTER_SOLICITATION_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == ICMP6_ROUTER_ADVERTISEMENT:
            return ICMP6_ROUTER_ADVERTISEMENT_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == ICMP6_NEIGHBOR_SOLICITATION:
            return ICMP6_NEIGHBOR_SOLICITATION_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            return ICMP6_NEIGHBOR_ADVERTISEMENT_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == ICMP6_MLD2_REPORT:
            return ICMP6_MLD2_REPORT_LEN + sum([len(_) for _ in self.mlr2_multicast_address_record])

    def assemble_packet(self, frame, hptr, pshdr_sum):
        """Assemble packet into the raw form"""

        if self.type == ICMP6_UNREACHABLE:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, self.un_reserved, self.un_data)

        elif self.type == ICMP6_ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == ICMP6_ECHO_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == ICMP6_ROUTER_SOLICITATION:
            struct.pack_into(f"! BBH L {len(self.raw_nd_options)}s", frame, hptr, self.type, self.code, 0, self.rs_reserved, self.raw_nd_options)

        elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
            struct.pack_into(
                f"! BBH BBH L L {len(self.raw_nd_options)}s",
                frame,
                hptr,
                self.type,
                self.code,
                0,
                self.ra_hop,
                (self.ra_flag_m << 7) | (self.ra_flag_o << 6),
                self.ra_router_lifetime,
                self.ra_reachable_time,
                self.ra_retrans_timer,
                self.raw_nd_options,
            )

        elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
            struct.pack_into(
                f"! BBH L 16s {len(self.raw_nd_options)}s",
                frame,
                hptr,
                self.type,
                self.code,
                0,
                self.ns_reserved,
                self.ns_target_address.packed,
                self.raw_nd_options,
            )

        elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            struct.pack_into(
                f"! BBH L 16s {len(self.raw_nd_options)}s",
                frame,
                hptr,
                self.type,
                self.code,
                0,
                (self.na_flag_r << 31) | (self.na_flag_s << 30) | (self.na_flag_o << 29) | self.na_reserved,
                self.na_target_address.packed,
                self.raw_nd_options,
            )

        elif self.type == ICMP6_MLD2_REPORT:
            struct.pack_into(
                f"! BBH HH {sum([len(_) for _ in self.mlr2_multicast_address_record])}s",
                frame,
                hptr,
                self.type,
                self.code,
                0,
                self.mlr2_reserved,
                self.mlr2_number_of_multicast_address_records,
                b"".join([_.raw_record for _ in self.mlr2_multicast_address_record]),
            )

        struct.pack_into("! H", frame, hptr + 2, inet_cksum(frame, hptr, len(self), pshdr_sum))

    @property
    def raw_nd_options(self):
        """ICMPv6 ND packet options in raw format"""

        raw_nd_options = b""

        for option in self.nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options


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

    def __init__(self, slla):
        self.slla = slla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", ICMP6_ND_OPT_SLLA, ICMP6_ND_OPT_SLLA_LEN >> 3, bytes.fromhex(self.slla.replace(":", "")))

    def __str__(self):
        return f"slla {self.slla}"

    def __len__(self):
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

    def __init__(self, tlla):
        self.tlla = tlla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", ICMP6_ND_OPT_TLLA, ICMP6_ND_OPT_TLLA_LEN >> 3, bytes.fromhex(self.tlla.replace(":", "")))

    def __str__(self):
        return f"tlla {self.tlla}"

    def __len__(self):
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

    def __init__(
        self,
        flag_l=False,
        flag_a=False,
        flag_r=False,
        valid_lifetime=None,
        preferred_lifetime=None,
        prefix=None,
    ):
        self.code = ICMP6_ND_OPT_PI
        self.len = ICMP6_ND_OPT_PI_LEN
        self.flag_l = flag_l
        self.flag_a = flag_a
        self.flag_r = flag_r
        self.valid_lifetime = valid_lifetime
        self.preferred_lifetime = preferred_lifetime
        self.prefix = IPv6Network(prefix)

    @property
    def raw_option(self):
        return struct.pack(
            "! BB BB L L L 16s",
            self.code,
            self.len >> 3,
            self.prefix.prefixlen,
            (self.flag_l << 7) | (self.flag_a << 6) | (self.flag_r << 6),
            self.valid_lifetime,
            self.preferred_lifetime,
            self.prefix.network_address.packed,
        )

    def __str__(self):
        return f"prefix_info {self.prefix}"

    def __len__(self):
        return ICMP6_ND_OPT_PI_LEN


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """Multicast Address Record used by MLDv2 Report message"""

    def __init__(self, record_type, multicast_address, source_address=None, aux_data=b""):
        """Class constructor"""

        self.record_type = record_type
        self.aux_data_len = len(aux_data)
        self.multicast_address = IPv6Address(multicast_address)
        self.source_address = [] if source_address is None else source_address
        self.number_of_sources = len(self.source_address)
        self.aux_data = aux_data

    def __len__(self):
        """Length of raw record"""

        return len(self.raw_record)

    def __hash__(self):
        """Hash of raw record"""

        return hash(self.raw_record)

    def __eq__(self, other):
        """Compare two records"""

        return self.raw_record == other.raw_record

    @property
    def raw_record(self):
        """Get record in raw format"""

        return (
            struct.pack("! BBH 16s", self.record_type, self.aux_data_len, self.number_of_sources, self.multicast_address.packed)
            + b"".join([_.packed for _ in self.source_address])
            + self.aux_data
        )
