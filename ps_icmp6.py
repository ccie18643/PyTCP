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
# ps_icmp6.py - protocol support libary for ICMPv6
#


import struct
from ipaddress import IPv6Address, IPv6Network

import loguru

import stack
from ip_helper import inet_cksum, ip6_is_unicast, ip6_solicited_node_multicast
from tracker import Tracker

# Destination Unreachable message (1/[0,1,3,4])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
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
ICMP6_UNREACHABLE_NOROUTE = 0
ICMP6_UNREACHABLE_PROHIBITED = 1
ICMP6_UNREACHABLE_ADDRESS = 2
ICMP6_UNREACHABLE_PORT = 4
ICMP6_ECHOREQUEST = 128
ICMP6_ECHOREPLY = 129
ICMP6_MLD2_QUERY = 130
ICMP6_ROUTER_SOLICITATION = 133
ICMP6_ROUTER_ADVERTISEMENT = 134
ICMP6_NEIGHBOR_SOLICITATION = 135
ICMP6_NEIGHBOR_ADVERTISEMENT = 136
ICMP6_MLD2_REPORT = 143

ICMP6_MART_MODE_IS_INCLUDE = 1
ICMP6_MART_MODE_IS_EXCLUDE = 2
ICMP6_MART_CHANGE_TO_INCLUDE = 3
ICMP6_MART_CHANGE_TO_EXCLUDE = 4
ICMP6_MART_ALLOW_NEW_SOURCES = 5
ICMP6_MART_BLOCK_OLD_SOURCES = 6


class Icmp6Packet:
    """ ICMPv6 packet support class """

    protocol = "ICMPv6"

    def __init__(
        self,
        parent_packet=None,
        icmp6_type=None,
        icmp6_code=0,
        icmp6_un_raw_data=b"",
        icmp6_ec_id=None,
        icmp6_ec_seq=None,
        icmp6_ec_raw_data=b"",
        icmp6_ra_hop=None,
        icmp6_ra_flag_m=False,
        icmp6_ra_flag_o=False,
        icmp6_ra_router_lifetime=None,
        icmp6_ra_reachable_time=None,
        icmp6_ra_retrans_timer=None,
        icmp6_ns_target_address=None,
        icmp6_na_flag_r=False,
        icmp6_na_flag_s=False,
        icmp6_na_flag_o=False,
        icmp6_na_target_address=None,
        icmp6_nd_options=None,
        icmp6_mlr2_multicast_address_record=None,
        echo_tracker=None,
    ):
        """ Class constructor """

        self.logger = loguru.logger.bind(object_name="ps_icmpv6.")
        self.sanity_check_failed = False

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data

            if not self.__pre_parse_sanity_check(raw_packet, parent_packet.ip_pseudo_header):
                self.sanity_check_failed = True
                return

            self.icmp6_type = raw_packet[0]
            self.icmp6_code = raw_packet[1]
            self.icmp6_cksum = struct.unpack("!H", raw_packet[2:4])[0]

            self.icmp6_nd_options = []

            if self.icmp6_type == ICMP6_UNREACHABLE:
                self.icmp6_un_reserved = struct.unpack("!L", raw_packet[4:8])[0]
                self.icmp6_un_raw_data = raw_packet[8:]

            elif self.icmp6_type == ICMP6_ECHOREQUEST:
                self.icmp6_ec_id = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmp6_ec_seq = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmp6_ec_raw_data = raw_packet[8:]

            elif self.icmp6_type == ICMP6_ECHOREPLY:
                self.icmp6_ec_id = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmp6_ec_seq = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmp6_ec_raw_data = raw_packet[8:]

            elif self.icmp6_type == ICMP6_ROUTER_SOLICITATION:
                self.icmp6_rs_reserved = struct.unpack("!L", raw_packet[4:8])[0]
                self.icmp6_nd_options = self.__read_nd_options(raw_packet[12:])

            elif self.icmp6_type == ICMP6_ROUTER_ADVERTISEMENT:
                self.icmp6_ra_hop = raw_packet[4]
                self.icmp6_ra_flag_m = bool(raw_packet[5] & 0b10000000)
                self.icmp6_ra_flag_o = bool(raw_packet[5] & 0b01000000)
                self.icmp6_ra_reserved = raw_packet[5] & 0b00111111
                self.icmp6_ra_router_lifetime = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmp6_ra_reachable_time = struct.unpack("!L", raw_packet[8:12])[0]
                self.icmp6_ra_retrans_timer = struct.unpack("!L", raw_packet[12:16])[0]
                self.icmp6_nd_options = self.__read_nd_options(raw_packet[16:])

            elif self.icmp6_type == ICMP6_NEIGHBOR_SOLICITATION:
                self.icmp6_ns_reserved = struct.unpack("!L", raw_packet[4:8])[0]
                self.icmp6_ns_target_address = IPv6Address(raw_packet[8:24])
                self.icmp6_nd_options = self.__read_nd_options(raw_packet[24:])

            elif self.icmp6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
                self.icmp6_na_flag_r = bool(raw_packet[4] & 0b10000000)
                self.icmp6_na_flag_s = bool(raw_packet[4] & 0b01000000)
                self.icmp6_na_flag_o = bool(raw_packet[4] & 0b00100000)
                self.icmp6_na_reserved = struct.unpack("!L", raw_packet[4:8])[0] & 0b00011111111111111111111111111111
                self.icmp6_na_target_address = IPv6Address(raw_packet[8:24])
                self.icmp6_nd_options = self.__read_nd_options(raw_packet[24:])

            elif self.icmp6_type == ICMP6_MLD2_REPORT:
                self.icmp6_mlr2_reserved = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmp6_mlr2_number_of_multicast_address_records = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmp6_mlr2_multicast_address_record = []
                raw_records = raw_packet[8:]
                for _ in range(self.icmp6_mlr2_number_of_multicast_address_records):
                    record = MulticastAddressRecord(raw_records)
                    raw_records = raw_records[len(record) :]
                    self.icmp6_mlr2_multicast_address_record.append(record)

            else:
                self.unknown_message = raw_packet[4:]

            if not self.__post_parse_sanity_check(parent_packet.ip6_src, parent_packet.ip6_dst, parent_packet.ip6_hop):
                self.sanity_check_failed = True

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmp6_type = icmp6_type
            self.icmp6_code = icmp6_code
            self.icmp6_cksum = 0

            self.icmp6_nd_options = [] if icmp6_nd_options is None else icmp6_nd_options

            if self.icmp6_type == ICMP6_UNREACHABLE:
                self.icmp6_un_reserved = 0
                self.icmp6_un_raw_data = icmp6_un_raw_data[:520]

            elif self.icmp6_type == ICMP6_ECHOREQUEST and self.icmp6_code == 0:
                self.icmp6_ec_id = icmp6_ec_id
                self.icmp6_ec_seq = icmp6_ec_seq
                self.icmp6_ec_raw_data = icmp6_ec_raw_data

            elif self.icmp6_type == ICMP6_ECHOREPLY and self.icmp6_code == 0:
                self.icmp6_ec_id = icmp6_ec_id
                self.icmp6_ec_seq = icmp6_ec_seq
                self.icmp6_ec_raw_data = icmp6_ec_raw_data

            elif self.icmp6_type == ICMP6_ROUTER_SOLICITATION:
                self.icmp6_rs_reserved = 0

            elif self.icmp6_type == ICMP6_ROUTER_ADVERTISEMENT:
                self.icmp6_ra_hop = icmp6_ra_hop
                self.icmp6_ra_flag_m = icmp6_ra_flag_m
                self.icmp6_ra_flag_o = icmp6_ra_flag_o
                self.icmp6_ra_router_lifetime = icmp6_ra_router_lifetime
                self.icmp6_ra_reachable_time = icmp6_ra_reachable_time
                self.icmp6_ra_retrans_timer = icmp6_ra_retrans_timer

            elif self.icmp6_type == ICMP6_NEIGHBOR_SOLICITATION:
                self.icmp6_ns_reserved = 0
                self.icmp6_ns_target_address = icmp6_ns_target_address

            elif self.icmp6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
                self.icmp6_na_flag_r = icmp6_na_flag_r
                self.icmp6_na_flag_s = icmp6_na_flag_s
                self.icmp6_na_flag_o = icmp6_na_flag_o
                self.icmp6_na_reserved = 0
                self.icmp6_na_target_address = icmp6_na_target_address

            elif self.icmp6_type == ICMP6_MLD2_REPORT:
                self.icmp6_mlr2_reserved = 0
                self.icmp6_mlr2_multicast_address_record = [] if icmp6_mlr2_multicast_address_record is None else icmp6_mlr2_multicast_address_record
                self.icmp6_mlr2_number_of_multicast_address_records = len(self.icmp6_mlr2_multicast_address_record)
                return

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv6 type {self.icmp6_type}, code {self.icmp6_code}"

        if self.icmp6_type == ICMP6_UNREACHABLE:
            pass

        elif self.icmp6_type == ICMP6_ECHOREQUEST:
            log += f", id {self.icmp6_ec_id}, seq {self.icmp6_ec_seq}"

        elif self.icmp6_type == ICMP6_ECHOREPLY:
            log += f", id {self.icmp6_ec_id}, seq {self.icmp6_ec_seq}"

        elif self.icmp6_type == ICMP6_ROUTER_SOLICITATION:
            for nd_option in self.icmp6_nd_options:
                log += ", " + str(nd_option)

        elif self.icmp6_type == ICMP6_ROUTER_ADVERTISEMENT:
            log += f", hop {self.icmp6_ra_hop}"
            log += f"flags {'M' if self.icmp6_ra_flag_m else '-'}{'O' if self.icmp6_ra_flag_o else '-'}"
            log += f"rlft {self.icmp6_ra_router_lifetime}, reacht {self.icmp6_ra_reachable_time}, retrt {self.icmp6_ra_retrans_timer}"
            for nd_option in self.icmp6_nd_options:
                log += ", " + str(nd_option)

        elif self.icmp6_type == ICMP6_NEIGHBOR_SOLICITATION:
            log += f", target {self.icmp6_ns_target_address}"
            for nd_option in self.icmp6_nd_options:
                log += ", " + str(nd_option)

        elif self.icmp6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            log += f", target {self.icmp6_na_target_address}"
            log += f", flags {'R' if self.icmp6_na_flag_r else '-'}{'S' if self.icmp6_na_flag_s else '-'}{'O' if self.icmp6_na_flag_o else '-'}"
            for nd_option in self.icmp6_nd_options:
                log += ", " + str(nd_option)

        elif self.icmp6_type == ICMP6_MLD2_REPORT:
            pass

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        if self.icmp6_type == ICMP6_UNREACHABLE:
            raw_packet = struct.pack("! BBH L", self.icmp6_type, self.icmp6_code, self.icmp6_cksum, self.icmp6_un_reserved) + self.icmp6_un_raw_data

        elif self.icmp6_type == ICMP6_ECHOREQUEST:
            raw_packet = (
                struct.pack("! BBH HH", self.icmp6_type, self.icmp6_code, self.icmp6_cksum, self.icmp6_ec_id, self.icmp6_ec_seq) + self.icmp6_ec_raw_data
            )

        elif self.icmp6_type == ICMP6_ECHOREPLY:
            raw_packet = (
                struct.pack("! BBH HH", self.icmp6_type, self.icmp6_code, self.icmp6_cksum, self.icmp6_ec_id, self.icmp6_ec_seq) + self.icmp6_ec_raw_data
            )

        elif self.icmp6_type == ICMP6_ROUTER_SOLICITATION:
            raw_packet = struct.pack("! BBH L", self.icmp6_type, self.icmp6_code, self.icmp6_cksum, self.icmp6_rs_reserved) + self.raw_nd_options

        elif self.icmp6_type == ICMP6_ROUTER_ADVERTISEMENT:
            raw_packet = (
                struct.pack(
                    "! BBH BBH L L",
                    self.icmp6_type,
                    self.icmp6_code,
                    self.icmp6_cksum,
                    self.icmp6_ra_hop,
                    (self.icmp6_ra_flag_m << 7) | (self.icmp6_ra_flag_o << 6) | self.icmp6_ra_reserved,
                    self.icmp6_ra_router_lifetime,
                    self.icmp6_ra_reachable_time,
                    self.icmp6_ra_retrans_timer,
                )
                + self.raw_nd_options
            )

        elif self.icmp6_type == ICMP6_NEIGHBOR_SOLICITATION:
            raw_packet = (
                struct.pack(
                    "! BBH L 16s",
                    self.icmp6_type,
                    self.icmp6_code,
                    self.icmp6_cksum,
                    self.icmp6_ns_reserved,
                    self.icmp6_ns_target_address.packed,
                )
                + self.raw_nd_options
            )

        elif self.icmp6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            raw_packet = (
                struct.pack(
                    "! BBH L 16s",
                    self.icmp6_type,
                    self.icmp6_code,
                    self.icmp6_cksum,
                    (self.icmp6_na_flag_r << 31) | (self.icmp6_na_flag_s << 30) | (self.icmp6_na_flag_o << 29) | self.icmp6_na_reserved,
                    self.icmp6_na_target_address.packed,
                )
                + self.raw_nd_options
            )

        elif self.icmp6_type == ICMP6_MLD2_REPORT:
            raw_packet = (
                struct.pack(
                    "! BBH HH",
                    self.icmp6_type,
                    self.icmp6_code,
                    self.icmp6_cksum,
                    self.icmp6_mlr2_reserved,
                    self.icmp6_mlr2_number_of_multicast_address_records,
                )
                + b"".join([_.raw_record for _ in self.icmp6_mlr2_multicast_address_record])
            )

        else:
            raw_packet = struct.pack("! BBH", self.icmp6_type, self.icmp6_code, self.icmp6_cksum) + self.unknown_message

        return raw_packet

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmp6_cksum = inet_cksum(ip_pseudo_header + self.raw_packet)

        return self.raw_packet

    @property
    def raw_nd_options(self):
        """ ICMPv6 ND packet options in raw format """

        raw_nd_options = b""

        for option in self.icmp6_nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options

    def validate_cksum(self, ip_pseudo_header):
        """ Validate packet checksum """

        return not bool(inet_cksum(ip_pseudo_header + self.raw_packet))

    @staticmethod
    def __read_nd_options(raw_nd_options):
        """ Read options for Neighbor Discovery """

        opt_cls = {
            ICMP6_ND_OPT_SLLA: Icmp6NdOptSLLA,
            ICMP6_ND_OPT_TLLA: Icmp6NdOptTLLA,
            ICMP6_ND_OPT_PI: Icmp6NdOptPI,
        }

        i = 0
        nd_options = []

        while i < len(raw_nd_options):
            nd_options.append(opt_cls.get(raw_nd_options[i], Icmp6NdOptUnk)(raw_nd_options[i : i + (raw_nd_options[i + 1] << 3)]))
            i += raw_nd_options[i + 1] << 3

        return nd_options

    @property
    def icmp6_nd_opt_slla(self):
        """ ICMPv6 ND option - Source Link Layer Address (1) """

        for option in self.icmp6_nd_options:
            if option.opt_code == ICMP6_ND_OPT_SLLA:
                return option.opt_slla
        return None

    @property
    def icmp6_nd_opt_tlla(self):
        """ ICMPv6 ND option - Target Link Layer Address (2) """

        for option in self.icmp6_nd_options:
            if option.opt_code == ICMP6_ND_OPT_TLLA:
                return option.opt_tlla
        return None

    @property
    def icmp6_nd_opt_pi(self):
        """ ICMPv6 ND option - Prefix Info (3) - Returns list of prefixes that can be used for address autoconfiguration"""

        return [_.opt_prefix for _ in self.icmp6_nd_options if _.opt_code == ICMP6_ND_OPT_PI and _.opt_flag_a and _.opt_prefix.prefixlen == 64]

    def __nd_option_pre_parse_sanity_check(self, raw_packet, index):
        """ Check integrity of ICMPv6 ND options """

        while index < len(raw_packet):
            if index + 1 > len(raw_packet):
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong option length (I)")
                return False
            if raw_packet[index + 1] == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong option length (II)")
                return False
            index += raw_packet[index + 1] << 3
            if index > len(raw_packet):
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong option length (III)")
                return False

        return True

    def __pre_parse_sanity_check(self, raw_packet, pseudo_header):
        """ Preliminary sanity check to be run on raw ICMPv6 packet prior to packet parsing """

        if not stack.pre_parse_sanity_check:
            return True

        if inet_cksum(pseudo_header + raw_packet):
            self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet checksum")
            return False

        if len(raw_packet) < 4:
            self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (I)")
            return False

        if raw_packet[0] == ICMP6_UNREACHABLE:
            if len(raw_packet) < 12:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False

        elif raw_packet[0] == ICMP6_ECHOREQUEST:
            if len(raw_packet) < 8:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False

        elif raw_packet[0] == ICMP6_ECHOREPLY:
            if len(raw_packet) < 8:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False

        elif raw_packet[0] == ICMP6_MLD2_QUERY:
            if len(raw_packet) < 28:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False
            if len(raw_packet) != 28 + struct.unpack("! H", raw_packet[26:28])[0] * 16:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (III)")
                return False

        elif raw_packet[0] == ICMP6_ROUTER_SOLICITATION:
            if len(raw_packet) < 8:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False
            if self.__nd_option_pre_parse_sanity_check(raw_packet, 8) is False:
                return False

        elif raw_packet[0] == ICMP6_ROUTER_ADVERTISEMENT:
            if len(raw_packet) < 16:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False
            if self.__nd_option_pre_parse_sanity_check(raw_packet, 16) is False:
                return False

        elif raw_packet[0] == ICMP6_NEIGHBOR_SOLICITATION:
            if len(raw_packet) < 24:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False
            if self.__nd_option_pre_parse_sanity_check(raw_packet, 24) is False:
                return False

        elif raw_packet[0] == ICMP6_NEIGHBOR_ADVERTISEMENT:
            if len(raw_packet) < 24:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False
            if self.__nd_option_pre_parse_sanity_check(raw_packet, 24) is False:
                return False

        elif raw_packet[0] == ICMP6_MLD2_REPORT:
            if len(raw_packet) < 8:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (II)")
                return False
            index = 8
            for _ in range(struct.unpack("! H", raw_packet[6:8])[0]):
                if index + 20 > len(raw_packet):
                    self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet length (III)")
                    return False
                index += 20 + raw_packet[index + 1] + struct.unpack("! H", raw_packet[index + 2 : index + 4])[0] * 16
            if index != len(raw_packet):
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - wrong packet lenght (IV)")
                return False

        return True

    def __post_parse_sanity_check(self, ip6_src, ip6_dst, ip6_hop):
        """ Sanity check to be run on parsed ICMPv6 packet """

        if not stack.post_parse_sanity_check:
            return True

        if self.icmp6_type == ICMP6_UNREACHABLE:
            # imcp6_code must be set to [0-6] (RFC 4861)
            if not self.icmp6_code in {0, 1, 2, 3, 4, 5, 6}:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not [0-6]")
                return False

        elif self.icmp6_type == ICMP6_ECHOREQUEST:
            # imcp6_code must be set to 0 (RFC 4861)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False

        elif self.icmp6_type == ICMP6_ECHOREPLY:
            # imcp6_code must be set to 0 (RFC 4861)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False

        elif self.icmp6_type == ICMP6_MLD2_QUERY:
            # imcp6_code must be set to 0 (RFC 3810)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False
            # ip6_hop must be set to 255 (RFC 3810)
            if not ip6_hop == 1:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - value of ip6_hop is not 1")
                return False

        elif self.icmp6_type == ICMP6_ROUTER_SOLICITATION:
            # imcp6_code must be set to 0 (RFC 4861)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False
            # ip6_hop must be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - value of ip6_hop is not 255")
                return False
            # ip6_src must be unicast o unspecified address (RFC 4861)
            if not (ip6_is_unicast(ip6_src) or ip6_src.is_unspecified):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_src address is not unicast and not unspecified")
                return False
            # ip6_dst must be all-routers multicast
            if not ip6_dst == IPv6Address("ff02::2"):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_dst address is not all-routers multicast")
                return False
            # icmp6_rs_opt_slla must not be included if ip6_src is unspecified address
            if ip6_src.is_unspecified and self.icmp6_nd_opt_slla:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - p6_src address is unspecified but slla option present")
                return False

        elif self.icmp6_type == ICMP6_ROUTER_ADVERTISEMENT:
            # imcp6_code must be set to 0 (RFC 4861)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False
            # ip6_hop must be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - value of ip6_hop is not 255")
                return False
            # ip6_src must be link local address (RFC 4861)
            if not ip6_src.is_link_local:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_src address is not link local")
                return False
            # ip6_dst must be unicast or all nodes multicast (RFC 4861)
            if not (ip6_is_unicast(ip6_dst) or ip6_dst == IPv6Address("ff02::1")):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_dst address is not unicast or all nodes multicast")
                return False

        elif self.icmp6_type == ICMP6_NEIGHBOR_SOLICITATION:
            # imcp6_code must be set to 0 (RFC 4861)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False
            # ip6_hop must be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - value of ip6_hop is not 255")
                return False
            # ip6_src must be unicast o unspecified address (RFC 4861)
            if not (ip6_is_unicast(ip6_src) or ip6_src.is_unspecified):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_src address is not unicast and not unspecified")
                return False
            # ip6_dst must be must be solicited-node multicast associated with target address or the target address (RFC 4861)
            if not (ip6_dst == ip6_solicited_node_multicast(self.icmp6_ns_target_address) or ip6_dst == self.icmp6_ns_target_address):
                self.logger.debug(
                    f"{self.tracker} - ICMPv6 sanity check fail - ip6_dst address is not solicited-node multicast for target_address and not target_address"
                )
                return False
            # icmp6_ns_target_address must be unicast address (RFC 4861)
            if not ip6_is_unicast(self.icmp6_ns_target_address):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - icmp6_ns_target_address is not unicast")
                return False
            # icmp6_rs_opt_slla must not be included if ip6_src is unspecified address
            if ip6_src.is_unspecified and not self.icmp6_nd_opt_slla is None:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_src address is unspecified but slla option present")
                return False

        elif self.icmp6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            # imcp6_code must be set to 0 (RFC 4861)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False
            # ip6_hop must be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - value of ip6_hop is not 255")
                return False
            # ip6_src must be unicast address (RFC 4861)
            if not ip6_is_unicast(ip6_src):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - ip6_src address is not unicast")
                return False
            # if icmp6_na_flag_s is set then ip6_dst must be unicast or all-nodes (RFC 4861)
            if self.icmp6_na_flag_s is True and not (ip6_is_unicast(ip6_dst) or ip6_dst == IPv6Address("ff02::1")):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - icmp6_na_flag_s set but ip6_dst address is not unicast and not all-nodes")
                return False
            # if icmp6_na_flag_s is not set then ip6_dst must be all-nodes (RFC 4861)
            if self.icmp6_na_flag_s is False and not ip6_dst == IPv6Address("ff02::1"):
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - icmp6_na_flag_s set but ip6_dst address is not all-nodes")
                return False

        elif self.icmp6_type == ICMP6_MLD2_REPORT:
            # imcp6_code must be set to 0 (RFC 3810)
            if not self.icmp6_code == 0:
                self.logger.critical(f"{self.tracker} - ICMPv6 sanity check fail - value of icmp6_code is not 0")
                return False
            # ip6_hop must be set to 255 (RFC 3810)
            if not ip6_hop == 1:
                self.logger.debug(f"{self.tracker} - ICMPv6 sanity check fail - value of ip6_hop is not 1")
                return False

        return True


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
    """ ICMPv6 ND option - Source Link Layer Address (1) """

    def __init__(self, raw_option=None, opt_slla=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1] << 3
            self.opt_slla = ":".join([f"{_:0>2x}" for _ in raw_option[2:8]])
        else:
            self.opt_code = ICMP6_ND_OPT_SLLA
            self.opt_len = ICMP6_ND_OPT_SLLA_LEN
            self.opt_slla = opt_slla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", self.opt_code, self.opt_len >> 3, bytes.fromhex(self.opt_slla.replace(":", "")))

    def __str__(self):
        return f"slla {self.opt_slla}"


# ICMPv6 ND option - Target Link Layer Address (2)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_TLLA = 2
ICMP6_ND_OPT_TLLA_LEN = 8


class Icmp6NdOptTLLA:
    """ ICMPv6 ND option - Target Link Layer Address (2) """

    def __init__(self, raw_option=None, opt_tlla=None):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1] << 3
            self.opt_tlla = ":".join([f"{_:0>2x}" for _ in raw_option[2:8]])
        else:
            self.opt_code = ICMP6_ND_OPT_TLLA
            self.opt_len = ICMP6_ND_OPT_TLLA_LEN
            self.opt_tlla = opt_tlla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", self.opt_code, self.opt_len >> 3, bytes.fromhex(self.opt_tlla.replace(":", "")))

    def __str__(self):
        return f"tlla {self.opt_tlla}"


# ICMPv6 ND option - Prefix Information (3)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |    Length     | Prefix Length |L|A|R|  Res1  |
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
    """ ICMPv6 ND option - Prefix Information (3) """

    def __init__(
        self,
        raw_option=None,
        opt_flag_l=False,
        opt_flag_a=False,
        opt_flag_r=False,
        opt_valid_lifetime=None,
        opt_preferred_lifetime=None,
        opt_prefix=None,
    ):
        if raw_option:
            self.opt_code = raw_option[0]
            self.opt_len = raw_option[1] << 3
            self.opt_flag_l = bool(raw_option[3] & 0b10000000)
            self.opt_flag_a = bool(raw_option[3] & 0b01000000)
            self.opt_flag_r = bool(raw_option[3] & 0b00100000)
            self.opt_reserved_1 = raw_option[3] & 0b00011111
            self.opt_valid_lifetime = struct.unpack("!L", raw_option[4:8])[0]
            self.opt_preferred_lifetime = struct.unpack("!L", raw_option[8:12])[0]
            self.opt_reserved_2 = struct.unpack("!L", raw_option[12:16])[0]
            self.opt_prefix = IPv6Network((raw_option[16:32], raw_option[2]))
        else:
            self.opt_code = ICMP6_ND_OPT_PI
            self.opt_len = ICMP6_ND_OPT_PI_LEN
            self.opt_flag_l = opt_flag_l
            self.opt_flag_a = opt_flag_a
            self.opt_flag_r = opt_flag_r
            self.opt_reserved_1 = 0
            self.opt_valid_lifetime = opt_valid_lifetime
            self.opt_valid_preferred = opt_preferred_lifetime
            self.opt_reserved_2 = 0
            self.opt_prefix = IPv6Network(opt_prefix)

    @property
    def raw_option(self):
        return struct.pack(
            "! BB BB L L L 16s",
            self.opt_code,
            self.opt_len >> 3,
            self.opt_prefix.prefixlen,
            (self.opt_flag_l << 7) | (self.opt_flag_a << 6) | (self.opt_flag_r << 6) | self.opt_reserved_1,
            self.opt_valid_lifetime,
            self.opt_preferred_lifetime,
            self.opt_reserved_2,
            self.opt_prefix.network_address.packed,
        )

    def __str__(self):
        return f"prefix_info {self.opt_prefix}"


# ICMPv6 ND option not supported by this stack


class Icmp6NdOptUnk:
    """ ICMPv6 ND  option not supported by this stack """

    def __init__(self, raw_option):
        self.opt_code = raw_option[0]
        self.opt_len = raw_option[1] << 3
        self.opt_data = raw_option[2 : self.opt_len]

    @property
    def raw_option(self):
        return struct.pack("! BB", self.opt_code, self.opt_len >> 3) + self.opt_data

    def __str__(self):
        return f"unk-{self.opt_code}-{self.opt_len}"


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """ Multicast Address Record used by MLDv2 Report message """

    def __init__(self, raw_record=None, record_type=None, multicast_address=None, source_address=None, aux_data=b""):
        """ Class constuctor """

        # Record parsing
        if raw_record:
            self.record_type = raw_record[0]
            self.aux_data_len = raw_record[1]
            self.number_of_sources = struct.unpack("!H", raw_record[2:4])[0]
            self.multicast_address = IPv6Address(raw_record[4:20])
            self.source_address = [IPv6Address(raw_record[20 + 16 * _ : 20 + 16 * (_ + 1)]) for _ in range(self.number_of_sources)]
            self.aux_data = raw_record[20 + 16 * self.number_of_sources :]

        # Record building
        else:
            self.record_type = record_type
            self.aux_data_len = len(aux_data)
            self.multicast_address = IPv6Address(multicast_address)
            self.source_address = [] if source_address is None else source_address
            self.number_of_sources = len(self.source_address)
            self.aux_data = aux_data

    def __len__(self):
        """ Length of raw record """

        return len(self.raw_record)

    def __hash__(self):
        """ Hash of raw record """

        return hash(self.raw_record)

    def __eq__(self, other):
        """ Compare two records """

        return self.raw_record == other.raw_record

    @property
    def raw_record(self):
        """ Get record in raw format """

        return (
            struct.pack("! BBH 16s", self.record_type, self.aux_data_len, self.number_of_sources, self.multicast_address.packed)
            + b"".join([_.packed for _ in self.source_address])
            + self.aux_data
        )
