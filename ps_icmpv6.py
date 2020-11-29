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
# ps_icmpv6.py - protocol support libary for ICMPv6
#


import struct
from ipaddress import IPv6Address, IPv6Network

import inet_cksum
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
ICMP6_MLDV2_QUERY = 130
ICMP6_ROUTER_SOLICITATION = 133
ICMP6_ROUTER_ADVERTISEMENT = 134
ICMP6_NEIGHBOR_SOLICITATION = 135
ICMP6_NEIGHBOR_ADVERTISEMENT = 136
ICMP6_MULTICAST_LISTENER_REPORT_V2 = 143

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
        icmpv6_type=None,
        icmpv6_code=0,
        icmpv6_un_raw_data=b"",
        icmpv6_ec_id=None,
        icmpv6_ec_seq=None,
        icmpv6_ec_raw_data=b"",
        icmpv6_ra_hop=None,
        icmpv6_ra_flag_m=False,
        icmpv6_ra_flag_o=False,
        icmpv6_ra_router_lifetime=None,
        icmpv6_ra_reachable_time=None,
        icmpv6_ra_retrans_timer=None,
        icmpv6_ns_target_address=None,
        icmpv6_na_flag_r=False,
        icmpv6_na_flag_s=False,
        icmpv6_na_flag_o=False,
        icmpv6_na_target_address=None,
        icmpv6_nd_options=None,
        icmpv6_mlr2_multicast_address_record=None,
        echo_tracker=None,
    ):
        """ Class constructor """

        # Packet parsing
        if parent_packet:
            self.tracker = parent_packet.tracker

            raw_packet = parent_packet.raw_data

            # from binascii import hexlify
            # print(hexlify(raw_packet))

            self.icmpv6_type = raw_packet[0]
            self.icmpv6_code = raw_packet[1]
            self.icmpv6_cksum = struct.unpack("!H", raw_packet[2:4])[0]

            self.icmpv6_nd_options = []

            if self.icmpv6_type == ICMP6_UNREACHABLE and self.icmpv6_code in range(0, 7):
                self.icmpv6_un_reserved = struct.unpack("!L", raw_packet[4:8])[0]
                self.icmpv6_un_raw_data = raw_packet[8:]
                return

            if self.icmpv6_type == ICMP6_ECHOREQUEST and self.icmpv6_code == 0:
                self.icmpv6_ec_id = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmpv6_ec_seq = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmpv6_ec_raw_data = raw_packet[8:]
                return

            if self.icmpv6_type == ICMP6_ECHOREPLY and self.icmpv6_code == 0:
                self.icmpv6_ec_id = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmpv6_ec_seqq = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmpv6_ec_raw_data = raw_packet[8:]
                return

            if self.icmpv6_type == ICMP6_ROUTER_SOLICITATION and self.icmpv6_code == 0:
                self.icmpv6_rs_reserved = struct.unpack("!L", raw_packet[4:8])[0]
                self.icmpv6_nd_options = self.__read_nd_options(raw_packet[12:])
                return

            if self.icmpv6_type == ICMP6_ROUTER_ADVERTISEMENT and self.icmpv6_code == 0:
                self.icmpv6_ra_hop = raw_packet[4]
                self.icmpv6_ra_flag_m = bool(raw_packet[5] & 0b10000000)
                self.icmpv6_ra_flag_o = bool(raw_packet[5] & 0b01000000)
                self.icmpv6_ra_reserved = raw_packet[5] & 0b00111111
                self.icmpv6_ra_router_lifetime = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmpv6_ra_reachable_time = struct.unpack("!L", raw_packet[8:12])[0]
                self.icmpv6_ra_retrans_timer = struct.unpack("!L", raw_packet[12:16])[0]
                self.icmpv6_nd_options = self.__read_nd_options(raw_packet[16:])
                return

            if self.icmpv6_type == ICMP6_NEIGHBOR_SOLICITATION and self.icmpv6_code == 0:
                self.icmpv6_ns_reserved = struct.unpack("!L", raw_packet[4:8])[0]
                self.icmpv6_ns_target_address = IPv6Address(raw_packet[8:24])
                self.icmpv6_nd_options = self.__read_nd_options(raw_packet[24:])
                return

            if self.icmpv6_type == ICMP6_NEIGHBOR_ADVERTISEMENT and self.icmpv6_code == 0:
                self.icmpv6_na_flag_r = bool(raw_packet[4] & 0b10000000)
                self.icmpv6_na_flag_s = bool(raw_packet[4] & 0b01000000)
                self.icmpv6_na_flag_o = bool(raw_packet[4] & 0b00100000)
                self.icmpv6_na_reserved = struct.unpack("!L", raw_packet[4:8])[0] & 0b00011111111111111111111111111111
                self.icmpv6_na_target_address = IPv6Address(raw_packet[8:24])
                self.icmpv6_nd_options = self.__read_nd_options(raw_packet[24:])
                return

            if self.icmpv6_type == ICMP6_MULTICAST_LISTENER_REPORT_V2:
                self.icmpv6_mlr2_reserved = struct.unpack("!H", raw_packet[4:6])[0]
                self.icmpv6_mlr2_number_of_multicast_address_records = struct.unpack("!H", raw_packet[6:8])[0]
                self.icmpv6_mlr2_multicast_address_record = []
                raw_records = raw_packet[8:]
                for _ in range(self.icmpv6_mlr2_number_of_multicast_address_records):
                    record = MulticastAddressRecord(raw_records)
                    raw_records = raw_records[len(record) :]
                    self.icmpv6_mlr2_multicast_address_record.append(record)

        # Packet building
        else:
            self.tracker = Tracker("TX", echo_tracker)

            self.icmpv6_type = icmpv6_type
            self.icmpv6_code = icmpv6_code
            self.icmpv6_cksum = 0

            self.icmpv6_nd_options = [] if icmpv6_nd_options is None else icmpv6_nd_options

            if self.icmpv6_type == ICMP6_UNREACHABLE:
                self.icmpv6_un_reserved = 0
                self.icmpv6_un_raw_data = icmpv6_un_raw_data[:520]
                return

            if self.icmpv6_type == ICMP6_ECHOREQUEST and self.icmpv6_code == 0:
                self.icmpv6_ec_id = icmpv6_ec_id
                self.icmpv6_ec_seq = icmpv6_ec_seq
                self.icmpv6_ec_raw_data = icmpv6_ec_raw_data
                return

            if self.icmpv6_type == ICMP6_ECHOREPLY and self.icmpv6_code == 0:
                self.icmpv6_ec_id = icmpv6_ec_id
                self.icmpv6_ec_seq = icmpv6_ec_seq
                self.icmpv6_ec_raw_data = icmpv6_ec_raw_data
                return

            if self.icmpv6_type == ICMP6_ROUTER_SOLICITATION:
                self.icmpv6_rs_reserved = 0
                return

            if self.icmpv6_type == ICMP6_ROUTER_ADVERTISEMENT:
                self.icmpv6_ra_hop = icmpv6_ra_hop
                self.icmpv6_ra_flag_m = icmpv6_ra_flag_m
                self.icmpv6_ra_flag_o = icmpv6_ra_flag_o
                self.icmpv6_ra_router_lifetime = icmpv6_ra_router_lifetime
                self.icmpv6_ra_reachable_time = icmpv6_ra_reachable_time
                self.icmpv6_ra_retrans_timer = icmpv6_ra_retrans_timer
                return

            if self.icmpv6_type == ICMP6_NEIGHBOR_SOLICITATION:
                self.icmpv6_ns_reserved = 0
                self.icmpv6_ns_target_address = icmpv6_ns_target_address
                return

            if self.icmpv6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
                self.icmpv6_na_flag_r = icmpv6_na_flag_r
                self.icmpv6_na_flag_s = icmpv6_na_flag_s
                self.icmpv6_na_flag_o = icmpv6_na_flag_o
                self.icmpv6_na_reserved = 0
                self.icmpv6_na_target_address = icmpv6_na_target_address
                return

            if self.icmpv6_type == ICMP6_MULTICAST_LISTENER_REPORT_V2:
                self.icmpv6_mlr2_reserved = 0
                self.icmpv6_mlr2_multicast_address_record = [] if icmpv6_mlr2_multicast_address_record is None else icmpv6_mlr2_multicast_address_record
                self.icmpv6_mlr2_number_of_multicast_address_records = len(self.icmpv6_mlr2_multicast_address_record)

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv6 type {self.icmpv6_type}, code {self.icmpv6_code}"

        if self.icmpv6_type == ICMP6_UNREACHABLE:
            pass

        if self.icmpv6_type == ICMP6_ECHOREQUEST:
            log += f", id {self.icmpv6_ec_id}, seq {self.icmpv6_ec_seq}"

        if self.icmpv6_type == ICMP6_ECHOREPLY:
            log += f", id {self.icmpv6_ec_id}, seq {self.icmpv6_ec_seq}"

        if self.icmpv6_type == ICMP6_ROUTER_SOLICITATION:
            for nd_option in self.icmpv6_nd_options:
                log += ", " + str(nd_option)

        if self.icmpv6_type == ICMP6_ROUTER_ADVERTISEMENT:
            log += f", hop {self.icmpv6_ra_hop}"
            log += f"flags {'M' if self.icmpv6_ra_flag_m else '-'}{'O' if self.icmpv6_ra_flag_o else '-'}"
            log += f"rlft {self.icmpv6_ra_router_lifetime}, reacht {self.icmpv6_ra_reachable_time}, retrt {self.icmpv6_ra_retrans_timer}"
            for nd_option in self.icmpv6_nd_options:
                log += ", " + str(nd_option)

        if self.icmpv6_type == ICMP6_NEIGHBOR_SOLICITATION:
            log += f", target {self.icmpv6_ns_target_address}"
            for nd_option in self.icmpv6_nd_options:
                log += ", " + str(nd_option)

        if self.icmpv6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            log += f", target {self.icmpv6_na_target_address}"
            log += f", flags {'R' if self.icmpv6_na_flag_r else '-'}{'S' if self.icmpv6_na_flag_s else '-'}{'O' if self.icmpv6_na_flag_o else '-'}"
            for nd_option in self.icmpv6_nd_options:
                log += ", " + str(nd_option)

        if self.icmpv6_type == ICMP6_MULTICAST_LISTENER_REPORT_V2:
            pass

        return log

    def __len__(self):
        """ Length of the packet """

        return len(self.raw_packet)

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        if self.icmpv6_type == ICMP6_UNREACHABLE:
            return struct.pack("! BBH L", self.icmpv6_type, self.icmpv6_code, self.icmpv6_cksum, self.icmpv6_un_reserved) + self.icmpv6_un_raw_data

        if self.icmpv6_type == ICMP6_ECHOREQUEST:
            return (
                struct.pack("! BBH HH", self.icmpv6_type, self.icmpv6_code, self.icmpv6_cksum, self.icmpv6_ec_id, self.icmpv6_ec_seq) + self.icmpv6_ec_raw_data
            )

        if self.icmpv6_type == ICMP6_ECHOREPLY:
            return (
                struct.pack("! BBH HH", self.icmpv6_type, self.icmpv6_code, self.icmpv6_cksum, self.icmpv6_ec_id, self.icmpv6_ec_seq) + self.icmpv6_ec_raw_data
            )

        if self.icmpv6_type == ICMP6_ROUTER_SOLICITATION:
            return struct.pack("! BBH L", self.icmpv6_type, self.icmpv6_code, self.icmpv6_cksum, self.icmpv6_rs_reserved) + self.raw_nd_options

        if self.icmpv6_type == ICMP6_ROUTER_ADVERTISEMENT:
            return (
                struct.pack(
                    "! BBH BBH L L",
                    self.icmpv6_type,
                    self.icmpv6_code,
                    self.icmpv6_cksum,
                    self.icmpv6_ra_hop,
                    (self.icmpv6_ra_flag_m << 7) | (self.icmpv6_ra_flag_o << 6) | self.icmpv6_ra_reserved,
                    self.icmpv6_ra_router_lifetime,
                    self.icmpv6_ra_reachable_time,
                    self.icmpv6_ra_retrans_timer,
                )
                + self.raw_nd_options
            )

        if self.icmpv6_type == ICMP6_NEIGHBOR_SOLICITATION:
            return (
                struct.pack(
                    "! BBH L 16s",
                    self.icmpv6_type,
                    self.icmpv6_code,
                    self.icmpv6_cksum,
                    self.icmpv6_ns_reserved,
                    self.icmpv6_ns_target_address.packed,
                )
                + self.raw_nd_options
            )

        if self.icmpv6_type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            return (
                struct.pack(
                    "! BBH L 16s",
                    self.icmpv6_type,
                    self.icmpv6_code,
                    self.icmpv6_cksum,
                    (self.icmpv6_na_flag_r << 31) | (self.icmpv6_na_flag_s << 30) | (self.icmpv6_na_flag_o << 29) | self.icmpv6_na_reserved,
                    self.icmpv6_na_target_address.packed,
                )
                + self.raw_nd_options
            )

        if self.icmpv6_type == ICMP6_MULTICAST_LISTENER_REPORT_V2:
            return (
                struct.pack(
                    "! BBH HH",
                    self.icmpv6_type,
                    self.icmpv6_code,
                    self.icmpv6_cksum,
                    self.icmpv6_mlr2_reserved,
                    self.icmpv6_mlr2_number_of_multicast_address_records,
                )
                + b"".join([_.raw_record for _ in self.icmpv6_mlr2_multicast_address_record])
            )

        return None

    def get_raw_packet(self, ip_pseudo_header):
        """ Get packet in raw format ready to be processed by lower level protocol """

        self.icmpv6_cksum = inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet)

        return self.raw_packet

    @property
    def raw_nd_options(self):
        """ ICMPv6 ND packet options in raw format """

        raw_nd_options = b""

        for option in self.icmpv6_nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options

    def validate_cksum(self, ip_pseudo_header):
        """ Validate packet checksum """

        # from binascii import hexlify
        # print(hexlify(self.raw_packet))

        return not bool(inet_cksum.compute_cksum(ip_pseudo_header + self.raw_packet))

    @staticmethod
    def __read_nd_options(raw_nd_options):
        """ Read options for Neighbor Discovery """

        opt_cls = {
            ICMP6_ND_OPT_SLLA: ICMPv6NdOptSLLA,
            ICMP6_ND_OPT_TLLA: ICMPv6NdOptTLLA,
            ICMP6_ND_OPT_PI: ICMPv6NdOptPI,
        }

        i = 0
        nd_options = []

        while i < len(raw_nd_options):
            nd_options.append(opt_cls.get(raw_nd_options[i], ICMPv6NdOptUnk)(raw_nd_options[i : i + (raw_nd_options[i + 1] << 3)]))
            i += raw_nd_options[i + 1] << 3

        return nd_options

    @property
    def icmpv6_nd_opt_slla(self):
        """ ICMPv6 ND option - Source Link Layer Address (1) """

        for option in self.icmpv6_nd_options:
            if option.opt_code == ICMP6_ND_OPT_SLLA:
                return option.opt_slla
        return None

    @property
    def icmpv6_nd_opt_tlla(self):
        """ ICMPv6 ND option - Target Link Layer Address (2) """

        for option in self.icmpv6_nd_options:
            if option.opt_code == ICMP6_ND_OPT_TLLA:
                return option.opt_tlla
        return None

    @property
    def icmpv6_nd_opt_pi(self):
        """ ICMPv6 ND option - Prefix Info (3) - Returns list of prefixes that can be used for address autoconfiguration"""

        return [_.opt_prefix for _ in self.icmpv6_nd_options if _.opt_code == ICMP6_ND_OPT_PI and _.opt_flag_a and _.opt_prefix.prefixlen == 64]


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


class ICMPv6NdOptSLLA:
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


class ICMPv6NdOptTLLA:
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


class ICMPv6NdOptPI:
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


class ICMPv6NdOptUnk:
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
            self.multicast_address = IPv6Address(raw_record[4:8])
            self.source_address = [IPv6Address(raw_record[8 + 16 * _ : 8 + 16 * (_ + 1)]) for _ in range(self.number_of_sources)]
            self.aux_data = raw_record[8 + 16 * self.number_of_sources :]

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
