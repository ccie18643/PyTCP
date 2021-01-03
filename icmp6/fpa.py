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


#
# icmp6/fpa.py - Fast Packet Assembler support class for ICMPv6 protocol
#


import struct

import icmp6.ps
import ip6.ps
from misc.ip_helper import inet_cksum
from misc.ipv6_address import IPv6Address, IPv6Network
from misc.tracker import Tracker


class Assembler(icmp6.ps.Base):
    """ ICMPv6 packet assembler support class """

    ip6_next = ip6.ps.NEXT_HEADER_ICMP6

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
        """ Class constructor """

        self.tracker = Tracker("TX", echo_tracker)

        self.type = type
        self.code = code

        self.nd_options = [] if nd_options is None else nd_options

        if self.type == icmp6.ps.UNREACHABLE:
            self.un_reserved = 0
            self.un_data = un_data[:520]

        elif self.type == icmp6.ps.ECHO_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == icmp6.ps.ECHO_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = ec_data

        elif self.type == icmp6.ps.ROUTER_SOLICITATION:
            self.rs_reserved = 0

        elif self.type == icmp6.ps.ROUTER_ADVERTISEMENT:
            self.ra_hop = ra_hop
            self.ra_flag_m = ra_flag_m
            self.ra_flag_o = ra_flag_o
            self.ra_router_lifetime = ra_router_lifetime
            self.ra_reachable_time = ra_reachable_time
            self.ra_retrans_timer = ra_retrans_timer

        elif self.type == icmp6.ps.NEIGHBOR_SOLICITATION:
            self.ns_reserved = 0
            self.ns_target_address = ns_target_address

        elif self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT:
            self.na_flag_r = na_flag_r
            self.na_flag_s = na_flag_s
            self.na_flag_o = na_flag_o
            self.na_reserved = 0
            self.na_target_address = na_target_address

        elif self.type == icmp6.ps.MLD2_REPORT:
            self.mlr2_reserved = 0
            self.mlr2_multicast_address_record = [] if mlr2_multicast_address_record is None else mlr2_multicast_address_record
            self.mlr2_number_of_multicast_address_records = len(self.mlr2_multicast_address_record)

    def __len__(self):
        """ Length of the packet """

        if self.type == icmp6.ps.UNREACHABLE:
            return icmp6.ps.UNREACHABLE_LEN + len(self.un_data)

        if self.type == icmp6.ps.ECHO_REQUEST:
            return icmp6.ps.ECHO_REQUEST_LEN + len(self.ec_data)

        if self.type == icmp6.ps.ECHO_REPLY:
            return icmp6.ps.ECHO_REPLY_LEN + len(self.ec_data)

        if self.type == icmp6.ps.ROUTER_SOLICITATION:
            return icmp6.ps.ROUTER_SOLICITATION_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.ROUTER_ADVERTISEMENT:
            return icmp6.ps.ROUTER_ADVERTISEMENT_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.NEIGHBOR_SOLICITATION:
            return icmp6.ps.NEIGHBOR_SOLICITATION_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT:
            return icmp6.ps.NEIGHBOR_ADVERTISEMENT_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.MLD2_REPORT:
            return icmp6.ps.MLD2_REPORT_LEN + sum([len(_) for _ in self.mlr2_multicast_address_record])

    def assemble(self, frame, hptr, pshdr_sum):
        """ Assemble packet into the raw form """

        if self.type == icmp6.ps.UNREACHABLE:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, self.un_reserved, self.un_data)

        elif self.type == icmp6.ps.ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == icmp6.ps.ECHO_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == icmp6.ps.ROUTER_SOLICITATION:
            struct.pack_into(f"! BBH L {len(self.raw_nd_options)}s", frame, hptr, self.type, self.code, 0, self.rs_reserved, self.raw_nd_options)

        elif self.type == icmp6.ps.ROUTER_ADVERTISEMENT:
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

        elif self.type == icmp6.ps.NEIGHBOR_SOLICITATION:
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

        elif self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT:
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

        elif self.type == icmp6.ps.MLD2_REPORT:
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
        """ ICMPv6 ND packet options in raw format """

        raw_nd_options = b""

        for option in self.nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options


#
#   ICMPv6 Neighbor Discovery options
#


class NdOptSLLA(icmp6.ps.NdOptSLLA):
    """ ICMPv6 ND option - Source Link Layer Address (1) """

    def __init__(self, slla):
        self.slla = slla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", icmp6.ps.ND_OPT_SLLA, icmp6.ps.ND_OPT_SLLA_LEN >> 3, bytes.fromhex(self.slla.replace(":", "")))


class NdOptTLLA(icmp6.ps.NdOptTLLA):
    """ ICMPv6 ND option - Target Link Layer Address (2) """

    def __init__(self, tlla):
        self.tlla = tlla

    @property
    def raw_option(self):
        return struct.pack("! BB 6s", icmp6.ps.ND_OPT_TLLA, icmp6.ps.ND_OPT_TLLA_LEN >> 3, bytes.fromhex(self.tlla.replace(":", "")))


class NdOptPI(icmp6.ps.NdOptPI):
    """ ICMPv6 ND option - Prefix Information (3) """

    def __init__(
        self,
        flag_l=False,
        flag_a=False,
        flag_r=False,
        valid_lifetime=None,
        preferred_lifetime=None,
        prefix=None,
    ):
        self.code = icmp6.ps.ND_OPT_PI
        self.len = icmp6.ps.ND_OPT_PI_LEN
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


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """ Multicast Address Record used by MLDv2 Report message """

    def __init__(self, record_type, multicast_address, source_address=None, aux_data=b""):
        """ Class constructor """

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
