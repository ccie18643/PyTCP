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
# icmp6/fpa.py - Fast Packet Assembler support class for ICMPv6 protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Optional

import icmp6.ps
import ip6.ps
from misc.ip_helper import inet_cksum
from misc.tracker import Tracker

if TYPE_CHECKING:
    from lib.ip6_address import Ip6Address, Ip6Network
    from lib.mac_address import MacAddress


class Icmp6Assembler:
    """ICMPv6 packet assembler support class"""

    ip6_next = ip6.ps.IP6_NEXT_HEADER_ICMP6

    def __init__(
        self,
        type: int,
        code: int = 0,
        un_data: Optional[bytes] = None,
        ec_id: Optional[int] = None,
        ec_seq: Optional[int] = None,
        ec_data: Optional[bytes] = None,
        ra_hop: Optional[int] = None,
        ra_flag_m: Optional[bool] = None,
        ra_flag_o: Optional[bool] = None,
        ra_router_lifetime: Optional[int] = None,
        ra_reachable_time: Optional[int] = None,
        ra_retrans_timer: Optional[int] = None,
        ns_target_address: Optional[Ip6Address] = None,
        na_flag_r: Optional[bool] = None,
        na_flag_s: Optional[bool] = None,
        na_flag_o: Optional[bool] = None,
        na_target_address: Optional[Ip6Address] = None,
        nd_options: Optional[list] = None,
        mlr2_multicast_address_record: Optional[list] = None,
        echo_tracker: Optional[Tracker] = None,
    ) -> None:
        """Class constructor"""

        self.tracker = Tracker("TX", echo_tracker)

        self.type = type
        self.code = code

        self.nd_options = [] if nd_options is None else nd_options

        if self.type == icmp6.ps.ICMP6_UNREACHABLE:
            self.un_reserved = 0
            self.un_data = b"" if un_data is None else un_data[:520]

        elif self.type == icmp6.ps.ICMP6_ECHOR_REQUEST:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = b"" if ec_data is None else ec_data

        elif self.type == icmp6.ps.ICMP6_ECHOR_REPLY:
            self.ec_id = ec_id
            self.ec_seq = ec_seq
            self.ec_data = b"" if ec_data is None else ec_data

        elif self.type == icmp6.ps.ICMP6_ROUTER_SOLICITATION:
            self.rs_reserved = 0

        elif self.type == icmp6.ps.ICMP6_ROUTER_ADVERTISEMENT:
            self.ra_hop = ra_hop
            self.ra_flag_m = False if ra_flag_m is None else ra_flag_m
            self.ra_flag_o = False if ra_flag_o is None else ra_flag_o
            self.ra_router_lifetime = ra_router_lifetime
            self.ra_reachable_time = ra_reachable_time
            self.ra_retrans_timer = ra_retrans_timer

        elif self.type == icmp6.ps.ICMP6_NEIGHBOR_SOLICITATION:
            self.ns_reserved = 0
            self.ns_target_address = ns_target_address

        elif self.type == icmp6.ps.ICMP6_NEIGHBOR_ADVERTISEMENT:
            self.na_flag_r = False if na_flag_r is None else na_flag_r
            self.na_flag_s = False if na_flag_s is None else na_flag_s
            self.na_flag_o = False if na_flag_o is None else na_flag_o
            self.na_reserved = 0
            self.na_target_address = na_target_address

        elif self.type == icmp6.ps.ICMP6_MLD2_REPORT:
            self.mlr2_reserved = 0
            self.mlr2_multicast_address_record = [] if mlr2_multicast_address_record is None else mlr2_multicast_address_record
            self.mlr2_number_of_multicast_address_records = len(self.mlr2_multicast_address_record)

    def __len__(self) -> int:
        """Length of the packet"""

        if self.type == icmp6.ps.ICMP6_UNREACHABLE:
            return icmp6.ps.ICMP6_UNREACHABLE_LEN + len(self.un_data)

        if self.type == icmp6.ps.ICMP6_ECHOR_REQUEST:
            return icmp6.ps.ICMP6_ECHOR_REQUEST_LEN + len(self.ec_data)

        if self.type == icmp6.ps.ICMP6_ECHOR_REPLY:
            return icmp6.ps.ICMP6_ECHOR_REPLY_LEN + len(self.ec_data)

        if self.type == icmp6.ps.ICMP6_ROUTER_SOLICITATION:
            assert self.nd_options is not None
            return icmp6.ps.ICMP6_ROUTER_SOLICITATION_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.ICMP6_ROUTER_ADVERTISEMENT:
            assert self.nd_options is not None
            return icmp6.ps.ICMP6_ROUTER_ADVERTISEMENT_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.ICMP6_NEIGHBOR_SOLICITATION:
            assert self.nd_options is not None
            return icmp6.ps.ICMP6_NEIGHBOR_SOLICITATION_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.ICMP6_NEIGHBOR_ADVERTISEMENT:
            assert self.nd_options is not None
            return icmp6.ps.ICMP6_NEIGHBOR_ADVERTISEMENT_LEN + sum([len(_) for _ in self.nd_options])

        if self.type == icmp6.ps.ICMP6_MLD2_REPORT:
            return icmp6.ps.ICMP6_MLD2_REPORT_LEN + sum([len(_) for _ in self.mlr2_multicast_address_record])

        return 0

    from icmp6.ps import __str__

    def assemble(self, frame: bytearray, hptr: int, pshdr_sum: int) -> None:
        """Assemble packet into the raw form"""

        if self.type == icmp6.ps.ICMP6_UNREACHABLE:
            struct.pack_into(f"! BBH L {len(self.un_data)}s", frame, hptr, self.type, self.code, 0, self.un_reserved, self.un_data)

        elif self.type == icmp6.ps.ICMP6_ECHOR_REQUEST:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == icmp6.ps.ICMP6_ECHOR_REPLY:
            struct.pack_into(f"! BBH HH {len(self.ec_data)}s", frame, hptr, self.type, self.code, 0, self.ec_id, self.ec_seq, self.ec_data)

        elif self.type == icmp6.ps.ICMP6_ROUTER_SOLICITATION:
            struct.pack_into(f"! BBH L {len(self.raw_nd_options)}s", frame, hptr, self.type, self.code, 0, self.rs_reserved, self.raw_nd_options)

        elif self.type == icmp6.ps.ICMP6_ROUTER_ADVERTISEMENT:
            assert self.ra_flag_m is not None
            assert self.ra_flag_o is not None
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

        elif self.type == icmp6.ps.ICMP6_NEIGHBOR_SOLICITATION:
            assert self.ns_target_address is not None
            struct.pack_into(
                f"! BBH L 16s {len(self.raw_nd_options)}s",
                frame,
                hptr,
                self.type,
                self.code,
                0,
                self.ns_reserved,
                bytes(self.ns_target_address),
                self.raw_nd_options,
            )

        elif self.type == icmp6.ps.ICMP6_NEIGHBOR_ADVERTISEMENT:
            assert self.na_flag_r is not None
            assert self.na_flag_s is not None
            assert self.na_flag_o is not None
            assert self.na_target_address is not None
            struct.pack_into(
                f"! BBH L 16s {len(self.raw_nd_options)}s",
                frame,
                hptr,
                self.type,
                self.code,
                0,
                (self.na_flag_r << 31) | (self.na_flag_s << 30) | (self.na_flag_o << 29) | self.na_reserved,
                bytes(self.na_target_address),
                self.raw_nd_options,
            )

        elif self.type == icmp6.ps.ICMP6_MLD2_REPORT:
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
    def raw_nd_options(self) -> bytes:
        """ICMPv6 ND packet options in raw format"""

        assert self.nd_options is not None

        raw_nd_options = b""

        for option in self.nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options


#
#   ICMPv6 Neighbor Discovery options
#


class Icmp6NdOptSLLA(icmp6.ps.Icmp6NdOptSLLA):
    """ICMPv6 ND option - Source Link Layer Address (1)"""

    def __init__(self, slla: MacAddress) -> None:
        self.slla = slla

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB 6s", icmp6.ps.ICMP6_ND_OPT_SLLA, icmp6.ps.ICMP6_ND_OPT_SLLA_LEN >> 3, bytes(self.slla))


class Icmp6NdOptTLLA(icmp6.ps.Icmp6NdOptTLLA):
    """ICMPv6 ND option - Target Link Layer Address (2)"""

    def __init__(self, tlla: MacAddress) -> None:
        self.tlla = tlla

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB 6s", icmp6.ps.ICMP6_ND_OPT_TLLA, icmp6.ps.ICMP6_ND_OPT_TLLA_LEN >> 3, bytes(self.tlla))


class Icmp6NdOptPI(icmp6.ps.Icmp6NdOptPI):
    """ICMPv6 ND option - Prefix Information (3)"""

    def __init__(
        self,
        valid_lifetime: int,
        preferred_lifetime: int,
        prefix: Ip6Network,
        flag_l: bool = False,
        flag_a: bool = False,
        flag_r: bool = False,
    ) -> None:
        self.code = icmp6.ps.ICMP6_ND_OPT_PI
        self.len = icmp6.ps.ICMP6_ND_OPT_PI_LEN
        self.flag_l = flag_l
        self.flag_a = flag_a
        self.flag_r = flag_r
        self.valid_lifetime = valid_lifetime
        self.preferred_lifetime = preferred_lifetime
        self.prefix = Ip6Network(prefix)

    @property
    def raw_option(self) -> bytes:
        return struct.pack(
            "! BB BB L L L 16s",
            self.code,
            self.len >> 3,
            len(self.prefix.mask),
            (self.flag_l << 7) | (self.flag_a << 6) | (self.flag_r << 6),
            self.valid_lifetime,
            self.preferred_lifetime,
            bytes(self.prefix.address),
        )


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """Multicast Address Record used by MLDv2 Report message"""

    def __init__(self, record_type: int, multicast_address: Ip6Address, source_address: Optional[list] = None, aux_data: Optional[bytes] = None) -> None:
        """Class constructor"""

        self.record_type = record_type
        self.multicast_address = multicast_address
        self.source_address = [] if source_address is None else source_address
        self.number_of_sources = len(self.source_address)
        self.aux_data = b"" if aux_data is None else aux_data
        self.aux_data_len = len(self.aux_data)

    def __len__(self) -> int:
        """Length of raw record"""

        return len(self.raw_record)

    def __hash__(self) -> int:
        """Hash of raw record"""

        return hash(self.raw_record)

    def __eq__(self, other: object) -> bool:
        """Compare two records"""

        if not isinstance(other, MulticastAddressRecord):
            return NotImplemented

        return self.raw_record == other.raw_record

    @property
    def raw_record(self) -> bytes:
        """Get record in raw format"""

        return (
            struct.pack("! BBH 16s", self.record_type, self.aux_data_len, self.number_of_sources, bytes(self.multicast_address))
            + b"".join([bytes(_) for _ in self.source_address])
            + self.aux_data
        )
