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
# protocols/icmp6/fpa.py - Fast Packet Assembler support class for ICMPv6 protocol
#


from __future__ import annotations  # Required by Python ver < 3.10

import struct
from typing import TYPE_CHECKING, Optional

from lib.tracker import Tracker
from misc.ip_helper import inet_cksum
from protocols.icmp6.ps import (
    ICMP6_ECHO_REPLY,
    ICMP6_ECHO_REPLY_LEN,
    ICMP6_ECHO_REQUEST,
    ICMP6_ECHO_REQUEST_LEN,
    ICMP6_MLD2_REPORT,
    ICMP6_MLD2_REPORT_LEN,
    ICMP6_ND_NEIGHBOR_ADVERTISEMENT,
    ICMP6_ND_NEIGHBOR_ADVERTISEMENT_LEN,
    ICMP6_ND_NEIGHBOR_SOLICITATION,
    ICMP6_ND_NEIGHBOR_SOLICITATION_LEN,
    ICMP6_ND_OPT_PI,
    ICMP6_ND_OPT_PI_LEN,
    ICMP6_ND_OPT_SLLA,
    ICMP6_ND_OPT_SLLA_LEN,
    ICMP6_ND_OPT_TLLA,
    ICMP6_ND_OPT_TLLA_LEN,
    ICMP6_ND_ROUTER_ADVERTISEMENT,
    ICMP6_ND_ROUTER_ADVERTISEMENT_LEN,
    ICMP6_ND_ROUTER_SOLICITATION,
    ICMP6_ND_ROUTER_SOLICITATION_LEN,
    ICMP6_UNREACHABLE,
    ICMP6_UNREACHABLE_LEN,
)
from protocols.ip6.ps import IP6_NEXT_HEADER_ICMP6

if TYPE_CHECKING:
    from lib.ip6_address import Ip6Address, Ip6Network
    from lib.mac_address import MacAddress


class Icmp6Assembler:
    """ICMPv6 packet assembler support class"""

    ip6_next = IP6_NEXT_HEADER_ICMP6

    def __init__(
        self,
        *,
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
        nd_options: Optional[list[Icmp6NdOptSLLA | Icmp6NdOptTLLA | Icmp6NdOptPI]] = None,
        mlr2_multicast_address_record: Optional[list[Icmp6MulticastAddressRecord]] = None,
        echo_tracker: Optional[Tracker] = None,
    ) -> None:
        """Class constructor"""

        self._tracker = Tracker("TX", echo_tracker)

        self._type = type
        self._code = code

        self._nd_options: list[Icmp6NdOptSLLA | Icmp6NdOptTLLA | Icmp6NdOptPI] = [] if nd_options is None else nd_options

        self._un_reserved: int
        self._un_data: bytes
        self._ec_id: int
        self._ec_seq: int
        self._ec_data: bytes
        self._rs_reserved: int
        self._ra_hop: int
        self._ra_flag_m: bool
        self._ra_flag_o: bool
        self._ra_router_lifetime: int
        self._ra_reachable_time: int
        self._ra_retrans_timer: int
        self._ns_reserved: int
        self._ns_target_address: Ip6Address
        self._na_flag_r: bool
        self._na_flag_s: bool
        self._na_flag_o: bool
        self._na_reserved: int
        self._na_target_address: Ip6Address
        self._mlr2_reserved: int
        self._mlr2_multicast_address_record: list[Icmp6MulticastAddressRecord]
        self._mlr2_number_of_multicast_address_records: int

        if self._type == ICMP6_UNREACHABLE:
            self._un_reserved = 0
            self._un_data = b"" if un_data is None else un_data[:520]

        elif self._type == ICMP6_ECHO_REQUEST:
            self._ec_id = 0 if ec_id is None else ec_id
            self._ec_seq = 0 if ec_seq is None else ec_seq
            self._ec_data = b"" if ec_data is None else ec_data

        elif self._type == ICMP6_ECHO_REPLY:
            self._ec_id = 0 if ec_id is None else ec_id
            self._ec_seq = 0 if ec_seq is None else ec_seq
            self._ec_data = b"" if ec_data is None else ec_data

        elif self._type == ICMP6_ND_ROUTER_SOLICITATION:
            self._rs_reserved = 0

        elif self._type == ICMP6_ND_ROUTER_ADVERTISEMENT:
            self._ra_hop = 0 if ra_hop is None else ra_hop
            self._ra_flag_m = False if ra_flag_m is None else ra_flag_m
            self._ra_flag_o = False if ra_flag_o is None else ra_flag_o
            self._ra_router_lifetime = 0 if ra_router_lifetime is None else ra_router_lifetime
            self._ra_reachable_time = 0 if ra_reachable_time is None else ra_reachable_time
            self._ra_retrans_timer = 0 if ra_retrans_timer is None else ra_retrans_timer

        elif self._type == ICMP6_ND_NEIGHBOR_SOLICITATION:
            self._ns_reserved = 0
            self._ns_target_address = Ip6Address(0) if ns_target_address is None else ns_target_address

        elif self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT:
            self._na_flag_r = False if na_flag_r is None else na_flag_r
            self._na_flag_s = False if na_flag_s is None else na_flag_s
            self._na_flag_o = False if na_flag_o is None else na_flag_o
            self._na_reserved = 0
            self._na_target_address = Ip6Address(0) if na_target_address is None else na_target_address

        elif self._type == ICMP6_MLD2_REPORT:
            self._mlr2_reserved = 0
            self._mlr2_multicast_address_record = [] if mlr2_multicast_address_record is None else mlr2_multicast_address_record
            self._mlr2_number_of_multicast_address_records = len(self._mlr2_multicast_address_record)

    def __len__(self) -> int:
        """Length of the packet"""

        if self._type == ICMP6_UNREACHABLE:
            return ICMP6_UNREACHABLE_LEN + len(self._un_data)

        if self._type == ICMP6_ECHO_REQUEST:
            return ICMP6_ECHO_REQUEST_LEN + len(self._ec_data)

        if self._type == ICMP6_ECHO_REPLY:
            return ICMP6_ECHO_REPLY_LEN + len(self._ec_data)

        if self._type == ICMP6_ND_ROUTER_SOLICITATION:
            assert self._nd_options is not None
            return ICMP6_ND_ROUTER_SOLICITATION_LEN + sum([len(_) for _ in self._nd_options])

        if self._type == ICMP6_ND_ROUTER_ADVERTISEMENT:
            assert self._nd_options is not None
            return ICMP6_ND_ROUTER_ADVERTISEMENT_LEN + sum([len(_) for _ in self._nd_options])

        if self._type == ICMP6_ND_NEIGHBOR_SOLICITATION:
            assert self._nd_options is not None
            return ICMP6_ND_NEIGHBOR_SOLICITATION_LEN + sum([len(_) for _ in self._nd_options])

        if self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT:
            assert self._nd_options is not None
            return ICMP6_ND_NEIGHBOR_ADVERTISEMENT_LEN + sum([len(_) for _ in self._nd_options])

        if self._type == ICMP6_MLD2_REPORT:
            return ICMP6_MLD2_REPORT_LEN + sum([len(_) for _ in self._mlr2_multicast_address_record])

        return 0

    def __str__(self) -> str:
        """Packet log string"""

        log = f"ICMPv6 type {self._type}, code {self._code}"

        if self._type == ICMP6_UNREACHABLE:
            pass

        elif self._type == ICMP6_ECHO_REQUEST:
            log += f", id {self._ec_id}, seq {self._ec_seq}"

        elif self._type == ICMP6_ECHO_REPLY:
            log += f", id {self._ec_id}, seq {self._ec_seq}"

        elif self._type == ICMP6_ND_ROUTER_SOLICITATION:
            assert self._nd_options is not None
            for nd_option in self._nd_options:
                log += ", " + str(nd_option)

        elif self._type == ICMP6_ND_ROUTER_ADVERTISEMENT:
            assert self._nd_options is not None
            log += f", hop {self._ra_hop}"
            log += f", flags {'M' if self._ra_flag_m else '-'}{'O' if self._ra_flag_o else '-'}"
            log += f", rlft {self._ra_router_lifetime}, reacht {self._ra_reachable_time}, retrt {self._ra_retrans_timer}"
            for nd_option in self._nd_options:
                log += ", " + str(nd_option)

        elif self._type == ICMP6_ND_NEIGHBOR_SOLICITATION:
            assert self._nd_options is not None
            log += f", target {self._ns_target_address}"
            for nd_option in self._nd_options:
                log += ", " + str(nd_option)

        elif self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT:
            assert self._nd_options is not None
            log += f", target {self._na_target_address}"
            log += f", flags {'R' if self._na_flag_r else '-'}{'S' if self._na_flag_s else '-'}{'O' if self._na_flag_o else '-'}"
            for nd_option in self._nd_options:
                log += ", " + str(nd_option)

        elif self._type == ICMP6_MLD2_REPORT:
            pass

        return log

    @property
    def tracker(self) -> Tracker:
        """Getter for _tracker"""

        return self._tracker

    def assemble(self, frame: memoryview, pshdr_sum: int) -> None:
        """Assemble packet into the raw form"""

        if self._type == ICMP6_UNREACHABLE:
            struct.pack_into(f"! BBH L {len(self._un_data)}s", frame, 0, self._type, self._code, 0, self._un_reserved, self._un_data)

        elif self._type == ICMP6_ECHO_REQUEST:
            struct.pack_into(f"! BBH HH {len(self._ec_data)}s", frame, 0, self._type, self._code, 0, self._ec_id, self._ec_seq, self._ec_data)

        elif self._type == ICMP6_ECHO_REPLY:
            # memoryview: bytes conversion required
            struct.pack_into(f"! BBH HH {len(self._ec_data)}s", frame, 0, self._type, self._code, 0, self._ec_id, self._ec_seq, bytes(self._ec_data))

        elif self._type == ICMP6_ND_ROUTER_SOLICITATION:
            struct.pack_into(f"! BBH L {len(self._raw_nd_options)}s", frame, 0, self._type, self._code, 0, self._rs_reserved, self._raw_nd_options)

        elif self._type == ICMP6_ND_ROUTER_ADVERTISEMENT:
            assert self._ra_flag_m is not None
            assert self._ra_flag_o is not None
            struct.pack_into(
                f"! BBH BBH L L {len(self._raw_nd_options)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._ra_hop,
                (self._ra_flag_m << 7) | (self._ra_flag_o << 6),
                self._ra_router_lifetime,
                self._ra_reachable_time,
                self._ra_retrans_timer,
                self._raw_nd_options,
            )

        elif self._type == ICMP6_ND_NEIGHBOR_SOLICITATION:
            assert self._ns_target_address is not None
            struct.pack_into(
                f"! BBH L 16s {len(self._raw_nd_options)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._ns_reserved,
                bytes(self._ns_target_address),
                self._raw_nd_options,
            )

        elif self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT:
            assert self._na_flag_r is not None
            assert self._na_flag_s is not None
            assert self._na_flag_o is not None
            assert self._na_target_address is not None
            struct.pack_into(
                f"! BBH L 16s {len(self._raw_nd_options)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                (self._na_flag_r << 31) | (self._na_flag_s << 30) | (self._na_flag_o << 29) | self._na_reserved,
                bytes(self._na_target_address),
                self._raw_nd_options,
            )

        elif self._type == ICMP6_MLD2_REPORT:
            struct.pack_into(
                f"! BBH HH {sum([len(_) for _ in self._mlr2_multicast_address_record])}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._mlr2_reserved,
                self._mlr2_number_of_multicast_address_records,
                b"".join([_.raw_record for _ in self._mlr2_multicast_address_record]),
            )

        struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))

    @property
    def _raw_nd_options(self) -> bytes:
        """ICMPv6 ND packet options in raw format"""

        assert self._nd_options is not None

        raw_nd_options = b""

        for option in self._nd_options:
            raw_nd_options += option.raw_option

        return raw_nd_options


#
#   ICMPv6 Neighbor Discovery options
#


class Icmp6NdOptSLLA:
    """ICMPv6 ND option - Source Link Layer Address (1)"""

    def __init__(self, slla: MacAddress) -> None:
        self._slla = slla

    def __str__(self) -> str:
        """Option log string"""

        return f"slla {self._slla}"

    def __len__(self) -> int:
        """Option length"""

        return ICMP6_ND_OPT_SLLA_LEN

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB 6s", ICMP6_ND_OPT_SLLA, ICMP6_ND_OPT_SLLA_LEN >> 3, bytes(self._slla))


class Icmp6NdOptTLLA:
    """ICMPv6 ND option - Target Link Layer Address (2)"""

    def __init__(self, tlla: MacAddress) -> None:
        self._tlla = tlla

    def __str__(self) -> str:
        """Option log string"""

        return f"tlla {self._tlla}"

    def __len__(self) -> int:
        """Option length"""

        return ICMP6_ND_OPT_TLLA_LEN

    @property
    def raw_option(self) -> bytes:
        return struct.pack("! BB 6s", ICMP6_ND_OPT_TLLA, ICMP6_ND_OPT_TLLA_LEN >> 3, bytes(self._tlla))


class Icmp6NdOptPI:
    """ICMPv6 ND option - Prefix Information (3)"""

    def __init__(
        self,
        valid_lifetime: int,
        preferr_lifetime: int,
        prefix: Ip6Network,
        flag_l: bool = False,
        flag_a: bool = False,
        flag_r: bool = False,
    ) -> None:
        self._code = ICMP6_ND_OPT_PI
        self._len = ICMP6_ND_OPT_PI_LEN
        self._flag_l = flag_l
        self._flag_a = flag_a
        self._flag_r = flag_r
        self._valid_lifetime = valid_lifetime
        self._preferr_lifetime = preferr_lifetime
        self._prefix = Ip6Network(prefix)

    def __str__(self) -> str:
        """Option log string"""

        return f"prefix_info {self._prefix}"

    def __len__(self) -> int:
        """Option length"""

        return ICMP6_ND_OPT_PI_LEN

    @property
    def raw_option(self) -> bytes:
        return struct.pack(
            "! BB BB L L L 16s",
            self._code,
            self._len >> 3,
            len(self._prefix.mask),
            (self._flag_l << 7) | (self._flag_a << 6) | (self._flag_r << 6),
            self._valid_lifetime,
            self._preferr_lifetime,
            bytes(self._prefix.address),
        )


#
#   ICMPv6 Multicast support classes
#


class Icmp6MulticastAddressRecord:
    """Multicast Address Record used by MLDv2 Report message"""

    def __init__(
        self, record_type: int, multicast_address: Ip6Address, source_address: Optional[list[Ip6Address]] = None, aux_data: Optional[bytes] = None
    ) -> None:
        """Class constructor"""

        self._record_type = record_type
        self._multicast_address = multicast_address
        self._source_address = [] if source_address is None else source_address
        self._number_of_sources = len(self._source_address)
        self._aux_data = b"" if aux_data is None else aux_data
        self._aux_data_len = len(self._aux_data)

    def __len__(self) -> int:
        """Length of raw record"""

        return len(self.raw_record)

    def __hash__(self) -> int:
        """Hash of raw record"""

        return hash(self.raw_record)

    def __eq__(self, other: object) -> bool:
        """Compare two records"""

        if not isinstance(other, Icmp6MulticastAddressRecord):
            return NotImplemented

        return self.raw_record == other.raw_record

    @property
    def multicast_address(self) -> Ip6Address:
        """Getter for multicast_address"""

        return self._multicast_address

    @property
    def raw_record(self) -> bytes:
        """Get record in raw format"""

        return (
            struct.pack("! BBH 16s", self._record_type, self._aux_data_len, self._number_of_sources, bytes(self._multicast_address))
            + b"".join([bytes(_) for _ in self._source_address])
            + self._aux_data
        )
