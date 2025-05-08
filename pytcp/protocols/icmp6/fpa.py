#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
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

# pylint: disable = too-many-instance-attributes
# pylint: disable = too-many-locals
# pylint: disable = too-many-return-statements
# pylint: disable = too-many-arguments
# pylint: disable = redefined-builtin

"""
Module contains Fast Packet Assembler support class for the ICMPv6 protocol.

pytcp/protocols/icmp6/fpa.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib.ip6_address import Ip6Address, Ip6Network
from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.ps import (
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
    ICMP6_UNREACHABLE__PORT,
    ICMP6_UNREACHABLE_LEN,
)
from pytcp.protocols.ip6.ps import IP6_NEXT_ICMP6

if TYPE_CHECKING:
    from pytcp.lib.mac_address import MacAddress


class Icmp6Assembler:
    """
    ICMPv6 packet assembler support class.
    """

    ip6_next = IP6_NEXT_ICMP6

    def __init__(
        self,
        *,
        type: int = 128,
        code: int = 0,
        un_data: bytes | None = None,
        ec_id: int | None = None,
        ec_seq: int | None = None,
        ec_data: bytes | None = None,
        ra_hop: int | None = None,
        ra_flag_m: bool | None = None,
        ra_flag_o: bool | None = None,
        ra_router_lifetime: int | None = None,
        ra_reachable_time: int | None = None,
        ra_retrans_timer: int | None = None,
        ns_target_address: Ip6Address | None = None,
        na_flag_r: bool | None = None,
        na_flag_s: bool | None = None,
        na_flag_o: bool | None = None,
        na_target_address: Ip6Address | None = None,
        nd_options: (
            list[Icmp6NdOptSLLA | Icmp6NdOptTLLA | Icmp6NdOptPI] | None
        ) = None,
        mlr2_multicast_address_record: (
            list[Icmp6MulticastAddressRecord] | None
        ) = None,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Class constructor.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._type = type
        self._code = code

        if (
            self._type == ICMP6_UNREACHABLE
            and self._code == ICMP6_UNREACHABLE__PORT
        ):
            self._un_reserved = 0
            self._un_data = b"" if un_data is None else un_data[:520]

            return

        if self._type == ICMP6_ECHO_REQUEST and self._code == 0:
            self._ec_id = 0 if ec_id is None else ec_id
            self._ec_seq = 0 if ec_seq is None else ec_seq
            self._ec_data = b"" if ec_data is None else ec_data

            assert 0 <= self._ec_id <= 0xFFFF
            assert 0 <= self._ec_seq <= 0xFFFF

            return

        if self._type == ICMP6_ECHO_REPLY and self._code == 0:
            self._ec_id = 0 if ec_id is None else ec_id
            self._ec_seq = 0 if ec_seq is None else ec_seq
            self._ec_data = b"" if ec_data is None else ec_data

            assert 0 <= self._ec_id <= 0xFFFF
            assert 0 <= self._ec_seq <= 0xFFFF

            return

        if self._type == ICMP6_ND_ROUTER_SOLICITATION and self._code == 0:
            self._rs_reserved = 0
            self._nd_options = [] if nd_options is None else nd_options

            return

        if self._type == ICMP6_ND_ROUTER_ADVERTISEMENT and self._code == 0:
            self._ra_hop = 0 if ra_hop is None else ra_hop
            self._ra_flag_m = False if ra_flag_m is None else ra_flag_m
            self._ra_flag_o = False if ra_flag_o is None else ra_flag_o
            self._ra_router_lifetime = (
                0 if ra_router_lifetime is None else ra_router_lifetime
            )
            self._ra_reachable_time = (
                0 if ra_reachable_time is None else ra_reachable_time
            )
            self._ra_retrans_timer = (
                0 if ra_retrans_timer is None else ra_retrans_timer
            )
            self._nd_options = [] if nd_options is None else nd_options

            assert 0 <= self._ra_hop <= 0xFF
            assert 0 <= self._ra_router_lifetime <= 0xFFFF
            assert 0 <= self._ra_reachable_time <= 0xFFFFFFFF
            assert 0 <= self._ra_retrans_timer <= 0xFFFFFFFF

            return

        if self._type == ICMP6_ND_NEIGHBOR_SOLICITATION and self._code == 0:
            self._ns_reserved = 0
            self._ns_target_address = (
                Ip6Address(0)
                if ns_target_address is None
                else ns_target_address
            )
            self._nd_options = [] if nd_options is None else nd_options

            return

        if self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT and self._code == 0:
            self._na_flag_r = False if na_flag_r is None else na_flag_r
            self._na_flag_s = False if na_flag_s is None else na_flag_s
            self._na_flag_o = False if na_flag_o is None else na_flag_o
            self._na_reserved = 0
            self._na_target_address = (
                Ip6Address(0)
                if na_target_address is None
                else na_target_address
            )
            self._nd_options = [] if nd_options is None else nd_options

            return

        if self._type == ICMP6_MLD2_REPORT and self._code == 0:
            self._mlr2_reserved = 0
            self._mlr2_multicast_address_record = (
                []
                if mlr2_multicast_address_record is None
                else mlr2_multicast_address_record
            )
            self._mlr2_number_of_multicast_address_records = len(
                self._mlr2_multicast_address_record
            )

            return

        assert False, "Unknown ICMPv6 Type/Code"

    def __len__(self) -> int:
        """
        Length of the packet.
        """

        if (
            self._type == ICMP6_UNREACHABLE
            and self._code == ICMP6_UNREACHABLE__PORT
        ):
            return ICMP6_UNREACHABLE_LEN + len(self._un_data)

        if self._type == ICMP6_ECHO_REQUEST and self._code == 0:
            return ICMP6_ECHO_REQUEST_LEN + len(self._ec_data)

        if self._type == ICMP6_ECHO_REPLY and self._code == 0:
            return ICMP6_ECHO_REPLY_LEN + len(self._ec_data)

        if self._type == ICMP6_ND_ROUTER_SOLICITATION and self._code == 0:
            assert self._nd_options is not None
            return ICMP6_ND_ROUTER_SOLICITATION_LEN + sum(
                len(_) for _ in self._nd_options
            )

        if self._type == ICMP6_ND_ROUTER_ADVERTISEMENT and self._code == 0:
            assert self._nd_options is not None
            return ICMP6_ND_ROUTER_ADVERTISEMENT_LEN + sum(
                len(_) for _ in self._nd_options
            )

        if self._type == ICMP6_ND_NEIGHBOR_SOLICITATION and self._code == 0:
            assert self._nd_options is not None
            return ICMP6_ND_NEIGHBOR_SOLICITATION_LEN + sum(
                len(_) for _ in self._nd_options
            )

        if self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT and self._code == 0:
            assert self._nd_options is not None
            return ICMP6_ND_NEIGHBOR_ADVERTISEMENT_LEN + sum(
                len(_) for _ in self._nd_options
            )

        if self._type == ICMP6_MLD2_REPORT and self._code == 0:
            return ICMP6_MLD2_REPORT_LEN + sum(
                len(_) for _ in self._mlr2_multicast_address_record
            )

        assert False, "Unknown ICMPv4 Type/Code"

    def __str__(self) -> str:
        """
        Packet log string.
        """

        header = f"ICMPv6 {self._type}/{self._code}"

        if (
            self._type == ICMP6_UNREACHABLE
            and self._code == ICMP6_UNREACHABLE__PORT
        ):
            return f"{header} (unreachable_port), dlen {len(self._un_data)}"

        if self._type == ICMP6_ECHO_REQUEST and self._code == 0:
            return (
                f"{header} (echo_request), id {self._ec_id}, "
                f"seq {self._ec_seq}, dlen {len(self._ec_data)}"
            )

        if self._type == ICMP6_ECHO_REPLY and self._code == 0:
            return (
                f"{header} (echo_reply), id {self._ec_id}, "
                f"seq {self._ec_seq}, dlen {len(self._ec_data)}"
            )

        if self._type == ICMP6_ND_ROUTER_SOLICITATION and self._code == 0:
            nd_options = ", ".join(
                str(nd_option) for nd_option in self._nd_options
            )
            return f"{header} (nd_router_solicitation)" + (
                f", {nd_options}" if nd_options else ""
            )

        if self._type == ICMP6_ND_ROUTER_ADVERTISEMENT and self._code == 0:
            nd_options = ", ".join(
                str(nd_option) for nd_option in self._nd_options
            )
            return (
                f"{header} (nd_router_advertisement), hop {self._ra_hop}"
                f", flags {'M' if self._ra_flag_m else '-'}"
                f"{'O' if self._ra_flag_o else '-'}, "
                f"rlft {self._ra_router_lifetime}, "
                f"reacht {self._ra_reachable_time}, "
                f"retrt {self._ra_retrans_timer}"
                f"{', ' + nd_options if nd_options else ''}"
            )

        if self._type == ICMP6_ND_NEIGHBOR_SOLICITATION and self._code == 0:
            nd_options = ", ".join(
                str(nd_option) for nd_option in self._nd_options
            )
            return (
                f"{header} (nd_neighbor_solicitation), "
                f"target {self._ns_target_address}"
                f"{', ' + nd_options if nd_options else ''}"
            )

        if self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT and self._code == 0:
            nd_options = ", ".join(
                str(nd_option) for nd_option in self._nd_options
            )
            return (
                f"{header} (nd_neighbor_advertisement), "
                f"target {self._na_target_address}, "
                f"flags {'R' if self._na_flag_r else '-'}"
                f"{'S' if self._na_flag_s else '-'}"
                f"{'O' if self._na_flag_o else '-'}"
                f"{', ' + nd_options if nd_options else ''}"
            )

        if self._type == ICMP6_MLD2_REPORT and self._code == 0:
            return f"{header} (mld2_report)"

        assert False, "Unknown ICMPv4 Type/Code"

    @property
    def tracker(self) -> Tracker:
        """
        Getter for ithe '_tracker' attribute.
        """
        return self._tracker

    def assemble(self, frame: memoryview, pshdr_sum: int) -> None:
        """
        Assemble packet into the raw form.
        """

        if (
            self._type == ICMP6_UNREACHABLE
            and self._code == ICMP6_UNREACHABLE__PORT
        ):
            struct.pack_into(
                f"! BBH L {len(self._un_data)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._un_reserved,
                self._un_data,
            )
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_ECHO_REQUEST and self._code == 0:
            struct.pack_into(
                f"! BBH HH {len(self._ec_data)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._ec_id,
                self._ec_seq,
                self._ec_data,
            )
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_ECHO_REPLY and self._code == 0:
            struct.pack_into(
                f"! BBH HH {len(self._ec_data)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._ec_id,
                self._ec_seq,
                bytes(self._ec_data),
            )
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_ND_ROUTER_SOLICITATION and self._code == 0:
            struct.pack_into(
                f"! BBH L {len(self._raw_nd_options)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._rs_reserved,
                self._raw_nd_options,
            )
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_ND_ROUTER_ADVERTISEMENT and self._code == 0:
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
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_ND_NEIGHBOR_SOLICITATION and self._code == 0:
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
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_ND_NEIGHBOR_ADVERTISEMENT and self._code == 0:
            struct.pack_into(
                f"! BBH L 16s {len(self._raw_nd_options)}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                (self._na_flag_r << 31)
                | (self._na_flag_s << 30)
                | (self._na_flag_o << 29)
                | self._na_reserved,
                bytes(self._na_target_address),
                self._raw_nd_options,
            )
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        if self._type == ICMP6_MLD2_REPORT and self._code == 0:
            struct.pack_into(
                f"! BBH HH {sum((len(_) for _ in self._mlr2_multicast_address_record))}s",
                frame,
                0,
                self._type,
                self._code,
                0,
                self._mlr2_reserved,
                self._mlr2_number_of_multicast_address_records,
                b"".join(
                    [_.raw_record for _ in self._mlr2_multicast_address_record]
                ),
            )
            struct.pack_into("! H", frame, 2, inet_cksum(frame, pshdr_sum))
            return

        assert False, "Unknown ICMPv4 Type/Code"

    @property
    def _raw_nd_options(self) -> bytes:
        """
        ICMPv6 ND packet options in raw format.
        """
        return b"".join(bytes(option) for option in self._nd_options)


#
#   ICMPv6 Neighbor Discovery options
#


class Icmp6NdOptSLLA:
    """
    ICMPv6 ND option - Source Link Layer Address (1).
    """

    def __init__(self, slla: MacAddress) -> None:
        """
        Constructor.
        """
        self._slla = slla

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"slla {self._slla}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return ICMP6_ND_OPT_SLLA_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return f"Icmp6NdOptSLLA({repr(self._slla)})"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB 6s",
            ICMP6_ND_OPT_SLLA,
            ICMP6_ND_OPT_SLLA_LEN >> 3,
            bytes(self._slla),
        )

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class Icmp6NdOptTLLA:
    """
    ICMPv6 ND option - Target Link Layer Address (2).
    """

    def __init__(self, tlla: MacAddress) -> None:
        """
        Constructor.
        """
        self._tlla = tlla

    def __str__(self) -> str:
        """
        Option log string.
        """
        return f"tlla {self._tlla}"

    def __len__(self) -> int:
        """
        Option length.
        """
        return ICMP6_ND_OPT_TLLA_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return f"Icmp6NdOptTLLA({repr(self._tlla)})"

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB 6s",
            ICMP6_ND_OPT_TLLA,
            ICMP6_ND_OPT_TLLA_LEN >> 3,
            bytes(self._tlla),
        )

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


class Icmp6NdOptPI:
    """
    ICMPv6 ND option - Prefix Information (3).
    """

    def __init__(
        self,
        valid_lifetime: int,
        prefer_lifetime: int,
        prefix: Ip6Network,
        flag_l: bool = False,
        flag_a: bool = False,
        flag_r: bool = False,
    ) -> None:
        """
        Constructor.
        """

        assert 0 <= valid_lifetime <= 0xFFFFFFFF
        assert 0 <= prefer_lifetime <= 0xFFFFFFFF

        self._code = ICMP6_ND_OPT_PI
        self._len = ICMP6_ND_OPT_PI_LEN
        self._flag_l = flag_l
        self._flag_a = flag_a
        self._flag_r = flag_r
        self._valid_lifetime = valid_lifetime
        self._prefer_lifetime = prefer_lifetime
        self._prefix = prefix

    def __str__(self) -> str:
        """
        Option log string.
        """
        return (
            f"prefix_info {self._prefix}, valid {self._valid_lifetime}, "
            f"prefer {self._prefer_lifetime}, "
            f"flags {'L' if self._flag_l else '-'}"
            f"{'A' if self._flag_a else '-'}{'R' if self._flag_r else '-'}"
        )

    def __len__(self) -> int:
        """
        Option length.
        """
        return ICMP6_ND_OPT_PI_LEN

    def __repr__(self) -> str:
        """
        Option representation.
        """
        return (
            f"Icmp6NdOptIP(valid_lifetime={self._valid_lifetime}, "
            f"prefer_lifetime={self._prefer_lifetime}, "
            f"prefix={repr(self._prefix)}, flag_l={self._flag_l}, "
            f"flag_s={self._flag_a}, flag_r={self._flag_r})"
        )

    def __bytes__(self) -> bytes:
        """
        Option in raw form.
        """
        return struct.pack(
            "! BB BB L L L 16s",
            self._code,
            self._len >> 3,
            len(self._prefix.mask),
            (self._flag_l << 7) | (self._flag_a << 6) | (self._flag_r << 6),
            self._valid_lifetime,
            self._prefer_lifetime,
            0,
            bytes(self._prefix.address),
        )

    def __eq__(self, other: object) -> bool:
        """
        Equal operator.
        """
        return repr(self) == repr(other)


#
#   ICMPv6 Multicast support classes
#


class Icmp6MulticastAddressRecord:
    """
    Multicast Address Record used by MLDv2 Report message.
    """

    def __init__(
        self,
        record_type: int,
        multicast_address: Ip6Address,
        source_address: list[Ip6Address] | None = None,
        aux_data: bytes | None = None,
    ) -> None:
        """
        Class constructor.
        """
        self._record_type = record_type
        self._multicast_address = multicast_address
        self._source_address = [] if source_address is None else source_address
        self._number_of_sources = len(self._source_address)
        self._aux_data = b"" if aux_data is None else aux_data
        self._aux_data_len = len(self._aux_data)

    def __len__(self) -> int:
        """
        Length of raw record.
        """
        return len(self.raw_record)

    def __hash__(self) -> int:
        """
        Hash of raw record.
        """
        return hash(self.raw_record)

    def __eq__(self, other: object) -> bool:
        """
        Compare two records.
        """
        if not isinstance(other, Icmp6MulticastAddressRecord):
            return NotImplemented
        return self.raw_record == other.raw_record

    @property
    def multicast_address(self) -> Ip6Address:
        """
        Getter for the '_multicast_address' attribute.
        """
        return self._multicast_address

    @property
    def raw_record(self) -> bytes:
        """
        Get record in raw format.
        """
        return (
            struct.pack(
                "! BBH 16s",
                self._record_type,
                self._aux_data_len,
                self._number_of_sources,
                bytes(self._multicast_address),
            )
            + b"".join([bytes(_) for _ in self._source_address])
            + self._aux_data
        )
