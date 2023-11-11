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
# pylint: disable = too-many-return-statements
# pylint: disable = too-many-branches
# pylint: disable = too-many-public-methods
# pylint: disable = attribute-defined-outside-init

"""
Module contains Fast Packet Parse support class for the ICMPv6 protocol.

pytcp/protocols/icmp6/fpp.py

ver 2.7
"""


from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from pytcp.lib.errors import PacketIntegrityError, PacketSanityError
from pytcp.lib.ip6_address import Ip6Address, Ip6Mask, Ip6Network
from pytcp.lib.ip_helper import inet_cksum
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.icmp6.ps import (
    ICMP6_HEADER_LEN,
    ICMP6_MESSAGE_LEN__ECHO_REPLY,
    ICMP6_MESSAGE_LEN__ECHO_REQUEST,
    ICMP6_MESSAGE_LEN__MLD2_QUERY,
    ICMP6_MESSAGE_LEN__MLD2_REPORT,
    ICMP6_MESSAGE_LEN__ND_NEIGHBOR_ADVERTISEMENT,
    ICMP6_MESSAGE_LEN__ND_NEIGHBOR_SOLICITATION,
    ICMP6_MESSAGE_LEN__ND_ROUTER_ADVERTISEMENT,
    ICMP6_MESSAGE_LEN__ND_ROUTER_SOLICITATION,
    ICMP6_MESSAGE_LEN__UNREACHABLE,
    ICMP6_MLD2_RECORD_LEN,
    Icmp6,
    Icmp6Code,
    Icmp6EchoReplyMessage,
    Icmp6EchoRequestMessage,
    Icmp6Mld2AddressRecord,
    Icmp6Mld2RecordType,
    Icmp6Mld2ReportMessage,
    Icmp6NdNeighborAdvertisementMessage,
    Icmp6NdNeighborSolicitationMessage,
    Icmp6NdOpt,
    Icmp6NdOptCode,
    Icmp6NdOptPi,
    Icmp6NdOptSlla,
    Icmp6NdOptTlla,
    Icmp6NdOptUnk,
    Icmp6NdRouterAdvertisementMessage,
    Icmp6NdRouterSolicitationMessage,
    Icmp6PortUnreachableMessage,
    Icmp6Type,
    Icmp6UnknownMessage,
    Icmp6UnreachableCode,
    Icmp6UnreachableMessage,
)

if TYPE_CHECKING:
    from pytcp.lib.packet import PacketRx


class Icmp6IntegrityError(PacketIntegrityError):
    """
    Exception raised when ICMPv6 packet integrity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ICMPv6] " + message)


class Icmp6SanityError(PacketSanityError):
    """
    Exception raised when ICMPv6 packet sanity check fails.
    """

    def __init__(self, message: str):
        super().__init__("[ICMPv6] " + message)


class Icmp6Parser(Icmp6):
    """
    ICMPv6 packet parser class.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Parse ICMPv6 packet.
        """

        self._frame = packet_rx.frame
        self._plen = packet_rx.ip6.dlen
        self._validate_integrity(
            pshdr_sum=packet_rx.ip6.pshdr_sum,
        )
        self._parse()
        self._validate_sanity(
            ip6__src=packet_rx.ip6.src,
            ip6__dst=packet_rx.ip6.dst,
            ip6__hop=packet_rx.ip6.hop,
        )

        packet_rx.icmp6 = self
        packet_rx.frame = packet_rx.frame[len(self) :]

    def __len__(self) -> int:
        """
        Get number of bytes remaining in the frame.
        """

        return len(self._frame)

    @property
    def __copy__(self) -> bytes:
        """
        Get the packet copy.
        """

        return self._frame[: self.plen]

    @property
    def plen(self) -> int:
        """
        Get packet length.
        """

        return self._plen

    def _nd_option_integrity_check(self, optr: int) -> None:
        """
        Check integrity of ICMPv6 ND options prior to parsing them.
        """

        while optr < len(self._frame):
            if optr + 1 > len(self._frame):
                raise Icmp6IntegrityError(
                    "Wrong option length (I)",
                )
            if self._frame[optr + 1] == 0:
                raise Icmp6IntegrityError(
                    "Wrong option length (II)",
                )
            optr += self._frame[optr + 1] << 3
            if optr > len(self._frame):
                raise Icmp6IntegrityError(
                    "Wrong option length (III)",
                )

    def _validate_integrity(self, *, pshdr_sum: int) -> None:
        """
        Check integrity of incoming packet prior to parsing it.
        """

        if inet_cksum(self._frame[: self._plen], pshdr_sum):
            raise Icmp6IntegrityError(
                "Wrong packet checksum.",
            )

        if not ICMP6_HEADER_LEN <= self._plen <= len(self):
            raise Icmp6IntegrityError(
                "Wrong packet length (I)",
            )

        match self._frame[0]:
            case Icmp6Type.UNREACHABLE:
                if (
                    not ICMP6_MESSAGE_LEN__UNREACHABLE
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )

            case Icmp6Type.ECHO_REQUEST:
                if (
                    not ICMP6_MESSAGE_LEN__ECHO_REQUEST
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )

            case Icmp6Type.ECHO_REPLY:
                if not ICMP6_MESSAGE_LEN__ECHO_REPLY <= self._plen <= len(self):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )

            case Icmp6Type.MLD2_QUERY:
                if not ICMP6_MESSAGE_LEN__MLD2_QUERY <= self._plen <= len(self):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )
                if self._plen != (
                    ICMP6_MESSAGE_LEN__MLD2_QUERY
                    + struct.unpack("! H", self._frame[26:28])[0] * 16
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (III)",
                    )

            case Icmp6Type.ND_ROUTER_SOLICITATION:
                if (
                    not ICMP6_MESSAGE_LEN__ND_ROUTER_SOLICITATION
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )
                self._nd_option_integrity_check(
                    ICMP6_HEADER_LEN + ICMP6_MESSAGE_LEN__ND_ROUTER_SOLICITATION
                )

            case Icmp6Type.ND_ROUTER_ADVERTISEMENT:
                if (
                    not ICMP6_MESSAGE_LEN__ND_ROUTER_ADVERTISEMENT
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )
                self._nd_option_integrity_check(
                    ICMP6_MESSAGE_LEN__ND_ROUTER_ADVERTISEMENT
                )

            case Icmp6Type.ND_NEIGHBOR_SOLICITATION:
                if (
                    not ICMP6_MESSAGE_LEN__ND_NEIGHBOR_SOLICITATION
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )
                self._nd_option_integrity_check(
                    ICMP6_MESSAGE_LEN__ND_ROUTER_SOLICITATION
                )

            case Icmp6Type.ND_NEIGHBOR_ADVERTISEMENT:
                if (
                    not ICMP6_MESSAGE_LEN__ND_NEIGHBOR_ADVERTISEMENT
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )
                self._nd_option_integrity_check(
                    ICMP6_MESSAGE_LEN__ND_ROUTER_ADVERTISEMENT
                )

            case Icmp6Type.MLD2_REPORT:
                if (
                    not ICMP6_MESSAGE_LEN__MLD2_REPORT
                    <= self._plen
                    <= len(self)
                ):
                    raise Icmp6IntegrityError(
                        "Wrong packet length (II)",
                    )
                optr = ICMP6_MESSAGE_LEN__MLD2_REPORT
                for _ in range(struct.unpack("! H", self._frame[6:8])[0]):
                    if optr + ICMP6_MLD2_RECORD_LEN > self._plen:
                        raise Icmp6IntegrityError(
                            "Wrong packet length (III)",
                        )
                    optr += (
                        ICMP6_MLD2_RECORD_LEN
                        + self._frame[optr + 1]
                        + struct.unpack_from("! H", self._frame, optr + 2)[0]
                        * 16
                    )
                if optr != self._plen:
                    raise Icmp6IntegrityError(
                        "Wrong packet length (IV)",
                    )

    def _parse(self) -> None:
        """
        Parse incoming packet.
        """

        match Icmp6Type.from_frame(self._frame):
            case Icmp6Type.UNREACHABLE:
                match Icmp6UnreachableCode.from_frame(self._frame):
                    case Icmp6UnreachableCode.PORT:
                        self._message = Icmp6PortUnreachableMessageParser(
                            self._frame,
                        )

            case Icmp6Type.ECHO_REQUEST:
                self._message = Icmp6EchoRequestMessageParser(
                    self._frame,
                )

            case Icmp6Type.ECHO_REPLY:
                self._message = Icmp6EchoReplyMessageParser(
                    self._frame,
                )

            case Icmp6Type.ND_ROUTER_SOLICITATION:
                self._message = Icmp6NdRouterSolicitationMessageParser(
                    self._frame,
                )

            case Icmp6Type.ND_ROUTER_ADVERTISEMENT:
                self._message = Icmp6NdRouterAdvertisementMessageParser(
                    self._frame,
                )

            case Icmp6Type.ND_NEIGHBOR_SOLICITATION:
                self._message = Icmp6NdNeighborSolicitationMessageParser(
                    self._frame,
                )

            case Icmp6Type.ND_NEIGHBOR_ADVERTISEMENT:
                self._message = Icmp6NdNeighborAdvertisementMessageParser(
                    self._frame,
                )

            case _:
                self._message = Icmp6UnknownMessageParser(
                    self._frame,
                )

    def _validate_sanity(
        self, *, ip6__src: Ip6Address, ip6__dst: Ip6Address, ip6__hop: int
    ) -> None:
        """
        Check sanity of incoming packet after it has been parsed.
        """

        if isinstance(self._message, Icmp6UnreachableMessage):
            return

        if isinstance(self._message, Icmp6EchoRequestMessage):
            return

        if isinstance(self._message, Icmp6EchoReplyMessage):
            return

        if isinstance(self._message, Icmp6NdRouterSolicitationMessage):
            if not ip6__hop == 255:
                raise Icmp6SanityError(
                    "The 'hop' field must be '255'. (RFC 4861)",
                )
            if not (ip6__src.is_unicast or ip6__src.is_unspecified):
                raise Icmp6SanityError(
                    "The 'src' address must be unicast or unspecified. (RFC 4861)",
                )
            if not ip6__dst == Ip6Address("ff02::2"):
                raise Icmp6SanityError(
                    "The 'dst' must be all-routers. (RFC 4861)",
                )
            if ip6__src.is_unspecified and self._message.opt_slla:
                raise Icmp6SanityError(
                    "The 'nd_opt_slla' field must not be included if "
                    "the 'src' address is unspecified. (RFC 4861)",
                )

            # TODO: Enforce proper option presence.

        if isinstance(self._message, Icmp6NdRouterAdvertisementMessage):
            if not ip6__hop == 255:
                raise Icmp6SanityError(
                    "The 'hop' field must be '255'. (RFC 4861)",
                )
            if not ip6__src.is_link_local:
                raise Icmp6SanityError(
                    "The 'src' address must be link local. (RFC 4861)",
                )
            if not (ip6__dst.is_unicast or ip6__dst == Ip6Address("ff02::1")):
                raise Icmp6SanityError(
                    "The 'dst' address must be unicast or all-nodes. (RFC 4861)",
                )

            # TODO: Enforce proper option presence.

        if isinstance(self._message, Icmp6NdNeighborSolicitationMessage):
            if not ip6__hop == 255:
                raise Icmp6SanityError(
                    "The 'hop' field must be '255'. (RFC 4861)",
                )
            if not (ip6__src.is_unicast or ip6__src.is_unspecified):
                raise Icmp6SanityError(
                    "The 'src' address must be unicast or unspecified. (RFC 4861)",
                )
            if ip6__dst not in {
                self._message.target_address,
                self._message.target_address.solicited_node_multicast,
            }:
                raise Icmp6SanityError(
                    "The 'dst' address must be 'ns_target_address' address or it's "
                    "solicited-node multicast address. (RFC 4861)",
                )
            if not self._message.target_address.is_unicast:
                raise Icmp6SanityError(
                    "The 'ns_target_address' address must be unicast. (RFC 4861)",
                )
            if ip6__src.is_unspecified and self._message.opt_slla is not None:
                raise Icmp6SanityError(
                    "The 'nd_opt_slla' address must not be included if "
                    "the 'src' is unspecified. (RFC 4861)",
                )

            # TODO: Enforce proper option presence.

        if isinstance(self._message, Icmp6NdNeighborAdvertisementMessage):
            if not ip6__hop == 255:
                raise Icmp6SanityError(
                    "The 'hop' field must be '255'. (RFC 4861)",
                )
            if not ip6__src.is_unicast:
                raise Icmp6SanityError(
                    "The 'src' address must be unicast. (RFC 4861)",
                )
            if self._message.flag_s is True and not (
                ip6__dst.is_unicast or ip6__dst == Ip6Address("ff02::1")
            ):
                raise Icmp6SanityError(
                    "If 'na_flag_s' flag is set then 'dst' address must be "
                    "either unicast or all-nodes. (RFC 4861)",
                )
            if self._message.flag_s is False and not ip6__dst == Ip6Address(
                "ff02::1"
            ):
                raise Icmp6SanityError(
                    "If 'na_flag_s' flag is not set then 'dst' address must "
                    "be all-nodes address. (RFC 4861)",
                )

            # TODO: Enforce proper option presence.

        if isinstance(self._message, Icmp6Mld2ReportMessage):
            if not ip6__hop == 1:
                raise Icmp6SanityError(
                    "The 'hop' field must be '1'. (RFC 3810)",
                )


#
#  The ICMPv6 message parser classes.
#


class Icmp6PortUnreachableMessageParser(Icmp6PortUnreachableMessage):
    """
    Parser class for ICMPv6 Port Unreachable Port message.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._reserved = struct.unpack("! L", frame[4:8])[0]
        self._data = frame[8:]


class Icmp6EchoRequestMessageParser(Icmp6EchoRequestMessage):
    """
    Parser class for ICMPv4 Echo Request message.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._id = struct.unpack("! H", frame[4:6])[0]
        self._seq = struct.unpack("! H", frame[6:8])[0]
        self._data = frame[8:]


class Icmp6EchoReplyMessageParser(Icmp6EchoReplyMessage):
    """
    Parser class for ICMPv6 Echo Reply message.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._id = struct.unpack("! H", frame[4:6])[0]
        self._seq = struct.unpack("! H", frame[6:8])[0]
        self._data = frame[8:]


class Icmp6NdRouterSolicitationMessageParser(Icmp6NdRouterSolicitationMessage):
    """
    Parser class for ICMPv6 ND Router Soliciation message.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._reserved = struct.unpack("! L", frame[4:8])[0]
        self._nd_options = _scan_icmp6_nd_options(frame[8:])


class Icmp6NdRouterAdvertisementMessageParser(
    Icmp6NdRouterAdvertisementMessage
):
    """
    Message parser class for ICMPv6 ND Router Advertisement packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._hop = frame[4]
        self._flag_m = bool(frame[5] & 0b10000000)
        self._flag_o = bool(frame[5] & 0b01000000)
        self._router_lifetime = struct.unpack("! H", frame[6:8])[0]
        self._reachable_time = struct.unpack("! L", frame[8:12])[0]
        self._retrans_timer = struct.unpack("! L", frame[12:16])[0]
        self._nd_options = _scan_icmp6_nd_options(frame[16:])


class Icmp6NdNeighborSolicitationMessageParser(
    Icmp6NdNeighborSolicitationMessage
):
    """
    Message parser class for ICMPv6 ND Neighbor Soliciation packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._reserved = struct.unpack("! L", frame[4:8])[0]
        self._target_address = Ip6Address(frame[8:24])
        self._nd_options = _scan_icmp6_nd_options(frame[24:])


class Icmp6NdNeighborAdvertisementMessageParser(
    Icmp6NdNeighborAdvertisementMessage
):
    """
    Message parser class for ICMPv6 ND Neighbor Advertisement packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._flag_r = bool(frame[4] & 0b10000000)
        self._flag_s = bool(frame[4] & 0b01000000)
        self._flag_o = bool(frame[4] & 0b00100000)
        self._reserved = (
            struct.unpack("! L", frame[4:8])[0]
            & 0b00011111_11111111_11111111_11111111
        )
        self._target_address = Ip6Address(frame[8:24])
        self._nd_options = _scan_icmp6_nd_options(frame[24:])


class Icmp6Mld2ReportMessageParser(Icmp6Mld2ReportMessage):
    """
    Message parser class for ICMPv6 MLD2 Report packet.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._reserved = struct.unpack("! H", frame[4:6])[0]
        self._nor = struct.unpack("! H", frame[6:8])[0]
        self._records = []

        raw_records = frame[8:]
        for _ in range(self._nor):
            record = Icmp6Mld2AddressRecordParser(raw_records)
            raw_records = raw_records[len(record) :]
            self._records.append(record)


class Icmp6UnknownMessageParser(Icmp6UnknownMessage):
    """
    Parser class for ICMPv6 unknown message.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Create the message object.
        """

        self._type = Icmp6Type.from_frame(frame)
        self._code = Icmp6Code.from_frame(frame)


#
#   The ICMPv6 Neighbor Discovery option classes.
#


class Icmp6NdOptSllaParser(Icmp6NdOptSlla):
    """
    ICMPv6 ND option parser - Source Link Layer Address (1).
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Option constructor.
        """

        self._code = Icmp6NdOptCode.from_frame(frame)
        self._len = frame[1] << 3
        self._slla = MacAddress(frame[2:8])


class Icmp6NdOptTllaParser(Icmp6NdOptTlla):
    """
    ICMPv6 ND option parser - Target Link Layer Address (2).
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Option constructor.
        """

        self._code = Icmp6NdOptCode.from_frame(frame)
        self._len = frame[1] << 3
        self._tlla = MacAddress(frame[2:8])


class Icmp6NdOptPiParser(Icmp6NdOptPi):
    """
    ICMPv6 ND option - Prefix Information (3).
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Option constructor.
        """

        self._code = Icmp6NdOptCode.from_frame(frame)
        self._len = frame[1] << 3
        self._flag_l = bool(frame[3] & 0b10000000)
        self._flag_a = bool(frame[3] & 0b01000000)
        self._flag_r = bool(frame[3] & 0b00100000)
        self._valid_lifetime = struct.unpack_from("!L", frame, 4)[0]
        self._preferred_lifetime = struct.unpack_from("!L", frame, 8)[0]
        self._prefix = Ip6Network(
            (Ip6Address(frame[16:32]), Ip6Mask(f"/{frame[2]}"))
        )


class Icmp6NdOptUnkParser(Icmp6NdOptUnk):
    """
    ICMPv6 ND option - Unknown.
    """

    def __init__(self, /, frame: bytes) -> None:
        """
        Option constructor.
        """

        self._code = Icmp6NdOptCode.from_frame(frame)
        self._len = frame[1] << 3
        self._data = frame[2 : self._len]


#
#   The ICMPv6 Multicast support classes.
#


class Icmp6Mld2AddressRecordParser(Icmp6Mld2AddressRecord):
    """
    Multicast Address Record used by MLDv2 Report message - parser.
    """

    def __init__(self, raw_record: bytes) -> None:
        """
        Multicast Address Record constructor.
        """

        self._record_type = Icmp6Mld2RecordType.from_frame(raw_record)
        self._aux_data_len = raw_record[1]
        self._number_of_sources = struct.unpack("! H", raw_record[2:4])[0]
        self._multicast_address = Ip6Address(raw_record[4:20])
        self._source_addresses = [
            Ip6Address(raw_record[20 + 16 * n : 20 + 16 * (n + 1)])
            for n in range(self._number_of_sources)
        ]
        self.aux_data = raw_record[20 + 16 * self._number_of_sources :]


#
#  Helper functions.
#


def _scan_icmp6_nd_options(
    frame: bytes,
) -> list[Icmp6NdOpt]:
    """
    Create ND option list from provided frame.
    """

    optr = 0
    options: list[Icmp6NdOpt] = []

    while optr < len(frame):
        match Icmp6NdOptCode.from_frame(frame[optr:]):
            case Icmp6NdOptCode.SLLA:
                options.append(Icmp6NdOptSllaParser(frame[optr:]))
            case Icmp6NdOptCode.TLLA:
                options.append(Icmp6NdOptTllaParser(frame[optr:]))
            case Icmp6NdOptCode.PI:
                options.append(Icmp6NdOptPiParser(frame[optr:]))
            case _:
                options.append(Icmp6NdOptUnkParser(frame[optr:]))

        optr += options[-1].len

    return options
