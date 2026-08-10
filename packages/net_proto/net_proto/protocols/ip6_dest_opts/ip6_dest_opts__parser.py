################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the IPv6 Destination Options packet parser class.

net_proto/protocols/ip6_dest_opts/ip6_dest_opts__parser.py

ver 3.0.10
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__base import Ip6DestOpts
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import Ip6DestOptsIntegrityError
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__header import (
    IP6_DEST_OPTS__HEADER__LEN,
    Ip6DestOptsHeader,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__options import Ip6DestOptsOptions


class Ip6DestOptsParser(Ip6DestOpts, ProtoParser):
    """
    The IPv6 Destination Options packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx, *, ip6_dst_is_multicast: bool = False) -> None:
        """
        Initialize the IPv6 Dest Opts packet parser.

        'ip6_dst_is_multicast' is the parent IPv6 header's
        destination-is-multicast bit, threaded in by the RX
        chain-walker so the RFC 8200 §4.2 action-11 option dispatch
        (discard + ICMP only when the destination is NOT multicast)
        can be evaluated correctly. Defaults to False (the
        conservative unicast assumption) for standalone construction.
        """

        self._frame = packet_rx.frame
        self._ip6__dst_is_multicast = ip6_dst_is_multicast

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.ip6_dest_opts = self
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv6 Dest Opts packet before parsing it.
        """

        # RFC 8200 §4.6 — the Destination Options header is at
        # minimum 2 octets (Next Header / Hdr Ext Len); the
        # options trailer is gated separately below.
        if len(self._frame) < IP6_DEST_OPTS__HEADER__LEN:
            raise Ip6DestOptsIntegrityError(
                "The condition 'IP6_DEST_OPTS__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP6_DEST_OPTS__HEADER__LEN=}, {len(self._frame)=}",
            )

        # RFC 8200 §4.6 — Hdr Ext Len in 8-octet units NOT
        # including the first 8 octets; total wire length =
        # (Hdr Ext Len + 1) * 8. Frame MUST hold every octet the
        # header claims.
        hdr_ext_len = self._frame[1]
        total_hbh_len = (hdr_ext_len + 1) * 8

        if total_hbh_len > len(self._frame):
            raise Ip6DestOptsIntegrityError(
                "The condition '(hdr_ext_len + 1) * 8 <= len(self._frame)' must be met. "
                f"Got: {hdr_ext_len=}, {total_hbh_len=}, {len(self._frame)=}",
            )

        # RFC 8200 §4.2 (TLV format) — walk the per-option Opt
        # Data Len bytes and confirm every option fits inside the
        # declared DestOpts region.
        Ip6DestOptsOptions.validate_integrity(
            buffer=self._frame[IP6_DEST_OPTS__HEADER__LEN:total_hbh_len],
        )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 Dest Opts packet.
        """

        self._header = Ip6DestOptsHeader.from_buffer(self._frame)
        total_hbh_len = (self._header.hdr_ext_len + 1) * 8
        self._options = Ip6DestOptsOptions.from_buffer(
            self._frame[IP6_DEST_OPTS__HEADER__LEN:total_hbh_len],
        )
        self._payload = self._frame[total_hbh_len:]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv6 Dest Opts packet after parsing it.

        Applies RFC 8200 §4.2 action-on-unrecognized to every option
        in the parsed block. The chain-walker dispatch in Phase 8
        catches any 'Ip6DestOptsSanityError' raised here, consults its
        'pointer' / 'multicast_only' fields, and emits ICMPv6
        Parameter Problem code 2 (or silent discard) accordingly.

        The destination-is-multicast bit is threaded in via the
        constructor ('ip6_dst_is_multicast', supplied by the RX
        chain-walker) so the §4.2 action-11 rule — discard + ICMP
        only when the destination is NOT multicast — is evaluated
        with the real destination scope.
        """

        total_hbh_len = (self._header.hdr_ext_len + 1) * 8
        Ip6DestOptsOptions.validate_sanity(
            buffer=self._frame[IP6_DEST_OPTS__HEADER__LEN:total_hbh_len],
            ip6_dst_is_multicast=self._ip6__dst_is_multicast,
        )

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv6 Dest Opts packet header bytes (full header including
        the trailing options block).
        """

        return self._frame[: (self._header.hdr_ext_len + 1) * 8]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv6 Dest Opts packet payload bytes.
        """

        return self._payload
