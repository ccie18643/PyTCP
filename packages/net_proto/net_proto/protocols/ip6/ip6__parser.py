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
This module contains the IPv6 packet parser.

net_proto/protocols/ip6/ip6__parser.py

ver 3.0.8
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip6.ip6__base import Ip6
from net_proto.protocols.ip6.ip6__errors import (
    Ip6IntegrityError,
    Ip6SanityError,
)
from net_proto.protocols.ip6.ip6__header import (
    IP6__HEADER__LEN,
    IP6__POINTER__HOP,
    IP6__POINTER__SRC,
    Ip6Header,
)


class Ip6Parser(Ip6[Buffer], ProtoParser):
    """
    The IPv6 packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv6 packet parser.
        """

        self._frame = packet_rx.frame
        # Whether this packet was looped internally by the loopback
        # interface — used by '_validate_sanity' to skip the
        # loopback-source martian check (a wire-ingress-only policy).
        self._from_loopback = packet_rx.from_loopback

        self._validate_integrity()
        self._parse()
        # Install on 'packet_rx' BEFORE the sanity stage so the
        # IPv6 RX handler can read 'packet_rx.ip6' from inside its
        # 'except Ip6SanityError' catch and emit an ICMPv6
        # Parameter Problem with the offending field's pointer
        # (RFC 1122 §3.2.2.5 / RFC 4443 §3.4). Frame advancement
        # stays AFTER sanity so the catch path leaves
        # 'packet_rx.frame' pointing at the original IPv6 packet
        # bytes.
        packet_rx.ip = packet_rx.ip6 = self
        self._validate_sanity()
        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv6 packet before parsing it.
        """

        # RFC 8200 §3 — the IPv6 base header is exactly 40 octets;
        # anything shorter cannot be parsed.
        if len(self._frame) < IP6__HEADER__LEN:
            raise Ip6IntegrityError(
                "The condition 'IP6__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP6__HEADER__LEN=}, {len(self._frame)=}",
            )

        # RFC 8200 §3 — Version field is the top 4 bits and MUST be
        # 6. RFC 8504 §4.1 requires hosts to silently discard
        # frames whose Version is not 6.
        if (value := self._frame[0] >> 4) != 6:
            raise Ip6IntegrityError(
                f"The 'ver' field must be 6. Got: {value!r}",
            )

        # RFC 8200 §3 — Payload Length is the length in octets of
        # the IPv6 payload (the portion of the packet following the
        # 40-byte fixed header); the on-wire frame MUST match.
        # RFC 2675 §3 jumbograms (Payload Length = 0 with a Jumbo
        # Payload HBH option) are out of scope here — the HBH
        # walker handles them.
        if (dlen := int.from_bytes(self._frame[4:6])) != len(self._frame) - IP6__HEADER__LEN:
            raise Ip6IntegrityError(
                "The condition 'dlen == len(self._frame) - IP6__HEADER__LEN' must be met. "
                f"Got: {dlen=}, {len(self._frame)=}, {IP6__HEADER__LEN=}",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the IPv6 packet.
        """

        self._header = Ip6Header.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) : len(self._header) + self._header.dlen]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv6 packet after parsing it. Each
        violation carries the canonical RFC 4443 'pointer' value
        (byte offset of the offending field) so the packet handler
        can emit an ICMPv6 Parameter Problem with the correct pointer.
        """

        # RFC 8200 §3 'Hop Limit' — "When forwarding the packet,
        # Hop Limit is decremented by 1; the packet is discarded
        # if Hop Limit is decremented to zero." A frame received
        # with hop=0 has either already been forwarded as far as
        # any spec-compliant router would allow or was crafted
        # locally; in either case it is invalid for delivery.
        if (hop := self.hop) == 0:
            raise Ip6SanityError(
                f"The 'hop' field must not be 0. Got: {hop!r}",
                pointer=IP6__POINTER__HOP,
            )

        # RFC 4291 §2.5.3 — "The loopback address must not be
        # used as the source address in IPv6 packets that are
        # sent outside of a single node." Direct analog of the
        # IPv4 §3.2.1.3(g) loopback ban; Linux enforces the same
        # rule. The unspecified address (::) is deliberately not
        # rejected here so DAD-style NS messages (RFC 4861 §4.3)
        # can reach the ICMPv6 RX path. The check is skipped when the
        # RX consumer marked the packet 'from_loopback' — a packet
        # looped internally by the loopback interface legitimately
        # carries a ::1 source.
        if not self._from_loopback and (src := self.src).is_loopback:
            raise Ip6SanityError(
                f"The 'src' field must not be a loopback address. Got: {src!r}",
                pointer=IP6__POINTER__SRC,
            )

        # RFC 4291 §2.7 — "Multicast addresses must not be used
        # as source addresses in IPv6 packets or appear in any
        # Routing header." Multicast identifies a group, not a
        # single sender.
        if (src := self.src).is_multicast:
            raise Ip6SanityError(
                f"The 'src' field must not be a multicast address. Got: {src!r}",
                pointer=IP6__POINTER__SRC,
            )

    def reanchor_payload(self, frame: Buffer, /) -> None:
        """
        Re-anchor the IPv6 payload onto the post-extension-header frame.
        """

        # RX-path mutation: after the IPv6 RX handler walks the
        # extension-header chain it re-anchors the payload onto the
        # post-chain frame so the downstream transport parser sees the
        # correct 'payload_len' / 'dlen' for ITS header.
        self._payload = frame

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv6 packet header bytes.
        """

        return self._frame[: len(self._header)]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv6 packet payload bytes.
        """

        return self._payload

    @property
    def packet_bytes(self) -> Buffer:
        """
        Get the IPv6 packet bytes.
        """

        return self._frame[: len(self._header) + self._header.dlen]
