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
This module contains the IPv4 packet parser.

net_proto/protocols/ip4/ip4__parser.py

ver 3.0.10
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.ip4.ip4__base import Ip4
from net_proto.protocols.ip4.ip4__errors import (
    Ip4IntegrityError,
    Ip4SanityError,
)
from net_proto.protocols.ip4.ip4__header import (
    IP4__HEADER__LEN,
    IP4__POINTER__FLAGS_OFFSET,
    IP4__POINTER__SRC,
    IP4__POINTER__TTL,
    Ip4Header,
)
from net_proto.protocols.ip4.options.ip4__options import Ip4Options


class Ip4Parser(Ip4[Buffer], ProtoParser):
    """
    The IPv4 packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the IPv4 packet parser.
        """

        self._frame = packet_rx.frame
        # Whether this packet was looped internally by the loopback
        # interface — used by '_validate_sanity' to skip the
        # loopback-source martian check (a wire-ingress-only policy).
        self._from_loopback = packet_rx.from_loopback

        self._validate_integrity()
        self._parse()
        # Install on 'packet_rx' BEFORE the sanity stage so the
        # IPv4 RX handler can read 'packet_rx.ip4' from inside its
        # 'except Ip4SanityError' catch and emit an ICMPv4
        # Parameter Problem with the offending field's pointer
        # (RFC 1122 §3.2.2.5 / RFC 792). Frame advancement stays
        # AFTER sanity so the catch path leaves 'packet_rx.frame'
        # pointing at the original IPv4 packet bytes.
        packet_rx.ip = packet_rx.ip4 = self
        self._validate_sanity()

        packet_rx.frame = self._payload

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the IPv4 packet before parsing it.
        """

        # RFC 791 §3.1 — the fixed portion of the IPv4 header is 20
        # octets; anything shorter cannot be parsed at all.
        if len(self._frame) < IP4__HEADER__LEN:
            raise Ip4IntegrityError(
                "The condition 'IP4__HEADER__LEN <= len(self._frame)' must be met. "
                f"Got: {IP4__HEADER__LEN=}, {len(self._frame)=}",
            )

        # RFC 1122 §3.2.1.1 — "A datagram whose version number is
        # not 4 MUST be silently discarded."
        if (value := self._frame[0] >> 4) != 4:
            raise Ip4IntegrityError(
                f"The 'ver' field must be 4. Got: {value!r}",
            )

        hlen = (self._frame[0] & 0b00001111) << 2
        plen = int.from_bytes(self._frame[2:4])

        # RFC 791 §3.1 — IHL (header length, in 32-bit words) is the
        # length of the internet header and "the minimum value for a
        # correct header is 5" (≥ 20 octets); Total Length is the
        # length of the datagram (header + data). The received frame
        # MUST be at least 'plen' octets and 'hlen <= plen' is a
        # structural invariant.
        if not (IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)):
            raise Ip4IntegrityError(
                "The condition 'IP4__HEADER__LEN <= hlen <= plen <= len(self._frame)' "
                f"must be met. Got: {IP4__HEADER__LEN=}, {hlen=}, {plen=}, {len(self._frame)=}",
            )

        # RFC 1122 §3.2.1.2 — "A host MUST verify the IP header
        # checksum on every received datagram and silently discard
        # every datagram that has a bad checksum." Algorithm: RFC
        # 1071 one's-complement sum over the IHL-bounded header
        # (RFC 791 §3.1 'Header Checksum').
        if inet_cksum(self._frame[:hlen]):
            raise Ip4IntegrityError(
                "The packet checksum must be valid.",
            )

        # RFC 791 §3.1 'Options' — Case 2 (TLV) option-type / length
        # encoding: each option-length octet is the length of the
        # option (≥ 2) and the cumulative option region MUST fit
        # within the IHL-bounded header.
        Ip4Options.validate_integrity(frame=self._frame, hlen=hlen)

    @override
    def _parse(self) -> None:
        """
        Parse the IPv4 packet.
        """

        self._header = Ip4Header.from_buffer(self._frame)

        self._options = Ip4Options.from_buffer(self._frame[len(self._header) : self._header.hlen])

        self._payload = self._frame[self._header.hlen : self._header.plen]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the IPv4 packet after parsing it. Each
        violation carries the canonical RFC 792 'pointer' value (byte
        offset of the offending field) so the packet handler can emit
        an ICMPv4 Parameter Problem with the correct pointer.
        """

        # RFC 791 §3.1 'Time to Live' — "If this field contains the
        # value zero, then the datagram must be destroyed." RFC 1122
        # §3.2.1.7 reflects this on the host side.
        if (ttl := self.ttl) == 0:
            raise Ip4SanityError(
                f"The 'ttl' field must be greater than 0. Got: {ttl!r}",
                pointer=IP4__POINTER__TTL,
            )

        # --- 'src' field rejections, in ascending address-space order ---

        # RFC 1122 §3.2.1.3(a) — "{0, <Host-number>} ... MUST NOT
        # be used as a source address". 0.0.0.0 (is_unspecified)
        # remains permitted for the DHCP-style initial-assignment
        # carve-out the same clause grants; only the 0.0.0.1 –
        # 0.255.255.255 range (is_invalid) is rejected here.
        if (src := self.src).is_invalid:
            raise Ip4SanityError(
                f"The 'src' field must not be in the 'this network' range (0.0.0.0/8). Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        # RFC 1122 §3.2.1.3(g) — "{127, <any>} Internal host
        # loopback address. Addresses of this form MUST NOT appear
        # outside a host." This is a wire-ingress policy: a packet
        # looped internally by the loopback interface legitimately
        # carries a loopback source, so the check is skipped when the
        # RX consumer marked the packet 'from_loopback'.
        if not self._from_loopback and (src := self.src).is_loopback:
            raise Ip4SanityError(
                f"The 'src' field must not be a loopback address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        # RFC 1122 §3.2.1.3 (Class D / multicast not a host source) —
        # a multicast address (224.0.0.0/4) identifies a group, not a
        # single sender.
        if (src := self.src).is_multicast:
            raise Ip4SanityError(
                f"The 'src' field must not be a multicast address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        # RFC 1122 §3.2.1.3 / RFC 6890 — 240.0.0.0/4 is reserved
        # (Class E) and never assignable to a host; cannot appear
        # as a source.
        if (src := self.src).is_reserved:
            raise Ip4SanityError(
                f"The 'src' field must not be a reserved address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        # RFC 1122 §3.2.1.3(c) — "{-1, -1} Limited broadcast ... It
        # MUST NOT be used as a source address."
        if (src := self.src).is_limited_broadcast:
            raise Ip4SanityError(
                f"The 'src' field must not be a limited broadcast address. Got: {src!r}",
                pointer=IP4__POINTER__SRC,
            )

        # --- Flags / fragment offset consistency ---

        # RFC 791 §3.1 'Flags' — DF=1 means "Don't Fragment"; MF=1
        # means "More Fragments" (this is a non-last fragment). The
        # two are mutually exclusive by definition (a DF=1 datagram
        # was not fragmented, so cannot have MF set). RFC 1122
        # §3.2.1.4 hardens this on the host side.
        if self.flag_df and self.flag_mf:
            raise Ip4SanityError(
                "The 'flag_df' and 'flag_mf' flags must not be set simultaneously. "
                f"Got: {self.flag_df=}, {self.flag_mf=}",
                pointer=IP4__POINTER__FLAGS_OFFSET,
            )

        # RFC 791 §3.1 — DF=1 implies the datagram is not
        # fragmented; a non-zero Fragment Offset contradicts that.
        if self.flag_df and (offset := self.offset) != 0:
            raise Ip4SanityError(
                f"The 'offset' field must be 0 when the 'flag_df' flag is set. Got: {offset!r}",
                pointer=IP4__POINTER__FLAGS_OFFSET,
            )

    @property
    def header_bytes(self) -> Buffer:
        """
        Get the IPv4 packet header bytes.
        """

        return self._frame[: len(self._header)]

    @property
    def payload_bytes(self) -> Buffer:
        """
        Get the IPv4 packet payload bytes.
        """

        return self._payload

    @property
    def packet_bytes(self) -> Buffer:
        """
        Get the whole IPv4 packet bytes.
        """

        return self._frame[: len(self._header) + len(self._options) + len(self._payload)]
