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
This module contains the UDP packet parser.

net_proto/protocols/udp/udp__parser.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer, IpVersion
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.udp.udp__base import Udp
from net_proto.protocols.udp.udp__errors import (
    UdpIntegrityError,
    UdpSanityError,
    UdpZeroCksumIp6Error,
)
from net_proto.protocols.udp.udp__header import UDP__HEADER__LEN, UdpHeader


class UdpParser(Udp, ProtoParser):
    """
    The UDP packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx, *, accept_zero_cksum_ip6: bool = False) -> None:
        """
        Initialize the UDP packet parser.
        'accept_zero_cksum_ip6' is the RFC 6935 §5 per-port
        opt-in lever consumed by the UDP RX handler when an
        inbound IPv6 datagram with cksum=0 matches a socket
        with 'UDP_NO_CHECK6_RX' set: the handler re-parses
        with this flag True so the parser bypasses the
        RFC 8200 §8.1 default-mode integrity drop.
        """

        self._frame = packet_rx.frame
        self._ip__payload_len = packet_rx.ip.payload_len
        self._ip__pshdr_sum = packet_rx.ip.pshdr_sum
        self._ip__ver = packet_rx.ip.ver
        self._accept_zero_cksum_ip6 = accept_zero_cksum_ip6

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.udp = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the UDP packet before parsing it.
        """

        # RFC 768 "Format" — UDP header is exactly 8 octets (sport
        # + dport + length + checksum); upper bound is the IP-
        # declared payload length, which itself MUST NOT exceed
        # the received frame.
        if not (UDP__HEADER__LEN <= self._ip__payload_len <= len(self._frame)):
            raise UdpIntegrityError(
                "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
                f"len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
                f"{self._ip__payload_len=}, {len(self._frame)=}",
            )

        # RFC 768 "Fields - Length" — "Length is the length in
        # octets of this user datagram including this header and
        # the data. (This means the minimum value of the length
        # is eight.)" The wire plen MUST equal the IP-layer's
        # declared payload length (cross-check catches
        # encapsulation truncation that the bare plen check
        # would miss).
        plen = int.from_bytes(self._frame[4:6])
        if not (UDP__HEADER__LEN <= plen == self._ip__payload_len <= len(self._frame)):
            raise UdpIntegrityError(
                "The condition 'UDP__HEADER__LEN <= plen == self._ip__payload_len "
                f"<= len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
                f"{plen=}, {self._ip__payload_len=}, {len(self._frame)=}",
            )

        raw_cksum = int.from_bytes(self._frame[6:8])

        if raw_cksum == 0:
            # RFC 8200 §8.1: IPv6 receivers MUST discard
            # zero-cksum UDP packets by default. RFC 6935 §5
            # carves out an alternative-mode opt-in for tunnel
            # encapsulations; the UDP RX handler retries the
            # parse with 'accept_zero_cksum_ip6=True' when the
            # destination port matches a socket with
            # 'UDP_NO_CHECK6_RX' set.
            if self._ip__ver is IpVersion.IP6 and not self._accept_zero_cksum_ip6:
                raise UdpZeroCksumIp6Error(
                    "IPv6 UDP datagram with zero checksum on a port " "not configured for RFC 6935 zero-checksum mode.",
                )
            # RFC 768 / RFC 6935 §5: IPv4 cksum=0 means
            # "sender did not compute" (always accepted); IPv6
            # cksum=0 with the per-port opt-in skips
            # validation by design.
            return

        # RFC 768 "Fields - Checksum" — "Checksum is the 16-bit
        # one's complement of the one's complement sum of a
        # pseudo header of information from the IP header, the
        # UDP header, and the data". Algorithm: RFC 1071 one's-
        # complement sum. The pseudo-header contribution is
        # precomputed by the IP layer (RFC 2460 §8.1 for IPv6,
        # RFC 768 / RFC 791 §3 for IPv4) and passed in via
        # 'init=pshdr_sum'.
        if inet_cksum(self._frame[: self._ip__payload_len], init=self._ip__pshdr_sum):
            raise UdpIntegrityError("The packet checksum must be valid.")

    @override
    def _parse(self) -> None:
        """
        Parse the UDP packet.
        """

        self._header = UdpHeader.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) : self._header.plen]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the UDP packet after parsing it.
        """

        # RFC 768 designates the Source Port as optional with a
        # wire value of 0 meaning "source port not used"; the
        # receiver delivers such datagrams normally. No sanity
        # check on sport. The Destination Port is not optional;
        # IANA reserves port 0 as unassigned and Linux drops
        # inbound dport=0 too — keep the rejection.
        if (value := self.dport) == 0:
            raise UdpSanityError(
                f"The 'dport' field must be greater than 0. Got: {value!r}",
            )
