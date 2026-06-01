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
This module contains the UDP packet assembler.

net_proto/protocols/udp/udp__assembler.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.lib.tracker import Tracker
from net_proto.protocols.udp.udp__base import Udp
from net_proto.protocols.udp.udp__header import UDP__HEADER__LEN, UdpHeader


class UdpAssembler(Udp, ProtoAssembler):
    """
    The UDP packet assembler.
    """

    _payload: Buffer

    def __init__(
        self,
        *,
        udp__sport: int = 0,
        udp__dport: int = 0,
        udp__payload: Buffer = bytes(),
        udp__no_cksum: bool = False,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the UDP packet assembler. 'udp__no_cksum'
        opts the assembled packet into the RFC 6935 §5
        alternative-mode zero-cksum surface: the assembler
        emits the literal value 0x0000 in the checksum slot,
        skipping the computation. The IPv6 receiver gate
        (RFC 8200 §8.1) requires the destination port to be
        opted in via 'UDP_NO_CHECK6_RX' for the datagram to
        be accepted. Default False matches the RFC 768 / RFC
        8200 default mode.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = udp__payload
        self._udp__no_cksum = udp__no_cksum

        self._header = UdpHeader(
            sport=udp__sport,
            dport=udp__dport,
            plen=UDP__HEADER__LEN + len(self._payload),
            cksum=0,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the UDP packet into list of buffers.
        """

        header = bytearray(self._header)
        if self._udp__no_cksum:
            # RFC 6935 §5 alternative mode: emit the literal
            # value 0x0000 — sender opts the datagram out of
            # the standard checksum coverage. The receiver
            # accepts iff the destination port is opted in
            # via 'UDP_NO_CHECK6_RX'.
            header[6:8] = b"\x00\x00"
        else:
            # RFC 768: a computed checksum of zero is
            # transmitted as all-ones so the wire value
            # 0x0000 remains unambiguously the "no checksum
            # generated" sentinel.
            cksum = inet_cksum(header, self._payload, init=self.pshdr_sum)
            header[6:8] = (cksum or 0xFFFF).to_bytes(2)

        buffers.append(header)
        buffers.append(self._payload)
