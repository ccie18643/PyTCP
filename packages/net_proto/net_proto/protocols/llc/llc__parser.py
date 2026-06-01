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
This module contains the IEEE 802.2 LLC U-frame packet
parser.

net_proto/protocols/llc/llc__parser.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.buffer import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.llc.llc__base import Llc
from net_proto.protocols.llc.llc__errors import LlcIntegrityError
from net_proto.protocols.llc.llc__header import LLC__HEADER__LEN, LlcHeader


class LlcParser(Llc, ProtoParser):
    """
    The IEEE 802.2 LLC U-frame parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the LLC packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.llc = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the LLC packet before parsing.
        """

        if len(self._frame) < LLC__HEADER__LEN:
            raise LlcIntegrityError(
                f"The minimum packet length must be {LLC__HEADER__LEN} bytes. " f"Got: {len(self._frame)} bytes."
            )

        # PyTCP supports only the 1-byte-Control U-frame
        # form. Detect non-U-frame Control values via the
        # low two bits; if either is 0 the frame is an I-
        # or S-frame (Type 2 connection-oriented LLC) which
        # PyTCP does not handle.
        if (self._frame[2] & 0b11) != 0b11:
            raise LlcIntegrityError(
                "The 'control' field's low two bits must be 0b11 (U-frame). "
                f"Got: control=0x{self._frame[2]:02x} (low2=0b{self._frame[2] & 0b11:02b})."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the LLC packet.
        """

        self._header = LlcHeader.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) :]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the LLC packet after parsing.
        """

        # No sanity checks are currently implemented for
        # the LLC packet parser — every DSAP / SSAP value
        # the parser will see has a legitimate use, even
        # the Global SAP (0xFF) which the Novell-raw-802.3
        # convention uses as a marker.
