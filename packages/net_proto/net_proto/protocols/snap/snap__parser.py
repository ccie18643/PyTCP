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
This module contains the SNAP packet parser.

net_proto/protocols/snap/snap__parser.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.snap.snap__base import Snap
from net_proto.protocols.snap.snap__errors import SnapIntegrityError
from net_proto.protocols.snap.snap__header import SNAP__HEADER__LEN, SnapHeader


class SnapParser(Snap, ProtoParser):
    """
    The SNAP packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the SNAP packet parser.
        """

        self._frame = packet_rx.frame

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.snap = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the SNAP packet before parsing.
        """

        if len(self._frame) < SNAP__HEADER__LEN:
            raise SnapIntegrityError(
                f"The minimum packet length must be {SNAP__HEADER__LEN} bytes. " f"Got: {len(self._frame)} bytes."
            )

    @override
    def _parse(self) -> None:
        """
        Parse the SNAP packet.
        """

        self._header = SnapHeader.from_buffer(self._frame)
        self._payload = self._frame[len(self._header) :]

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the SNAP packet after parsing.
        """

        # No sanity checks are currently implemented for the
        # SNAP packet parser — every OUI / PID combination
        # is logically valid; the higher-level dispatcher
        # (PacketHandlerEthernet8023Rx) is responsible for
        # deciding what to do with each one.
