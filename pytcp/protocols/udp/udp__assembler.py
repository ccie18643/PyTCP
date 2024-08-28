#!/usr/bin/env python3

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
Module contains the UDP packet assembler class.

pytcp/protocols/udp/udp__assembler.py

ver 3.0.1
"""


from __future__ import annotations

from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.lib.tracker import Tracker
from pytcp.protocols.udp.udp__base import Udp
from pytcp.protocols.udp.udp__header import UDP__HEADER__LEN, UdpHeader


class UdpAssembler(Udp, ProtoAssembler):
    """
    The UDP packet assembler.
    """

    _payload: bytes

    def __init__(
        self,
        *,
        udp__sport: int = 0,
        udp__dport: int = 0,
        udp__payload: bytes = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the UDP packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = udp__payload

        self._header = UdpHeader(
            sport=udp__sport,
            dport=udp__dport,
            plen=UDP__HEADER__LEN + len(self._payload),
            cksum=0,
        )
