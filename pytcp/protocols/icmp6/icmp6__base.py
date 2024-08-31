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
Module contains the ICMPv6 protccol base class.

pytcp/protocols/icmp6/icmp6__base.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto import Proto
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Message


class Icmp6(Proto):
    """
    The ICMPv6 protocol base.
    """

    _message: Icmp6Message

    pshdr_sum: int = 0

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv6 the packet length.
        """

        return len(self._message)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv6 packet log string.
        """

        return str(self._message)

    @override
    def __repr__(self) -> str:
        """
        Get the ICMPv6 packet representation string.
        """

        return f"{self._message!r}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv6 packet as bytes.
        """

        _bytes = bytearray(bytes(self._message))
        _bytes[2:4] = inet_cksum(_bytes, self.pshdr_sum).to_bytes(2)

        return bytes(_bytes)

    @property
    def message(self) -> Icmp6Message:
        """
        Get the ICMPv6 packet '_message' attribute.
        """

        return self._message
