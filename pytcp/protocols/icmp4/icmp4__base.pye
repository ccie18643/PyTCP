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
Module contains the ICMPv4 protocol base class.

pytcp/protocols/icmp4/icmp4__base.py

ver 3.0.1
"""


from __future__ import annotations

from typing import override

from pytcp.lib.inet_cksum import inet_cksum
from pytcp.lib.proto import Proto
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Message


class Icmp4(Proto):
    """
    The ICMPv4 protocol base.
    """

    _message: Icmp4Message

    @override
    def __len__(self) -> int:
        """
        Get the ICMPv4 packet length.
        """

        return len(self._message)

    @override
    def __str__(self) -> str:
        """
        Get the ICMPv4 packet log string.
        """

        return str(self._message)

    @override
    def __repr__(self) -> str:
        """
        Get the ICMPv4 packet representation string.
        """

        return f"{self._message!r}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the ICMPv4 packet as bytes.
        """

        _bytes = bytearray(bytes(self._message))
        _bytes[2:4] = inet_cksum(_bytes).to_bytes(2)

        return bytes(_bytes)

    @property
    def message(self) -> Icmp4Message:
        """
        Get the ICMPv4 packet 'message' attribute.
        """

        return self._message
