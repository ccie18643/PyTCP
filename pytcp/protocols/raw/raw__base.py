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
This module contains the Raw protocol base class.

pytcp/protocols/raw/raw__base.py

ver 3.0.2
"""


from __future__ import annotations

from typing import override

from pytcp.lib.proto import Proto
from pytcp.protocols.enums import IpProto


class Raw(Proto):
    """
    The Raw protocol base.
    """

    _payload: bytes
    _ip_proto: IpProto

    @override
    def __len__(self) -> int:
        """
        Get the Raw packet length.
        """

        return len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the Raw packet log string.
        """

        return f"Raw, len {len(self)}"

    @override
    def __repr__(self) -> str:
        """
        Get the Raw packet representation string.
        """

        return f"{self.__class__.__name__}(raw__payload={self._payload!r})"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the Raw packet as bytes.
        """

        return self._payload

    @property
    def payload(self) -> bytes:
        """
        Get the Raw packet '_payload' attribute.
        """

        return self._payload

    @property
    def ip_proto(self) -> IpProto:
        """
        Get the IP protocol number.
        """

        return self._ip_proto
