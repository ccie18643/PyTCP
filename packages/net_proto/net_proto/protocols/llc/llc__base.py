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
This module contains the LLC protocol base class.

net_proto/protocols/llc/llc__base.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer
from net_proto.lib.proto import Proto
from net_proto.protocols.llc.llc__header import LlcHeader, LlcHeaderProperties


class Llc(Proto, LlcHeaderProperties):
    """
    The LLC protocol base.
    """

    _header: LlcHeader
    _payload: Buffer

    @override
    def __len__(self) -> int:
        """
        Get the LLC packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the LLC packet log string.
        """

        return (
            f"LLC dsap {self._header.dsap} ssap {self._header.ssap}"
            f" ctrl {self._header.control}, len {len(self._payload)}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the LLC packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the LLC packet as a memoryview.
        """

        buffer = bytearray(self._header) + bytearray(self._payload)
        return memoryview(buffer)

    @property
    def header(self) -> LlcHeader:
        """
        Get the LLC packet '_header' attribute.
        """

        return self._header

    @property
    def payload(self) -> Buffer:
        """
        Get the LLC packet '_payload' attribute.
        """

        return self._payload
