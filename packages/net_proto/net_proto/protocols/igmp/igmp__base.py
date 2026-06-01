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
This module contains the IGMP protocol base class.

net_proto/protocols/igmp/igmp__base.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.proto import Proto
from net_proto.protocols.igmp.message.igmp__message import IgmpMessage


class Igmp(Proto):
    """
    The IGMP protocol base.
    """

    _message: IgmpMessage

    @override
    def __len__(self) -> int:
        """
        Get the IGMP packet length.
        """

        return len(self._message)

    @override
    def __str__(self) -> str:
        """
        Get the IGMP packet log string.
        """

        return str(self._message)

    @override
    def __repr__(self) -> str:
        """
        Get the IGMP packet representation string.
        """

        return f"{self._message!r}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IGMP packet as a memoryview, injecting the checksum
        computed over the whole message.
        """

        buffer = memoryview(self._message)
        buffer[2:4] = inet_cksum(buffer).to_bytes(2)

        return buffer

    @property
    def message(self) -> IgmpMessage:
        """
        Get the IGMP packet '_message' attribute.
        """

        return self._message
