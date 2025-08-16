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
This module contains interface class for the IP Parser -> Raw Socket communication.

pytcp/socket/raw__metadata.py

ver 3.0.3
"""


from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pytcp.socket.socket import AddressFamily, SocketType
from pytcp.socket.socket_id import SocketId

if TYPE_CHECKING:
    from net_addr import Ip4Address, Ip6Address, IpVersion
    from pytcp.lib.tracker import Tracker
    from pytcp.protocols.enums import IpProto


@dataclass(frozen=True, kw_only=True)
class RawMetadata:
    """
    Store the Raw metadata taken from the received packet.
    """

    ip__ver: IpVersion
    ip__local_address: Ip6Address | Ip4Address
    ip__remote_address: Ip6Address | Ip4Address
    ip__proto: IpProto

    raw__data: bytes = bytes()

    tracker: Tracker | None = None

    @property
    def socket_ids(self) -> list[SocketId]:
        """
        Get list of the listening socket IDs that match the metadata.
        """

        return [
            SocketId(
                address_family=AddressFamily.from_ver(self.ip__ver),
                socket_type=SocketType.RAW,
                local_address=self.ip__local_address,
                local_port=int(self.ip__proto),
                remote_address=self.ip__remote_address,
                remote_port=0,
            ),
        ]
