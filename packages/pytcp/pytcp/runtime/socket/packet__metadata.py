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
This module contains the interface class for the Ethernet RX tap ->
Packet Socket communication ('PacketMetadata') — the captured frame
plus the 'sockaddr_ll' describing how it arrived.

pytcp/runtime/socket/packet__metadata.py

ver 3.0.10
"""

from dataclasses import dataclass

from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


@dataclass(frozen=True, kw_only=True, slots=True)
class PacketMetadata:
    """
    The AF_PACKET socket metadata taken from a received Ethernet frame.
    'frame' is the complete link-layer frame (a detached copy, never an
    alias of the RX-ring buffer); 'sockaddr_ll' carries the arrival
    interface, ethertype, packet type, and source MAC.
    """

    frame: bytes
    sockaddr_ll: SockAddrLl
