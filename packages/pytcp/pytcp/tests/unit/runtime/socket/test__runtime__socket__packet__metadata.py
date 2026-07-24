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
This module contains tests for the AF_PACKET RX metadata value type
('PacketMetadata') — the captured frame plus its 'sockaddr_ll' that
the Ethernet RX tap queues onto a packet socket.

pytcp/tests/unit/runtime/socket/test__runtime__socket__packet__metadata.py

ver 3.0.9
"""

from unittest import TestCase

from net_addr import MacAddress
from pytcp.runtime.socket import ETH_P_ARP, PacketType
from pytcp.runtime.socket.packet__metadata import PacketMetadata
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl


class TestPacketMetadata(TestCase):
    """
    The AF_PACKET 'PacketMetadata' RX value type tests.
    """

    def test__packet_metadata__stores_frame_and_sockaddr(self) -> None:
        """
        Ensure 'PacketMetadata' preserves the captured frame bytes and
        the originating 'sockaddr_ll' verbatim through its read surface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06rest"
        sockaddr = SockAddrLl(
            ifindex=1,
            ethertype=ETH_P_ARP,
            pkttype=PacketType.PACKET_BROADCAST,
            mac=MacAddress("02:00:00:00:00:91"),
        )

        md = PacketMetadata(frame=frame, sockaddr_ll=sockaddr)

        self.assertEqual(md.frame, frame, msg="PacketMetadata must preserve the captured frame bytes.")
        self.assertEqual(md.sockaddr_ll, sockaddr, msg="PacketMetadata must preserve the originating sockaddr_ll.")
