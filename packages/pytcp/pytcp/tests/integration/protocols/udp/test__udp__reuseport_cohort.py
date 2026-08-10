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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains integration tests for the SO_REUSEPORT cohort
demux on the inbound UDP path: several unconnected sockets bound to
the identical (ip, port) form a cohort, and inbound datagrams
round-robin across them (one datagram delivered to one socket). The
round-robin selection lives transparently in 'SocketTable.get'; this
file pins the end-to-end behaviour through the real RX handler.

pytcp/tests/integration/protocols/udp/test__udp__reuseport_cohort.py

ver 3.0.10
"""

from net_addr import Ip4Address
from net_proto import EthernetAssembler, Ip4Assembler, UdpAssembler
from pytcp import stack
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.udp_testcase import UdpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 9000


def _build_udp4(*, sport: int, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP frame from HOST_A to the stack's
    listen (ip, port), with the given source port and payload.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=Ip4Assembler(
                ip4__src=HOST_A__IP4_ADDRESS,
                ip4__dst=STACK__IP,
                ip4__payload=UdpAssembler(
                    udp__sport=sport,
                    udp__dport=LISTEN__PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


class TestUdpReusePortCohort(UdpTestCase):
    """
    Integration tests for the SO_REUSEPORT UDP socket-cohort demux.
    """

    def _make_cohort(self, *, size: int) -> list[UdpSocket]:
        """
        Build 'size' unconnected SO_REUSEPORT UDP sockets, all bound
        to the identical (STACK__IP, LISTEN__PORT) and registered into
        the shared cohort via 'stack.sockets.register'.
        """

        sockets: list[UdpSocket] = []
        for _ in range(size):
            sock = UdpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM)
            sock._so_reuseport = True
            sock._local_ip_address = STACK__IP
            sock._local_port = LISTEN__PORT
            stack.sockets.register(sock)
            sockets.append(sock)
        return sockets

    def test__reuseport__datagrams_round_robin_one_per_socket(self) -> None:
        """
        Ensure four inbound datagrams to a four-member SO_REUSEPORT
        cohort each deliver to a distinct socket — round-robin
        distribution — so every socket receives exactly one datagram.

        Reference: socket(7) SO_REUSEPORT (load-balanced demux).
        """

        sockets = self._make_cohort(size=4)

        for index in range(4):
            self._drive_udp_rx(frame=_build_udp4(sport=40000 + index, payload=bytes([index])))

        for index, sock in enumerate(sockets):
            self.assertEqual(
                len(sock._packet_rx_md),
                1,
                msg=(
                    f"Socket {index} must receive exactly one datagram — "
                    "the cohort demux must spread four datagrams one-per-socket."
                ),
            )

    def test__reuseport__fifth_datagram_wraps_to_first_socket(self) -> None:
        """
        Ensure a fifth datagram into a four-member cohort wraps the
        round-robin cursor back to the first socket, which then holds
        two datagrams while the others hold one.

        Reference: socket(7) SO_REUSEPORT (load-balanced demux).
        """

        sockets = self._make_cohort(size=4)

        for index in range(5):
            self._drive_udp_rx(frame=_build_udp4(sport=40000 + index, payload=bytes([index])))

        self.assertEqual(
            [len(sock._packet_rx_md) for sock in sockets],
            [2, 1, 1, 1],
            msg=(
                "The fifth datagram must wrap to the first socket, giving it "
                "two queued datagrams and the rest one each."
            ),
        )
