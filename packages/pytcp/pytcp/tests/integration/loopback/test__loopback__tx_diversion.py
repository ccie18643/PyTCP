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
Integration tests for the IP-TX-layer loopback diversion.

pytcp/tests/integration/loopback/test__loopback__tx_diversion.py

ver 3.0.9
"""

from typing import override
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address
from net_proto import RawAssembler
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    NetworkTestCase,
)

_IP4_LOOPBACK = Ip4Address("127.0.0.1")
_IP6_LOOPBACK = Ip6Address("::1")


class TestLoopbackTxDiversion(NetworkTestCase):
    """
    The IP-TX loopback-diversion tests — a locally-destined packet is
    enqueued on the loopback ring instead of emitted on the wire.
    """

    @override
    def setUp(self) -> None:
        """
        Bring up the boot interface and register a loopback interface.
        """

        super().setUp()
        self._lo = self._register_loopback()

    def test__loopback__ipv4_loopback_dst_diverts(self) -> None:
        """
        Ensure an IPv4 packet destined to 127.0.0.1 is diverted onto the
        loopback ring — it returns PASSED__IP4__LOOPBACK, emits no wire
        frame, and enqueues exactly one packet on the loopback ring.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._lo._phtx_ip4(
            ip4__src=_IP4_LOOPBACK,
            ip4__dst=_IP4_LOOPBACK,
            ip4__payload=RawAssembler(raw__payload=b"loopback"),
        )

        self.assertIs(status, TxStatus.PASSED__IP4__LOOPBACK, msg="Loopback dst must return PASSED__IP4__LOOPBACK.")
        self.assertEqual(self._frames_tx, [], msg="A diverted loopback packet must not reach the wire.")
        self.assertEqual(self._lo._lo_ring.qsize, 1, msg="Exactly one packet must be enqueued on the loopback ring.")

    def test__loopback__ipv4_own_ip_diverts_without_arp(self) -> None:
        """
        Ensure an IPv4 packet destined to the host's own routable address
        is diverted onto the loopback ring without an ARP resolution — the
        old own-IP path resolved the stack's own address and dropped on an
        ARP cache miss.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # The boot interface's ARP mock raises on any unexpected lookup;
        # the own-IP address is not in its table, so a surviving ARP call
        # would fail the test — proving the diversion bypasses resolution.
        status = self._packet_handler._phtx_ip4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=STACK__IP4_HOST.address,
            ip4__payload=RawAssembler(raw__payload=b"own-ip"),
        )

        self.assertIs(status, TxStatus.PASSED__IP4__LOOPBACK, msg="Own-IP dst must return PASSED__IP4__LOOPBACK.")
        self.assertEqual(self._frames_tx, [], msg="An own-IP loop must not reach the wire.")
        self.assertEqual(self._lo._lo_ring.qsize, 1, msg="Own-IP loop must enqueue one packet on the loopback ring.")
        self._arp_cache.find_entry.assert_not_called()

    def test__loopback__ipv6_loopback_dst_diverts(self) -> None:
        """
        Ensure an IPv6 packet destined to ::1 is diverted onto the
        loopback ring — it returns PASSED__IP6__LOOPBACK and emits no wire
        frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._lo._phtx_ip6(
            ip6__src=_IP6_LOOPBACK,
            ip6__dst=_IP6_LOOPBACK,
            ip6__payload=RawAssembler(raw__payload=b"loopback6"),
        )

        self.assertIs(status, TxStatus.PASSED__IP6__LOOPBACK, msg="Loopback dst must return PASSED__IP6__LOOPBACK.")
        self.assertEqual(self._frames_tx, [], msg="A diverted loopback packet must not reach the wire.")
        self.assertEqual(self._lo._lo_ring.qsize, 1, msg="Exactly one packet must be enqueued on the loopback ring.")

    def test__loopback__ipv6_own_ip_diverts_without_nd(self) -> None:
        """
        Ensure an IPv6 packet destined to the host's own global address is
        diverted onto the loopback ring without a Neighbor Discovery
        resolution.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=STACK__IP6_HOST.address,
            ip6__payload=RawAssembler(raw__payload=b"own-ip6"),
        )

        self.assertIs(status, TxStatus.PASSED__IP6__LOOPBACK, msg="Own-IP dst must return PASSED__IP6__LOOPBACK.")
        self.assertEqual(self._frames_tx, [], msg="An own-IP loop must not reach the wire.")
        self.assertEqual(self._lo._lo_ring.qsize, 1, msg="Own-IP loop must enqueue one packet on the loopback ring.")
        self._nd_cache.find_entry.assert_not_called()

    def test__loopback__diversion_does_not_nest_into_rx(self) -> None:
        """
        Ensure the TX diversion only enqueues — it does not synchronously
        deliver into the RX path — so a full exchange never nests an
        entire handshake in one call stack.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(self._lo, "_deliver_loopback") as deliver:
            self._lo._phtx_ip4(
                ip4__src=_IP4_LOOPBACK,
                ip4__dst=_IP4_LOOPBACK,
                ip4__payload=RawAssembler(raw__payload=b"no-nest"),
            )

        deliver.assert_not_called()
        self.assertEqual(self._lo._lo_ring.qsize, 1, msg="The diverted packet must sit on the ring, undelivered.")

    def test__loopback__enqueued_frame_is_the_assembled_packet(self) -> None:
        """
        Ensure the frame enqueued on the loopback ring is the assembled
        IPv4 packet — a bare IP datagram (no L2 framing) carrying the
        loopback destination.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._lo._phtx_ip4(
            ip4__src=_IP4_LOOPBACK,
            ip4__dst=_IP4_LOOPBACK,
            ip4__payload=RawAssembler(raw__payload=b"payload"),
        )

        packet_rx = self._lo._lo_ring.dequeue()
        assert packet_rx is not None  # narrowed; one packet was enqueued
        self.assertEqual(packet_rx.frame[0] >> 4, 4, msg="The enqueued frame must be an IPv4 packet.")
        self.assertEqual(
            bytes(packet_rx.frame[16:20]),
            bytes(_IP4_LOOPBACK),
            msg="The enqueued IPv4 packet must carry the loopback destination address.",
        )
