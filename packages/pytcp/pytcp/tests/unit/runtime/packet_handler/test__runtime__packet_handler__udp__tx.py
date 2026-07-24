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
This module contains unit tests for the 'UdpTxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__udp__tx.py

ver 3.0.9
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import UdpAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__udp__tx import UdpTxHandler

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")
STACK__IP6_ADDRESS = Ip6Address("2001:db8::7")
HOST_A__IP6 = Ip6Address("2001:db8::91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the TX-stat counters, the async TX marshal seam, and the
    IP TX entry points ('_phtx_ip4' / '_phtx_ip6') the UDP TX
    sub-handler reaches through 'self._if', recording each call for
    assertions. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self.ip4_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_calls: list[dict[str, object]] = []
        self.marshal_tx_async_calls = 0

    def _marshal_tx_async(
        self,
        run: Callable[[], TxStatus],
        /,
        *,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        # 'send_udp_packet' fire-and-forget marshals '_phtx_udp' through
        # '_marshal_tx_async'; with no TX worker under test, run the
        # callable inline so the routing still reaches '_phtx_ip4' /
        # '_phtx_ip6' synchronously. Fire 'on_complete' in a 'finally'
        # to mirror the real SO_SNDBUF release path.
        self.marshal_tx_async_calls += 1
        try:
            run()
        finally:
            if on_complete is not None:
                on_complete()

    def _phtx_ip4(self, **kwargs: object) -> TxStatus:
        self.ip4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _make_udp_tx() -> tuple[UdpTxHandler, _StubInterface]:
    """
    Build a 'UdpTxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface()
    return UdpTxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)), interface


class TestPacketHandlerUdpTxRouting(TestCase):
    """
    The version-routing tests for 'PacketHandlerUdpTx._phtx_udp'.
    """

    def test__stack__packet_handler__udp__tx__ip4_routes_to_phtx_ip4(self) -> None:
        """
        Ensure a UDP datagram with IPv4 src/dst is forwarded to '_phtx_ip4'.

        Reference: RFC 768 (UDP TX).
        """

        handler, iface = _make_udp_tx()
        status = handler._phtx_udp(
            ip__src=STACK__IP4_ADDRESS,
            ip__dst=HOST_A__IP4,
            udp__sport=12345,
            udp__dport=54321,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(iface.ip4_tx_calls), 1)
        self.assertEqual(iface.ip6_tx_calls, [])
        self.assertEqual(iface._packet_stats_tx.udp__send, 1)
        self.assertEqual(iface._packet_stats_tx.udp__pre_assemble, 1)
        self.assertIsInstance(iface.ip4_tx_calls[0]["ip4__payload"], UdpAssembler)

    def test__stack__packet_handler__udp__tx__ip6_routes_to_phtx_ip6(self) -> None:
        """
        Ensure a UDP datagram with IPv6 src/dst is forwarded to '_phtx_ip6'.

        Reference: RFC 768 (UDP TX).
        """

        handler, iface = _make_udp_tx()
        status = handler._phtx_udp(
            ip__src=STACK__IP6_ADDRESS,
            ip__dst=HOST_A__IP6,
            udp__sport=12345,
            udp__dport=54321,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(iface.ip6_tx_calls), 1)
        self.assertEqual(iface.ip4_tx_calls, [])
        self.assertEqual(iface._packet_stats_tx.udp__send, 1)

    def test__stack__packet_handler__udp__tx__mixed_ip_versions_raises(self) -> None:
        """
        Ensure a mismatched IPv4 src / IPv6 dst raises ValueError.

        Reference: RFC 768 (UDP TX).
        """

        handler, iface = _make_udp_tx()
        with self.assertRaises(ValueError):
            handler._phtx_udp(
                ip__src=STACK__IP4_ADDRESS,
                ip__dst=HOST_A__IP6,
                udp__sport=12345,
                udp__dport=54321,
            )


class TestPacketHandlerUdpTxSendHelper(TestCase):
    """
    The public 'send_udp_packet' helper tests.
    """

    def test__stack__packet_handler__udp__tx__send_udp_packet_forwards(self) -> None:
        """
        Ensure 'send_udp_packet' forwards its arguments verbatim to
        '_phtx_udp'.

        Reference: RFC 768 (UDP TX).
        """

        handler, iface = _make_udp_tx()
        handler.send_udp_packet(
            ip__local_address=STACK__IP4_ADDRESS,
            ip__remote_address=HOST_A__IP4,
            udp__local_port=12345,
            udp__remote_port=54321,
            udp__payload=b"hello",
        )

        self.assertEqual(iface._packet_stats_tx.udp__send, 1)
        self.assertEqual(len(iface.ip4_tx_calls), 1)
        payload = iface.ip4_tx_calls[0]["ip4__payload"]
        assert isinstance(payload, UdpAssembler)
        self.assertEqual(payload.sport, 12345)
        self.assertEqual(payload.dport, 54321)

    def test__stack__packet_handler__udp__tx__send_udp_packet_routes_through_marshal_tx_async(self) -> None:
        """
        Ensure 'send_udp_packet' hands the '_phtx_udp' pipeline to the
        interface's TX worker fire-and-forget via '_marshal_tx_async'
        (Phase 4b) rather than calling '_phtx_udp' directly on the
        caller's thread or blocking for a result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_udp_tx()
        handler.send_udp_packet(
            ip__local_address=STACK__IP4_ADDRESS,
            ip__remote_address=HOST_A__IP4,
            udp__local_port=12345,
            udp__remote_port=54321,
            udp__payload=b"hello",
        )

        self.assertEqual(
            iface.marshal_tx_async_calls,
            1,
            msg="send_udp_packet must route the TX through _marshal_tx_async exactly once.",
        )
