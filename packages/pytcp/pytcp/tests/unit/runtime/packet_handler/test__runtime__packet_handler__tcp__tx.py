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
This module contains unit tests for the 'TcpTxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__tcp__tx.py

ver 3.0.10
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import TcpAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__tcp__tx import TcpTxHandler

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

    Carries the TX-stat counters, the TX marshal seam, and the IP TX
    entry points ('_phtx_ip4' / '_phtx_ip6') the TCP TX sub-handler
    reaches through 'self._if', recording each call for assertions. A
    purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self.ip4_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_calls: list[dict[str, object]] = []
        self.marshal_tx_calls = 0

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # 'send_tcp_packet' marshals '_phtx_tcp' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        self.marshal_tx_calls += 1
        return run()

    def _phtx_ip4(self, **kwargs: object) -> TxStatus:
        self.ip4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _make_tcp_tx() -> tuple[TcpTxHandler, _StubInterface]:
    """
    Build a 'TcpTxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface()
    return TcpTxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)), interface


class TestPacketHandlerTcpTxRouting(TestCase):
    """
    The version-routing tests for 'PacketHandlerTcpTx._phtx_tcp'.
    """

    def test__stack__packet_handler__tcp__tx__ip4_routes_to_phtx_ip4(self) -> None:
        """
        Ensure a TCP segment with IPv4 src/dst is forwarded to '_phtx_ip4'.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        status = handler._phtx_tcp(
            ip__src=STACK__IP4_ADDRESS,
            ip__dst=HOST_A__IP4,
            tcp__sport=12345,
            tcp__dport=80,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(iface.ip4_tx_calls), 1)
        self.assertEqual(iface.ip6_tx_calls, [])
        self.assertEqual(iface._packet_stats_tx.tcp__send, 1)
        self.assertEqual(iface._packet_stats_tx.tcp__pre_assemble, 1)
        self.assertIsInstance(iface.ip4_tx_calls[0]["ip4__payload"], TcpAssembler)

    def test__stack__packet_handler__tcp__tx__ip6_routes_to_phtx_ip6(self) -> None:
        """
        Ensure a TCP segment with IPv6 src/dst is forwarded to '_phtx_ip6'.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        status = handler._phtx_tcp(
            ip__src=STACK__IP6_ADDRESS,
            ip__dst=HOST_A__IP6,
            tcp__sport=12345,
            tcp__dport=80,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(iface.ip6_tx_calls), 1)
        self.assertEqual(iface.ip4_tx_calls, [])
        self.assertEqual(iface._packet_stats_tx.tcp__send, 1)

    def test__stack__packet_handler__tcp__tx__mixed_ip_versions_raises(self) -> None:
        """
        Ensure a mismatched IPv4 src with IPv6 dst raises ValueError
        rather than silently picking a layer.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        with self.assertRaises(ValueError):
            handler._phtx_tcp(
                ip__src=STACK__IP4_ADDRESS,
                ip__dst=HOST_A__IP6,
                tcp__sport=12345,
                tcp__dport=80,
            )


class TestPacketHandlerTcpTxFlags(TestCase):
    """
    The per-flag counter tests.
    """

    def test__stack__packet_handler__tcp__tx__flag_counters_increment(self) -> None:
        """
        Ensure each TCP flag increments its own statistic counter.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        handler._phtx_tcp(
            ip__src=STACK__IP4_ADDRESS,
            ip__dst=HOST_A__IP4,
            tcp__sport=12345,
            tcp__dport=80,
            tcp__flag_syn=True,
            tcp__flag_ack=True,
            tcp__flag_psh=True,
            tcp__flag_rst=True,
            tcp__flag_fin=True,
            tcp__flag_urg=True,
            tcp__flag_ns=True,
            tcp__flag_cwr=True,
            tcp__flag_ece=True,
        )

        stats = iface._packet_stats_tx
        self.assertEqual(stats.tcp__flag_syn, 1)
        self.assertEqual(stats.tcp__flag_ack, 1)
        self.assertEqual(stats.tcp__flag_psh, 1)
        self.assertEqual(stats.tcp__flag_rst, 1)
        self.assertEqual(stats.tcp__flag_fin, 1)
        self.assertEqual(stats.tcp__flag_urg, 1)
        self.assertEqual(stats.tcp__flag_ns, 1)
        self.assertEqual(stats.tcp__flag_cwr, 1)
        self.assertEqual(stats.tcp__flag_ece, 1)


class TestPacketHandlerTcpTxOptions(TestCase):
    """
    The TCP-option-set tests.
    """

    def test__stack__packet_handler__tcp__tx__mss_option_counted(self) -> None:
        """
        Ensure passing 'tcp__mss' emits a segment with the MSS option
        and increments 'tcp__opt_mss'.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        handler._phtx_tcp(
            ip__src=STACK__IP4_ADDRESS,
            ip__dst=HOST_A__IP4,
            tcp__sport=12345,
            tcp__dport=80,
            tcp__mss=1460,
        )

        self.assertEqual(iface._packet_stats_tx.tcp__opt_mss, 1)

    def test__stack__packet_handler__tcp__tx__wscale_option_counted(self) -> None:
        """
        Ensure passing 'tcp__wscale' emits a segment with NOP+WSCALE
        and increments both 'tcp__opt_nop' and 'tcp__opt_wscale'.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        handler._phtx_tcp(
            ip__src=STACK__IP4_ADDRESS,
            ip__dst=HOST_A__IP4,
            tcp__sport=12345,
            tcp__dport=80,
            tcp__wscale=7,
        )

        self.assertEqual(iface._packet_stats_tx.tcp__opt_wscale, 1)
        self.assertEqual(iface._packet_stats_tx.tcp__opt_nop, 1)


class TestPacketHandlerTcpTxSendHelper(TestCase):
    """
    The public 'send_tcp_packet' helper tests.
    """

    def test__stack__packet_handler__tcp__tx__send_tcp_packet_forwards(self) -> None:
        """
        Ensure 'send_tcp_packet' forwards its arguments to '_phtx_tcp'.

        Reference: RFC 9293 §3.1 (TCP TX segment emission).
        """

        handler, iface = _make_tcp_tx()
        status = handler.send_tcp_packet(
            ip__local_address=STACK__IP4_ADDRESS,
            ip__remote_address=HOST_A__IP4,
            tcp__local_port=12345,
            tcp__remote_port=80,
            tcp__flag_syn=True,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(iface._packet_stats_tx.tcp__flag_syn, 1)
        self.assertEqual(len(iface.ip4_tx_calls), 1)

    def test__stack__packet_handler__tcp__tx__send_tcp_packet_routes_through_marshal_tx(self) -> None:
        """
        Ensure 'send_tcp_packet' marshals the '_phtx_tcp' pipeline onto
        the interface's TX worker via '_marshal_tx' (ring-handoff
        single-writer) rather than calling '_phtx_tcp' directly on the
        caller's thread.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_tcp_tx()
        handler.send_tcp_packet(
            ip__local_address=STACK__IP4_ADDRESS,
            ip__remote_address=HOST_A__IP4,
            tcp__local_port=12345,
            tcp__remote_port=80,
            tcp__flag_syn=True,
        )

        self.assertEqual(
            iface.marshal_tx_calls,
            1,
            msg="send_tcp_packet must route the TX through _marshal_tx exactly once.",
        )
