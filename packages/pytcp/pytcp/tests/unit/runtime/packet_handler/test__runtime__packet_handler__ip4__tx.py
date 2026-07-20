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
This module contains unit tests for the 'Ip4TxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip4__tx.py

ver 3.0.8
"""

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import create_autospec

from net_addr import Ip4Address, Ip4IfAddr
from net_proto import Ip4Assembler, Ip4FragAssembler, IpProto, RawAssembler, UdpAssembler
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__ip4__tx import (
    Ip4TxHandler,
)
from pytcp.runtime.tx_ring import TxRing

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


STACK__IP4_HOST = Ip4IfAddr("10.0.1.7/24")
STACK__IP4_ADDRESS = STACK__IP4_HOST.address
STACK__IP4_MULTICAST = Ip4Address("224.0.0.1")
STACK__IP4_NET_BROADCAST = STACK__IP4_HOST.network.broadcast
STACK__IP4_LIMITED_BROADCAST = Ip4Address("255.255.255.255")
HOST_A__IP4 = Ip4Address("10.0.1.91")
OFF_NET__IP4 = Ip4Address("192.168.99.99")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the TX-stat counters, the address lists / fragment-id lock,
    the interface MTU / layer, the TX ring, and the '_phtx_ethernet' +
    '_marshal_tx_async' seams the IPv4 TX sub-handler reaches through
    'self._if', recording each call for assertions. A purpose-built
    double is used rather than 'create_autospec(PacketHandlerL2)' — the
    god-class still carries 'TYPE_CHECKING'-only annotations
    'inspect.signature' (which autospec walks) cannot evaluate at runtime.
    """

    def __init__(
        self,
        *,
        ip4_support: bool = True,
        interface_layer: InterfaceLayer = InterfaceLayer.L2,
        interface_mtu: int = 1500,
        ip4_hosts: list[Ip4IfAddr] | None = None,
    ) -> None:
        """
        Initialize the stub handler and record every _phtx_ethernet call.
        """

        self._packet_stats_tx = PacketStatsTx()
        self._ip4_support = ip4_support
        self._interface_layer = interface_layer
        self._interface_mtu = interface_mtu
        self._interface_name: str | None = None
        self._ip4_ifaddr = ip4_hosts if ip4_hosts is not None else [STACK__IP4_HOST]
        self._ip4_multicast = [STACK__IP4_MULTICAST]
        self._ip4_id = 0
        # Lock guarding the masked IP-id increment ('_next_ip4_id').
        # The stub doesn't run the base ctor that normally builds it.
        self._lock__ip4_id = threading.Lock()
        # Per-interface TX ring — injected by the L3-enqueue tests
        # that exercise '__send_out_packet'; None for the L2 tests
        # whose '_phtx_ethernet' override records calls instead.
        self._tx_ring = None

        self.ethernet_tx_calls: list[dict[str, object]] = []
        self.ethernet_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING
        self.marshal_tx_async_calls = 0

    def _marshal_tx_async(
        self,
        run: Callable[[], TxStatus],
        /,
        *,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        # 'send_ip4_packet' fire-and-forget marshals '_phtx_ip4' through
        # '_marshal_tx_async'; with no TX worker under test, run inline.
        self.marshal_tx_async_calls += 1
        run()

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        return [host.address for host in self._ip4_ifaddr]

    @property
    def _ip4_broadcast(self) -> list[Ip4Address]:
        return [host.network.broadcast for host in self._ip4_ifaddr] + [STACK__IP4_LIMITED_BROADCAST]

    def _phtx_ethernet(self, **kwargs: object) -> TxStatus:
        self.ethernet_tx_calls.append(kwargs)
        return self.ethernet_tx_status


def _make_ip4_tx(
    *,
    ip4_support: bool = True,
    interface_layer: InterfaceLayer = InterfaceLayer.L2,
    interface_mtu: int = 1500,
    ip4_hosts: list[Ip4IfAddr] | None = None,
) -> tuple[Ip4TxHandler, _StubInterface]:
    """
    Build an 'Ip4TxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface(
        ip4_support=ip4_support,
        interface_layer=interface_layer,
        interface_mtu=interface_mtu,
        ip4_hosts=ip4_hosts,
    )
    return (
        Ip4TxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)),
        interface,
    )


class TestPacketHandlerIp4TxGating(TestCase):
    """
    The IPv4-support-flag gating tests.
    """

    def test__stack__packet_handler__ip4__tx__ip4_disabled_drops(self) -> None:
        """
        Ensure the handler drops when IPv4 support is disabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(ip4_support=False)
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(
            status,
            TxStatus.DROPPED__IP4__NO_PROTOCOL_SUPPORT,
            msg="IP4 TX with support disabled must return DROPPED__IP4__NO_PROTOCOL_SUPPORT.",
        )
        self.assertEqual(iface._packet_stats_tx.ip4__no_proto_support__drop, 1)


class TestPacketHandlerIp4TxSrcValidation(TestCase):
    """
    The source-address validation branches.
    """

    @override
    def setUp(self) -> None:
        self._handler, self._if = _make_ip4_tx()

    def test__stack__packet_handler__ip4__tx__src_not_owned_drops(self) -> None:
        """
        Ensure an src not owned by the stack drops with SRC_NOT_OWNED.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._handler._phtx_ip4(
            ip4__src=OFF_NET__IP4,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP4__SRC_NOT_OWNED)
        self.assertEqual(self._if._packet_stats_tx.ip4__src_not_owned__drop, 1)

    def test__stack__packet_handler__ip4__tx__src_multicast_replaced(self) -> None:
        """
        Ensure a multicast src is replaced with the stack primary unicast.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip4(
            ip4__src=STACK__IP4_MULTICAST,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip4__src_multicast__replace, 1)
        self.assertEqual(len(self._if.ethernet_tx_calls), 1)
        payload = self._if.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, Ip4Assembler)
        self.assertEqual(payload.src, STACK__IP4_ADDRESS)

    def test__stack__packet_handler__ip4__tx__src_multicast_no_unicast_drops(self) -> None:
        """
        Ensure a multicast src with no stack unicast available drops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(ip4_hosts=[])
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_MULTICAST,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP4__SRC_MULTICAST)
        self.assertEqual(iface._packet_stats_tx.ip4__src_multicast__drop, 1)

    def test__stack__packet_handler__ip4__tx__src_limited_broadcast_replaced(self) -> None:
        """
        Ensure a 255.255.255.255 src is replaced with the stack primary
        unicast.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip4(
            ip4__src=STACK__IP4_LIMITED_BROADCAST,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip4__src_limited_broadcast__replace, 1)

    def test__stack__packet_handler__ip4__tx__src_network_broadcast_replaced(self) -> None:
        """
        Ensure a network-broadcast src is replaced with the matching
        network's unicast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip4(
            ip4__src=STACK__IP4_NET_BROADCAST,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip4__src_network_broadcast__replace, 1)

    def test__stack__packet_handler__ip4__tx__src_unspec_local_dst_replaced(self) -> None:
        """
        Ensure an unspecified src with a local-network dst is replaced
        with the local-network unicast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip4(
            ip4__src=Ip4Address(),
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip4__src_network_unspecified__replace_local, 1)

    def test__stack__packet_handler__ip4__tx__src_unspec_external_uses_gateway_src(self) -> None:
        """
        Ensure an unspecified src with an external dst is replaced with
        the first stack host that has a gateway set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip4(
            ip4__src=Ip4Address(),
            ip4__dst=OFF_NET__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip4__src_network_unspecified__replace_external, 1)

    def test__stack__packet_handler__ip4__tx__src_unspec_dhcp_allowed(self) -> None:
        """
        Ensure an unspecified src is allowed for a DHCP UDP packet
        (sport=68 → dport=67) — the only valid zero-src send.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(ip4_hosts=[])
        dhcp_payload = UdpAssembler(udp__sport=68, udp__dport=67)
        status = handler._phtx_ip4(
            ip4__src=Ip4Address(),
            ip4__dst=Ip4Address("255.255.255.255"),
            ip4__payload=dhcp_payload,
        )

        # The 'ip4__src_unspecified__send' counter is incremented only
        # on this specific branch, guarding against regressions that
        # would widen the DHCP exception.
        self.assertEqual(iface._packet_stats_tx.ip4__src_unspecified__send, 1)
        self.assertNotEqual(
            status,
            TxStatus.DROPPED__IP4__SRC_UNSPECIFIED,
            msg="DHCP UDP 68->67 must bypass the unspecified-src drop.",
        )

    def test__stack__packet_handler__ip4__tx__src_unspec_nothing_matches_drops(self) -> None:
        """
        Ensure an unspecified src with no replacement candidate drops
        with SRC_UNSPECIFIED.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(ip4_hosts=[])
        status = handler._phtx_ip4(
            ip4__src=Ip4Address(),
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP4__SRC_UNSPECIFIED)
        self.assertEqual(iface._packet_stats_tx.ip4__src_unspecified__drop, 1)


class TestPacketHandlerIp4TxDstValidation(TestCase):
    """
    The destination-address validation branches.
    """

    def test__stack__packet_handler__ip4__tx__dst_unspecified_drops(self) -> None:
        """
        Ensure an unspecified dst drops with DST_UNSPECIFIED.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx()
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=Ip4Address(),
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP4__DST_UNSPECIFIED)
        self.assertEqual(iface._packet_stats_tx.ip4__dst_unspecified__drop, 1)


class TestPacketHandlerIp4TxSend(TestCase):
    """
    The successful-send path tests.
    """

    def test__stack__packet_handler__ip4__tx__l2_forwards_to_ethernet(self) -> None:
        """
        Ensure an L2-layer stack forwards the assembled IPv4 packet to
        the Ethernet TX layer when within MTU.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(interface_layer=InterfaceLayer.L2)
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(iface._packet_stats_tx.ip4__mtu_ok__send, 1)
        self.assertEqual(len(iface.ethernet_tx_calls), 1)

    def test__stack__packet_handler__ip4__tx__l3_enqueues_on_tx_ring(self) -> None:
        """
        Ensure an L3-layer stack enqueues the IPv4 packet directly on
        the TX ring, bypassing the Ethernet layer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(interface_layer=InterfaceLayer.L3)
        mock_tx_ring = create_autospec(TxRing, spec_set=True)
        iface._tx_ring = mock_tx_ring
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            ip4__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.PASSED__IP4__TO_TX_RING)
        self.assertEqual(iface._packet_stats_tx.ip4__mtu_ok__send, 1)
        mock_tx_ring.enqueue.assert_called_once()
        self.assertEqual(iface.ethernet_tx_calls, [])


class TestPacketHandlerIp4TxFragmentation(TestCase):
    """
    The MTU-exceeded fragmentation tests.
    """

    def test__stack__packet_handler__ip4__tx__over_mtu_fragments(self) -> None:
        """
        Ensure a packet exceeding the MTU is split into multiple
        fragments, each passed through the Ethernet TX layer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(interface_layer=InterfaceLayer.L2, interface_mtu=200)
        # Build a raw payload large enough to require fragmentation.
        payload = RawAssembler(raw__payload=b"\x00" * 400)
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            ip4__payload=payload,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Fragmented send with every fragment passing must return PASSED__ETHERNET__TO_TX_RING.",
        )
        self.assertEqual(
            iface._packet_stats_tx.ip4__mtu_exceed__frag,
            1,
            msg="ip4__mtu_exceed__frag must be incremented once per outbound packet.",
        )
        self.assertGreaterEqual(
            iface._packet_stats_tx.ip4__mtu_exceed__frag__send,
            2,
            msg="At least two fragments must be sent when the packet exceeds the MTU.",
        )
        # Every ethernet payload must be an Ip4FragAssembler.
        for call in iface.ethernet_tx_calls:
            self.assertIsInstance(call["ethernet__payload"], Ip4FragAssembler)

    def test__stack__packet_handler__ip4__tx__over_mtu_l3_enqueues_fragments(self) -> None:
        """
        Ensure the L3 fragmentation path enqueues each fragment on the
        TX ring and reports PASSED__IP4__TO_TX_RING when every fragment
        is enqueued successfully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx(interface_layer=InterfaceLayer.L3, interface_mtu=200)
        payload = RawAssembler(raw__payload=b"\x00" * 400)
        mock_tx_ring = create_autospec(TxRing, spec_set=True)
        iface._tx_ring = mock_tx_ring
        status = handler._phtx_ip4(
            ip4__src=STACK__IP4_ADDRESS,
            ip4__dst=HOST_A__IP4,
            ip4__payload=payload,
        )

        self.assertEqual(
            status,
            TxStatus.PASSED__IP4__TO_TX_RING,
            msg="L3 fragmented send with every fragment enqueued must return PASSED__IP4__TO_TX_RING.",
        )
        self.assertGreaterEqual(
            mock_tx_ring.enqueue.call_count,
            2,
            msg="At least two fragments must be enqueued on the TX ring when fragmentation fires.",
        )


class TestPacketHandlerIp4TxSendIp4PacketHelper(TestCase):
    """
    The public 'send_ip4_packet' interface used by RAW sockets.
    """

    def test__stack__packet_handler__ip4__tx__send_ip4_packet_builds_raw_assembler(self) -> None:
        """
        Ensure 'send_ip4_packet' wraps the caller's bytes payload in a
        RawAssembler tagged with the supplied proto and forwards it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx()
        handler.send_ip4_packet(
            ip4__local_address=STACK__IP4_ADDRESS,
            ip4__remote_address=HOST_A__IP4,
            ip4__proto=IpProto.UDP,
            ip4__payload=b"\x00" * 8,
        )

        self.assertEqual(len(iface.ethernet_tx_calls), 1)
        payload = iface.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, Ip4Assembler)
        self.assertEqual(payload.proto, IpProto.UDP)

    def test__stack__packet_handler__ip4__tx__send_ip4_packet_routes_through_marshal_tx_async(self) -> None:
        """
        Ensure 'send_ip4_packet' hands the '_phtx_ip4' pipeline to the
        interface's TX worker fire-and-forget via '_marshal_tx_async'
        (Phase 4b) rather than calling '_phtx_ip4' directly on the
        caller's thread or blocking for a result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip4_tx()
        handler.send_ip4_packet(
            ip4__local_address=STACK__IP4_ADDRESS,
            ip4__remote_address=HOST_A__IP4,
            ip4__proto=IpProto.UDP,
            ip4__payload=b"\x00" * 8,
        )

        self.assertEqual(
            iface.marshal_tx_async_calls,
            1,
            msg="send_ip4_packet must route the TX through _marshal_tx_async exactly once.",
        )
