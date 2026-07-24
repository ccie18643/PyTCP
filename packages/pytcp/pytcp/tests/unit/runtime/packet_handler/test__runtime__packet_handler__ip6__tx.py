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
This module contains unit tests for the 'Ip6TxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6__tx.py

ver 3.0.9
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import create_autospec

from net_addr import Ip6Address, Ip6IfAddr
from net_proto import Ip6Assembler, IpProto, RawAssembler
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.nd.nd__router_state import (
    Icmp6SlaacAddress,
    Icmp6TempAddress,
)
from pytcp.runtime.packet_handler.packet_handler__ip6__tx import (
    Ip6TxHandler,
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


STACK__IP6_HOST = Ip6IfAddr("2001:db8:0:1::7/64")
STACK__IP6_ADDRESS = STACK__IP6_HOST.address
STACK__IP6_MULTICAST = Ip6Address("ff02::1")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")
OFF_NET__IP6 = Ip6Address("2001:db8:ffff::99")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the TX-stat counters, the address lists, the interface MTU /
    layer, the TX ring, the SLAAC / temp-address tables, and the
    '_phtx_ethernet' / '_phtx_ip6_frag' / '_marshal_tx_async' /
    '_effective_ip6_hop_limit' seams the IPv6 TX sub-handler reaches
    through 'self._if', recording each call for assertions. A
    purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which autospec
    walks) cannot evaluate at runtime.
    """

    def __init__(
        self,
        *,
        ip6_support: bool = True,
        interface_layer: InterfaceLayer = InterfaceLayer.L2,
        interface_mtu: int = 1500,
        ip6_hosts: list[Ip6IfAddr] | None = None,
    ) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self._ip6_support = ip6_support
        self._interface_layer = interface_layer
        self._interface_mtu = interface_mtu
        self._interface_name: str | None = None
        self._ip6_ifaddr = ip6_hosts if ip6_hosts is not None else [STACK__IP6_HOST]
        self._ip6_multicast = [STACK__IP6_MULTICAST]
        self._icmp6_slaac_addresses: list[Icmp6SlaacAddress] = []
        self._icmp6_temp_addresses: list[Icmp6TempAddress] = []

        # Per-interface TX ring — injected by the L3-enqueue test that
        # exercises '__send_out_packet'; None for the L2 tests whose
        # '_phtx_ethernet' override records calls instead.
        self._tx_ring = None

        self.ethernet_tx_calls: list[dict[str, object]] = []
        self.frag_tx_calls: list[Ip6Assembler] = []
        self.ethernet_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING
        self.frag_tx_status: TxStatus = TxStatus.PASSED__IP6__TO_TX_RING
        self.marshal_tx_async_calls = 0

    def _marshal_tx_async(
        self,
        run: Callable[[], TxStatus],
        /,
        *,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        # 'send_ip6_packet' fire-and-forget marshals '_phtx_ip6' through
        # '_marshal_tx_async'; with no TX worker under test, run inline.
        self.marshal_tx_async_calls += 1
        run()

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        return [host.address for host in self._ip6_ifaddr]

    def _phtx_ethernet(self, **kwargs: object) -> TxStatus:
        self.ethernet_tx_calls.append(kwargs)
        return self.ethernet_tx_status

    def _phtx_ip6_frag(self, *, ip6_packet_tx: Ip6Assembler) -> TxStatus:
        self.frag_tx_calls.append(ip6_packet_tx)
        return self.frag_tx_status

    # Stub the cross-mixin helper added with the §13b parity
    # work. This unit test exercises only the gating /
    # validation / fragmentation paths; the RA-aware effective
    # default is covered by the integration tests in
    # 'pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__ra_parameter_consumers.py'.
    def _effective_ip6_hop_limit(self) -> int:
        return 64


def _make_ip6_tx(
    *,
    ip6_support: bool = True,
    interface_layer: InterfaceLayer = InterfaceLayer.L2,
    interface_mtu: int = 1500,
    ip6_hosts: list[Ip6IfAddr] | None = None,
) -> tuple[Ip6TxHandler, _StubInterface]:
    """
    Build an 'Ip6TxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface(
        ip6_support=ip6_support,
        interface_layer=interface_layer,
        interface_mtu=interface_mtu,
        ip6_hosts=ip6_hosts,
    )
    return (
        Ip6TxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)),
        interface,
    )


class TestPacketHandlerIp6TxGating(TestCase):
    """
    The IPv6-support-flag gating tests.
    """

    def test__stack__packet_handler__ip6__tx__disabled_drops(self) -> None:
        """
        Ensure the handler drops when IPv6 support is disabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx(ip6_support=False)
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP6__NO_PROTOCOL_SUPPORT)
        self.assertEqual(iface._packet_stats_tx.ip6__no_proto_support__drop, 1)


class TestPacketHandlerIp6TxValidation(TestCase):
    """
    The source- and destination-address validation branches.
    """

    @override
    def setUp(self) -> None:
        self._handler, self._if = _make_ip6_tx()

    def test__stack__packet_handler__ip6__tx__src_not_owned_drops(self) -> None:
        """
        Ensure an src not owned by the stack drops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._handler._phtx_ip6(
            ip6__src=OFF_NET__IP6,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP6__SRC_NOT_OWNED)
        self.assertEqual(self._if._packet_stats_tx.ip6__src_not_owned__drop, 1)

    def test__stack__packet_handler__ip6__tx__src_multicast_replaced(self) -> None:
        """
        Ensure a multicast src is replaced with the stack unicast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip6(
            ip6__src=STACK__IP6_MULTICAST,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip6__src_multicast__replace, 1)

    def test__stack__packet_handler__ip6__tx__src_multicast_no_unicast_drops(self) -> None:
        """
        Ensure a multicast src with no stack unicast drops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx(ip6_hosts=[])
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_MULTICAST,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP6__SRC_MULTICAST)
        self.assertEqual(iface._packet_stats_tx.ip6__src_multicast__drop, 1)

    def test__stack__packet_handler__ip6__tx__src_unspec_local_dst_replaced(self) -> None:
        """
        Ensure an unspecified src with an in-network dst is replaced.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip6__src_network_unspecified__replace_local, 1)

    def test__stack__packet_handler__ip6__tx__src_unspec_external_gateway_replaced(self) -> None:
        """
        Ensure an unspecified src with an external unicast dst picks
        the first gateway-having host.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=OFF_NET__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(self._if._packet_stats_tx.ip6__src_network_unspecified__replace_external, 1)

    def test__stack__packet_handler__ip6__tx__src_unspec_multicast_dst_replaced(self) -> None:
        """
        Ensure an unspecified src to a multicast destination is filled in
        via RFC 6724 source selection — a DHCPv6 SOLICIT to ff02::1:2 takes
        the link-local source — rather than being dropped as malformed.

        Reference: RFC 6724 §4 (source selection applies to multicast destinations).
        """

        handler, iface = _make_ip6_tx(ip6_hosts=[Ip6IfAddr("fe80::7/64")])

        status = handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=Ip6Address("ff02::1:2"),
            ip6__payload=RawAssembler(),
        )

        self.assertNotEqual(
            status,
            TxStatus.DROPPED__IP6__SRC_UNSPECIFIED,
            msg="A multicast destination with an unspecified source must not be dropped.",
        )
        self.assertEqual(
            iface._packet_stats_tx.ip6__src_unspecified__replace_multicast,
            1,
            msg="The link-local source must be selected for a link-local multicast destination.",
        )

    def test__stack__packet_handler__ip6__tx__src_unspec_no_replacement_drops(self) -> None:
        """
        Ensure an unspecified src with no replacement candidate drops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx(ip6_hosts=[])
        status = handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP6__SRC_UNSPECIFIED)
        self.assertEqual(iface._packet_stats_tx.ip6__src_unspecified__drop, 1)

    def test__stack__packet_handler__ip6__tx__dst_unspecified_drops(self) -> None:
        """
        Ensure an unspecified dst drops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        status = self._handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=Ip6Address(),
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPPED__IP6__DST_UNSPECIFIED)
        self.assertEqual(self._if._packet_stats_tx.ip6__dst_unspecified__drop, 1)


class TestPacketHandlerIp6TxSend(TestCase):
    """
    The successful-send tests.
    """

    def test__stack__packet_handler__ip6__tx__l2_forwards_to_ethernet(self) -> None:
        """
        Ensure an L2-layer stack forwards within-MTU packets to the
        Ethernet TX layer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx(interface_layer=InterfaceLayer.L2)
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(iface._packet_stats_tx.ip6__mtu_ok__send, 1)
        self.assertEqual(len(iface.ethernet_tx_calls), 1)

    def test__stack__packet_handler__ip6__tx__l3_enqueues_on_tx_ring(self) -> None:
        """
        Ensure an L3-layer stack enqueues IPv6 packets directly on the
        TX ring.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx(interface_layer=InterfaceLayer.L3)
        mock_tx_ring = create_autospec(TxRing, spec_set=True)
        iface._tx_ring = mock_tx_ring
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.PASSED__IP6__TO_TX_RING)
        self.assertEqual(iface._packet_stats_tx.ip6__mtu_ok__send, 1)
        mock_tx_ring.enqueue.assert_called_once()

    def test__stack__packet_handler__ip6__tx__over_mtu_delegates_to_frag(self) -> None:
        """
        Ensure a packet exceeding the interface MTU is delegated to
        '_phtx_ip6_frag' and its TxStatus returned.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx(interface_mtu=200)
        payload = RawAssembler(raw__payload=b"\x00" * 400)
        iface.frag_tx_status = TxStatus.PASSED__IP6__TO_TX_RING
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=payload,
        )

        self.assertEqual(status, TxStatus.PASSED__IP6__TO_TX_RING)
        self.assertEqual(iface._packet_stats_tx.ip6__mtu_exceed__frag, 1)
        self.assertEqual(len(iface.frag_tx_calls), 1)
        self.assertIsInstance(iface.frag_tx_calls[0], Ip6Assembler)


class TestPacketHandlerIp6TxSendIp6PacketHelper(TestCase):
    """
    The public 'send_ip6_packet' interface used by RAW sockets.
    """

    def test__stack__packet_handler__ip6__tx__send_ip6_packet_builds_raw_assembler(self) -> None:
        """
        Ensure 'send_ip6_packet' wraps the caller's bytes payload in a
        RawAssembler tagged with the supplied next header.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx()
        handler.send_ip6_packet(
            ip6__local_address=STACK__IP6_ADDRESS,
            ip6__remote_address=HOST_A__IP6,
            ip6__next=IpProto.UDP,
            ip6__payload=b"\x00" * 8,
        )

        self.assertEqual(len(iface.ethernet_tx_calls), 1)
        payload = iface.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, Ip6Assembler)
        self.assertEqual(payload.next, IpProto.UDP)

    def test__stack__packet_handler__ip6__tx__send_ip6_packet_routes_through_marshal_tx_async(self) -> None:
        """
        Ensure 'send_ip6_packet' hands the '_phtx_ip6' pipeline to the
        interface's TX worker fire-and-forget via '_marshal_tx_async'
        (Phase 4b) rather than calling '_phtx_ip6' directly on the
        caller's thread or blocking for a result.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler, iface = _make_ip6_tx()
        handler.send_ip6_packet(
            ip6__local_address=STACK__IP6_ADDRESS,
            ip6__remote_address=HOST_A__IP6,
            ip6__next=IpProto.UDP,
            ip6__payload=b"\x00" * 8,
        )

        self.assertEqual(
            iface.marshal_tx_async_calls,
            1,
            msg="send_ip6_packet must route the TX through _marshal_tx_async exactly once.",
        )
