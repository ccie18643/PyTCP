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
This module contains unit tests for the 'Ip6RxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6__rx.py

ver 3.0.8
"""

from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import create_autospec, patch

from net_addr import Ip6Address
from net_proto import Ip6Assembler, Ip6Parser, IpProto, RawAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.dispatch import DispatchRegistry
from pytcp.runtime.packet_handler.packet_handler__ip6__rx import (
    Ip6RxHandler,
)
from pytcp.runtime.socket.raw__socket import RawSocket

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


STACK__IP6_ADDRESS = Ip6Address("2001:db8:0:1::7")
STACK__IP6_MULTICAST = Ip6Address("ff02::1")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")
OFF_NET__IP6 = Ip6Address("2001:db8:ffff::99")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the RX-stat counters, the address lists, the TX marshal
    seam, and the upper-layer / cross-protocol dispatch spies
    ('_phrx_ip6_frag' / '_phrx_icmp6' / '_phrx_udp' / '_phrx_tcp',
    '_phtx_icmp6') the IPv6 RX sub-handler reaches through 'self._if',
    recording each call for assertions. A purpose-built double is used
    rather than 'create_autospec(PacketHandlerL2)' — the god-class still
    carries 'TYPE_CHECKING'-only annotations 'inspect.signature' (which
    autospec walks) cannot evaluate at runtime.
    """

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        # Marshaled TX entry points route '_phtx_*' through '_marshal_tx';
        # with no TX worker under test, run the callable inline.
        return run()

    def __init__(self) -> None:
        """
        Initialize the stub handler with dispatch spies.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._ip6_unicast_list = [STACK__IP6_ADDRESS]
        self._ip6_multicast = [STACK__IP6_MULTICAST]

        self.dispatched: list[str] = []

        # Build the IPv6 transport dispatch registry the way the real
        # handler does, with the ICMPv6 / UDP / TCP spies registered.
        # (IP6-frag and the No-Next-Header terminator are not registry
        # handlers — the EH-chain walker reaches them directly.)
        self._ip6_proto_registry: DispatchRegistry[IpProto] = DispatchRegistry()
        self._ip6_proto_registry.register(IpProto.ICMP6, self._phrx_icmp6)
        self._ip6_proto_registry.register(IpProto.UDP, self._phrx_udp)
        self._ip6_proto_registry.register(IpProto.TCP, self._phrx_tcp)

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        return self._ip6_unicast_list

    def _accepts_local_dst_ip6(self, dst: Ip6Address, /) -> bool:
        """
        Mirror the base 'PacketHandler._accepts_local_dst_ip6' host-deliver
        membership test the refactored '_forward_or_deliver_ip6' delegates
        to.
        """

        return dst in {*self._ip6_unicast, *self._ip6_multicast}

    def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("ip6_frag")

    def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("icmp6")

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("udp")

    def _phrx_tcp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("tcp")

    def _phtx_icmp6(self, **_kwargs: object) -> TxStatus:
        """
        Stub the outbound ICMPv6 emit so the unsupported-next-header
        path's SHOULD-emit Parameter Problem response goes to a no-op.
        """

        self.dispatched.append("phtx_icmp6")
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _make_ip6_rx() -> tuple[Ip6RxHandler, _StubInterface]:
    """
    Build an 'Ip6RxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface()
    return (
        Ip6RxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)),
        interface,
    )


def _ip6_frame(
    *,
    src: Ip6Address = HOST_A__IP6,
    dst: Ip6Address = STACK__IP6_ADDRESS,
    ip_proto: IpProto = IpProto.UDP,
    payload: bytes = b"",
) -> bytes:
    """
    Build an IPv6 wire frame carrying the given proto in the next-header
    field via a 'RawAssembler' tagged with 'ip_proto'.
    """

    return bytes(
        Ip6Assembler(
            ip6__src=src,
            ip6__dst=dst,
            ip6__payload=RawAssembler(raw__payload=payload, ip_proto=ip_proto),
        )
    )


class _Ip6RxTestBase(TestCase):
    """
    Common setUp for the IPv6 RX tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the stub handler and isolate the stack sockets dict.
        """

        self._handler, self._if = _make_ip6_rx()
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()

    @override
    def tearDown(self) -> None:
        """
        Restore the stack sockets dict.
        """

        self._sockets_patch.stop()


class TestPacketHandlerIp6RxParseAndFilter(_Ip6RxTestBase):
    """
    The parse-and-filter branches of 'Ip6RxHandler._phrx_ip6'.
    """

    def test__stack__packet_handler__ip6__rx__parse_fail_drops(self) -> None:
        """
        Ensure a truncated IPv6 frame is counted in
        'ip6__failed_parse__drop'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(b"\x60\x00\x00"))

        self.assertEqual(
            self._if._packet_stats_rx.ip6__failed_parse__drop,
            1,
            msg="Truncated IPv6 frame must be counted in ip6__failed_parse__drop.",
        )

    def test__stack__packet_handler__ip6__rx__unknown_dst_drops(self) -> None:
        """
        Ensure a packet to an unowned IPv6 is dropped.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(dst=OFF_NET__IP6)))

        self.assertEqual(
            self._if._packet_stats_rx.ip6__dst_unknown__drop,
            1,
            msg="Unknown IPv6 destination must be counted in ip6__dst_unknown__drop.",
        )

    def test__stack__packet_handler__ip6__rx__unicast_dst_counts(self) -> None:
        """
        Ensure a packet to the stack unicast IPv6 increments
        'ip6__dst_unicast'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(dst=STACK__IP6_ADDRESS, payload=b"\x00" * 8)))

        self.assertEqual(self._if._packet_stats_rx.ip6__dst_unicast, 1)

    def test__stack__packet_handler__ip6__rx__multicast_dst_counts(self) -> None:
        """
        Ensure a packet to a joined multicast group increments
        'ip6__dst_multicast'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(dst=STACK__IP6_MULTICAST, payload=b"\x00" * 8)))

        self.assertEqual(self._if._packet_stats_rx.ip6__dst_multicast, 1)


class TestPacketHandlerIp6RxForwardOrDeliver(_Ip6RxTestBase):
    """
    The RFC 1812 §5.2.1 forward-or-deliver seam
    ('Ip6RxHandler._forward_or_deliver_ip6') — the separable
    delivery decision the Phase-2 router fills the forward branch of.
    """

    @staticmethod
    def _parsed(dst: Ip6Address) -> PacketRx:
        """
        Build and parse an IPv6 PacketRx addressed to 'dst'.
        """

        packet_rx = PacketRx(_ip6_frame(dst=dst, payload=b"\x00" * 8))
        Ip6Parser(packet_rx)
        return packet_rx

    def test__stack__packet_handler__ip6__rx__forward_or_deliver__local_unicast_delivers(self) -> None:
        """
        Ensure the seam returns True for a datagram addressed to one
        of the stack's unicast addresses — it is delivered locally.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver: local delivery).
        """

        self.assertTrue(
            self._handler._forward_or_deliver_ip6(self._parsed(STACK__IP6_ADDRESS)),
            msg="A locally-addressed unicast datagram must be delivered (True).",
        )

    def test__stack__packet_handler__ip6__rx__forward_or_deliver__local_multicast_delivers(self) -> None:
        """
        Ensure the seam returns True for a datagram addressed to a
        joined multicast group.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver: local delivery).
        """

        self.assertTrue(
            self._handler._forward_or_deliver_ip6(self._parsed(STACK__IP6_MULTICAST)),
            msg="A joined-multicast datagram must be delivered (True).",
        )

    def test__stack__packet_handler__ip6__rx__forward_or_deliver__non_local_does_not_deliver(self) -> None:
        """
        Ensure the seam returns False and bumps 'ip6__dst_unknown__drop'
        for a datagram addressed elsewhere — a host has no forwarding
        plane, so the forward branch drops it.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver: non-local datagram).
        """

        self.assertFalse(
            self._handler._forward_or_deliver_ip6(self._parsed(OFF_NET__IP6)),
            msg="A non-local datagram must not be delivered locally (False).",
        )
        self.assertEqual(
            self._if._packet_stats_rx.ip6__dst_unknown__drop,
            1,
            msg="The host forward-stub must drop the non-local datagram (ip6__dst_unknown__drop).",
        )


class TestPacketHandlerIp6RxDispatch(_Ip6RxTestBase):
    """
    The protocol-dispatch branches.
    """

    def test__stack__packet_handler__ip6__rx__udp_dispatches(self) -> None:
        """
        Ensure a UDP packet dispatches to '_phrx_udp'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.UDP, payload=b"\x00" * 8)))

        self.assertEqual(self._if.dispatched, ["udp"])

    def test__stack__packet_handler__ip6__rx__tcp_dispatches(self) -> None:
        """
        Ensure a TCP packet dispatches to '_phrx_tcp'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.TCP, payload=b"\x00" * 20)))

        self.assertEqual(self._if.dispatched, ["tcp"])

    def test__stack__packet_handler__ip6__rx__icmp6_dispatches(self) -> None:
        """
        Ensure an ICMPv6 packet dispatches to '_phrx_icmp6'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.ICMP6, payload=b"\x00" * 8)))

        self.assertEqual(self._if.dispatched, ["icmp6"])

    def test__stack__packet_handler__ip6__rx__frag_dispatches(self) -> None:
        """
        Ensure an IPv6 fragment dispatches to '_phrx_ip6_frag'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.IP6_FRAG, payload=b"\x00" * 8)))

        self.assertEqual(self._if.dispatched, ["ip6_frag"])

    def test__stack__packet_handler__ip6__rx__unsupported_proto_drops(self) -> None:
        """
        Ensure an unsupported next-header drops with
        'ip6__no_proto_support__drop'.

        Reference: RFC 8200 §3 (IPv6 RX dispatch).
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.RAW, payload=b"\x00" * 8)))

        self.assertEqual(
            self._if._packet_stats_rx.ip6__no_proto_support__drop,
            1,
            msg="Unsupported IPv6 next-header must be counted in ip6__no_proto_support__drop.",
        )
        # SHOULD-emit Parameter Problem code 1 per RFC 8200 §4 — the stub
        # records the outbound dispatch via 'phtx_icmp6'.
        self.assertEqual(self._if.dispatched, ["phtx_icmp6"])
        self.assertEqual(
            self._if._packet_stats_rx.ip6__no_proto_support__respond_icmp6_param_problem,
            1,
            msg="Unsupported next-header must trigger the Param Problem emit counter.",
        )


class TestPacketHandlerIp6RxRawSocketMatch(_Ip6RxTestBase):
    """
    The RAW-socket fastpath tests.
    """

    def test__stack__packet_handler__ip6__rx__raw_socket_match_copies_without_consuming(self) -> None:
        """
        Ensure a matching RAW socket receives a copy of the datagram and
        increments 'raw__socket_match', while the packet still continues
        to the extension-header chain walker / transport handler — Linux
        'raw_local_deliver' raw delivery is a non-consuming copy.

        Reference: RFC 8200 §3 (IPv6 RX dispatch — RAW non-consuming copy).
        """

        # The RX fastpath gates on 'isinstance(socket, RawSocket)', so the
        # stub must be a RawSocket-spec'd autospec (its '__class__' passes
        # isinstance) — a bare MagicMock is skipped and never matches.
        fake_socket = create_autospec(RawSocket, spec_set=True, instance=True)

        class _MatchAllDict(dict[object, object]):
            @override
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", _MatchAllDict())
        self._sockets_patch.start()

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.UDP, payload=b"\x00" * 8)))

        self.assertEqual(
            self._if._packet_stats_rx.raw__socket_match,
            1,
            msg="A matched RAW socket must increment raw__socket_match.",
        )
        fake_socket.process_raw_packet.assert_called_once()
        self.assertEqual(
            self._if.dispatched,
            ["udp"],
            msg="A matched RAW socket receives a copy but does not consume; the transport handler still dispatches.",
        )
