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
This module contains unit tests for the 'Ip6FragRxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6_frag__rx.py

ver 3.0.10
"""

from typing import TYPE_CHECKING, cast, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Ip6Assembler, Ip6Parser, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_frag.ip6_frag__assembler import Ip6FragAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.protocols.ip.ip_frag import IpFragFlowId
from pytcp.protocols.ip.ip_frag_table import IpFragTable
from pytcp.runtime.packet_handler.packet_handler__ip6_frag__rx import (
    Ip6FragRxHandler,
)

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
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")


class _StubInterface:
    """
    Minimal stand-in for the owning 'PacketHandlerL2' / 'PacketHandlerL3'
    interface.

    Carries the RX-stat counters and the IPv6 fragment flow table the
    IPv6-fragment RX sub-handler reaches through 'self._if', plus a
    '_phrx_ip6' spy that records each reassembled packet forwarded to
    the IPv6 RX path. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which autospec
    walks) cannot evaluate at runtime.
    """

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self._ip6_frag_table = IpFragTable(timeout=stack.IP6__FRAG_FLOW_TIMEOUT__S)

        # Spy: record each reassembled packet forwarded to _phrx_ip6.
        self.ip6_reassembled: list[PacketRx] = []

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        self.ip6_reassembled.append(packet_rx)


def _ip6_frag_packet_rx(
    *,
    src: Ip6Address = HOST_A__IP6,
    dst: Ip6Address = STACK__IP6_ADDRESS,
    frag_id: int,
    offset: int,
    flag_mf: bool,
    payload: bytes,
    next_proto: IpProto = IpProto.UDP,
    dscp: int = 0,
    ecn: int = 0,
    flow: int = 0,
    hop: int = 64,
) -> PacketRx:
    """
    Build a 'PacketRx' that looks like one just parsed by 'Ip6Parser':
    'packet_rx.frame' points at the fragment extension header and
    'packet_rx.ip6' is populated.
    """

    frame = bytes(
        Ip6Assembler(
            ip6__src=src,
            ip6__dst=dst,
            ip6__dscp=dscp,
            ip6__ecn=ecn,
            ip6__flow=flow,
            ip6__hop=hop,
            ip6__payload=Ip6FragAssembler(
                ip6_frag__next=next_proto,
                ip6_frag__offset=offset,
                ip6_frag__flag_mf=flag_mf,
                ip6_frag__id=frag_id,
                ip6_frag__payload=payload,
            ),
        )
    )
    packet_rx = PacketRx(frame)
    Ip6Parser(packet_rx)
    return packet_rx


class TestPacketHandlerIp6FragRx(TestCase):
    """
    The 'Ip6FragRxHandler._phrx_ip6_frag' behaviour tests.
    """

    @override
    def setUp(self) -> None:
        self._if = _StubInterface()
        self._handler = Ip6FragRxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", self._if))

    def test__stack__packet_handler__ip6_frag__rx__first_fragment_stored(self) -> None:
        """
        Ensure the first of two fragments is stored in the flow table
        and does not trigger a reassembly.

        Reference: RFC 8200 §4.5 (IPv6 reassembly).
        """

        packet_rx = _ip6_frag_packet_rx(
            frag_id=1111,
            offset=0,
            flag_mf=True,
            payload=b"\x00" * 8,
        )
        self._handler._phrx_ip6_frag(packet_rx)

        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__pre_parse,
            1,
            msg="ip6_frag__pre_parse must be incremented on every inbound fragment.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__defrag,
            0,
            msg="Incomplete fragment set must not trigger defrag counter.",
        )
        self.assertEqual(
            len(self._if._ip6_frag_table.flows),
            1,
            msg="The first fragment must be stored in the flow table.",
        )
        self.assertEqual(
            self._if.ip6_reassembled,
            [],
            msg="Incomplete fragment set must not dispatch to _phrx_ip6.",
        )

    def test__stack__packet_handler__ip6_frag__rx__full_reassembly_dispatches_ip6(self) -> None:
        """
        Ensure two in-order fragments reassemble into a single packet
        dispatched to '_phrx_ip6' and the flow is purged.

        Reference: RFC 8200 §4.5 (IPv6 reassembly).
        """

        frag0 = _ip6_frag_packet_rx(
            frag_id=2222,
            offset=0,
            flag_mf=True,
            payload=b"\xaa" * 8,
        )
        frag1 = _ip6_frag_packet_rx(
            frag_id=2222,
            offset=8,
            flag_mf=False,
            payload=b"\xbb" * 8,
        )

        self._handler._phrx_ip6_frag(frag0)
        self._handler._phrx_ip6_frag(frag1)

        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__defrag,
            1,
            msg="Successful reassembly must increment ip6_frag__defrag.",
        )
        self.assertEqual(
            self._if._ip6_frag_table.flows,
            {},
            msg="Flow entry must be cleared after full reassembly.",
        )
        self.assertEqual(
            len(self._if.ip6_reassembled),
            1,
            msg="Reassembled packet must be forwarded to _phrx_ip6 exactly once.",
        )

    def test__stack__packet_handler__ip6_frag__rx__out_of_order_pending(self) -> None:
        """
        Ensure the reassembler stays pending when the final fragment
        arrives before the first.

        Reference: RFC 8200 §4.5 (IPv6 reassembly).
        """

        # Final fragment (offset=8) arrives first.
        frag1 = _ip6_frag_packet_rx(
            frag_id=3333,
            offset=8,
            flag_mf=False,
            payload=b"\xbb" * 8,
        )
        self._handler._phrx_ip6_frag(frag1)

        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__defrag,
            0,
            msg="Out-of-order final fragment alone must not trigger reassembly.",
        )
        self.assertEqual(self._if.ip6_reassembled, [])

    def test__stack__packet_handler__ip6_frag__rx__same_fragment_twice_drops_flow(self) -> None:
        """
        Ensure that re-receiving a fragment with the same offset
        is treated as an overlapping arrival under PyTCP's
        strict reading: the flow is marked discarded, its stored
        payload is cleared, and the 'ip6_frag__overlap__drop'
        counter increments. Benign duplicates therefore destroy
        in-progress reassemblies — the stricter security
        posture is preferred over the lenient retransmit-tolerant
        interpretation.

        Reference: RFC 5722 §3 (silent-discard on fragment overlap;
        strict reading treats exact duplicates as overlapping).
        """

        frag = _ip6_frag_packet_rx(
            frag_id=4444,
            offset=0,
            flag_mf=True,
            payload=b"\xcc" * 8,
        )
        self._handler._phrx_ip6_frag(frag)
        frag2 = _ip6_frag_packet_rx(
            frag_id=4444,
            offset=0,
            flag_mf=True,
            payload=b"\xdd" * 8,
        )
        self._handler._phrx_ip6_frag(frag2)

        flow = IpFragFlowId(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            id=4444,
        )
        self.assertTrue(
            self._if._ip6_frag_table.flows[flow].discarded,
            msg="Repeated fragment must mark the flow discarded.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__overlap__drop,
            1,
            msg="Overlap detection must increment 'ip6_frag__overlap__drop'.",
        )

    def test__stack__packet_handler__ip6_frag__rx__atomic_fragment_dispatches_without_flow_table(self) -> None:
        """
        Ensure an atomic IPv6 fragment (offset=0, M=0) dispatches
        to the upper layer immediately, bumps both
        'ip6_frag__defrag' and 'ip6_frag__atomic__defrag', and
        leaves the flow table untouched.

        Reference: RFC 8200 §4.5 (atomic fragment fast-path).
        Reference: RFC 6946 §4 (atomic fragments isolated from
        any non-atomic reassembly).
        """

        atomic = _ip6_frag_packet_rx(
            frag_id=6060,
            offset=0,
            flag_mf=False,
            payload=b"\x77" * 16,
        )

        self._handler._phrx_ip6_frag(atomic)

        self.assertEqual(
            len(self._if.ip6_reassembled),
            1,
            msg="An atomic fragment must dispatch to '_phrx_ip6' once.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__defrag,
            1,
            msg="An atomic fragment must increment 'ip6_frag__defrag'.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__atomic__defrag,
            1,
            msg="An atomic fragment must increment 'ip6_frag__atomic__defrag'.",
        )
        self.assertEqual(
            self._if._ip6_frag_table.flows,
            {},
            msg="An atomic fragment must not allocate a flow-table entry.",
        )

    def test__stack__packet_handler__ip6_frag__rx__overlapping_fragments_drop_flow(self) -> None:
        """
        Ensure two non-final fragments whose byte ranges overlap
        (offset 0 length 16, then offset 8 length 8) are dropped:
        no dispatch to '_phrx_ip6', the
        'ip6_frag__overlap__drop' counter increments, and the
        flow is marked discarded.

        Reference: RFC 5722 §3 (silent-discard on fragment overlap).
        """

        frag_a = _ip6_frag_packet_rx(
            frag_id=5454,
            offset=0,
            flag_mf=True,
            payload=b"\xaa" * 16,
        )
        frag_b = _ip6_frag_packet_rx(
            frag_id=5454,
            offset=8,
            flag_mf=True,
            payload=b"\xbb" * 8,
        )

        self._handler._phrx_ip6_frag(frag_a)
        self._handler._phrx_ip6_frag(frag_b)

        self.assertEqual(
            self._if.ip6_reassembled,
            [],
            msg="An overlapping flow must not dispatch to '_phrx_ip6'.",
        )
        self.assertEqual(
            self._if._packet_stats_rx.ip6_frag__overlap__drop,
            1,
            msg="Overlap detection must increment 'ip6_frag__overlap__drop'.",
        )
        flow = IpFragFlowId(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            id=5454,
        )
        self.assertTrue(
            self._if._ip6_frag_table.flows[flow].discarded,
            msg="Overlap detection must mark the flow as discarded.",
        )

    def test__stack__packet_handler__ip6_frag__rx__out_of_order_three_fragments_reassemble(self) -> None:
        """
        Ensure three IPv6 fragments arriving out of order
        (middle, last, first) reassemble into a single datagram
        with the payload bytes laid out in offset order regardless
        of arrival order.

        Reference: RFC 8200 §4.5 (IPv6 reassembly assembles in offset order).
        """

        payload_a = b"\xaa" * 8
        payload_b = b"\xbb" * 8
        payload_c = b"\xcc" * 8
        expected_payload = payload_a + payload_b + payload_c

        frag_a = _ip6_frag_packet_rx(
            frag_id=21111,
            offset=0,
            flag_mf=True,
            payload=payload_a,
        )
        frag_b = _ip6_frag_packet_rx(
            frag_id=21111,
            offset=8,
            flag_mf=True,
            payload=payload_b,
        )
        frag_c = _ip6_frag_packet_rx(
            frag_id=21111,
            offset=16,
            flag_mf=False,
            payload=payload_c,
        )

        # Arrival order: middle → last → first.
        self._handler._phrx_ip6_frag(frag_b)
        self._handler._phrx_ip6_frag(frag_c)
        self._handler._phrx_ip6_frag(frag_a)

        self.assertEqual(
            len(self._if.ip6_reassembled),
            1,
            msg="Reassembled datagram must dispatch to _phrx_ip6 exactly once.",
        )
        reassembled = self._if.ip6_reassembled[0]
        Ip6Parser(reassembled)
        self.assertEqual(
            bytes(reassembled.ip6.payload_bytes),
            expected_payload,
            msg="Reassembled payload bytes must be in offset order regardless of arrival order.",
        )

    def test__stack__packet_handler__ip6_frag__rx__reassembled_header_preserves_first_fragment_fields(self) -> None:
        """
        Ensure the reassembled IPv6 datagram preserves the DSCP,
        ECN, Flow Label, and Hop Limit fields from the first
        fragment while rewriting Payload Length and Next Header
        (the latter to the upper-layer protocol carried after the
        Fragment header).

        Reference: RFC 8200 §4.5 (reassembled header preserves
        first-fragment fields apart from payload length and the
        Next Header, which becomes the upper-layer protocol).
        """

        payload_a = b"\xaa" * 8
        payload_b = b"\xbb" * 8

        frag_a = _ip6_frag_packet_rx(
            frag_id=33333,
            offset=0,
            flag_mf=True,
            payload=payload_a,
            next_proto=IpProto.UDP,
            dscp=0x3A,
            ecn=0x02,
            flow=0x12345,
            hop=42,
        )
        frag_b = _ip6_frag_packet_rx(
            frag_id=33333,
            offset=8,
            flag_mf=False,
            payload=payload_b,
            next_proto=IpProto.UDP,
            dscp=0x3A,
            ecn=0x02,
            flow=0x12345,
            hop=42,
        )

        self._handler._phrx_ip6_frag(frag_a)
        self._handler._phrx_ip6_frag(frag_b)

        reassembled = self._if.ip6_reassembled[0]
        Ip6Parser(reassembled)
        ip6 = reassembled.ip6

        # Preserved from first fragment.
        self.assertEqual(
            ip6.dscp,
            0x3A,
            msg="Reassembled header must preserve the first-fragment DSCP.",
        )
        self.assertEqual(
            ip6.ecn,
            0x02,
            msg="Reassembled header must preserve the first-fragment ECN.",
        )
        self.assertEqual(
            ip6.flow,
            0x12345,
            msg="Reassembled header must preserve the first-fragment Flow Label.",
        )
        self.assertEqual(
            ip6.hop,
            42,
            msg="Reassembled header must preserve the first-fragment Hop Limit.",
        )
        self.assertEqual(
            ip6.src,
            HOST_A__IP6,
            msg="Reassembled header must preserve the first-fragment source.",
        )
        self.assertEqual(
            ip6.dst,
            STACK__IP6_ADDRESS,
            msg="Reassembled header must preserve the first-fragment destination.",
        )

        # Rewritten by the rebuild path.
        self.assertEqual(
            ip6.next,
            IpProto.UDP,
            msg=(
                "Reassembled header Next Header must be the upper-layer "
                "protocol carried by the original Fragment Extension "
                "Header (UDP), not IP6_FRAG."
            ),
        )
        self.assertEqual(
            ip6.dlen,
            len(payload_a) + len(payload_b),
            msg="Reassembled header Payload Length must equal the joined fragment payloads.",
        )

    def test__stack__packet_handler__ip6_frag__rx__expired_flow_is_reaped(self) -> None:
        """
        Ensure a fragment flow whose timestamp is older than
        'IP6__FRAG_FLOW_TIMEOUT__S' seconds is removed from the flow
        table on the next defragment pass, freeing the buffer that
        would otherwise grow without bound.

        Reference: RFC 8200 §4.5 (reassembly timeout, fragments discarded).
        Reference: RFC 8504 §16 (host buffer-hygiene requirement).
        """

        stale_frag = _ip6_frag_packet_rx(
            frag_id=5555,
            offset=0,
            flag_mf=True,
            payload=b"\xee" * 8,
        )
        self._handler._phrx_ip6_frag(stale_frag)

        stale_flow_id = IpFragFlowId(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            id=5555,
        )
        self.assertIn(
            stale_flow_id,
            self._if._ip6_frag_table.flows,
            msg="Precondition: the stale flow must exist after the first fragment.",
        )

        # Backdate the stored fragment's timestamp past the timeout
        # so the next defragment pass should reap it.
        stale_flow = self._if._ip6_frag_table.flows[stale_flow_id]
        object.__setattr__(
            stale_flow,
            "timestamp",
            stale_flow.timestamp - (stack.IP6__FRAG_FLOW_TIMEOUT__S + 1),
        )

        # Fire an unrelated fragment so '__defragment_ip6_packet' runs
        # its cleanup pass.
        fresh_frag = _ip6_frag_packet_rx(
            frag_id=9999,
            offset=0,
            flag_mf=True,
            payload=b"\xff" * 8,
        )
        self._handler._phrx_ip6_frag(fresh_frag)

        self.assertNotIn(
            stale_flow_id,
            self._if._ip6_frag_table.flows,
            msg=(
                "A flow whose timestamp predates 'time() - IP6__FRAG_FLOW_TIMEOUT__S' "
                "must be removed by the cleanup pass at the start of "
                "'__defragment_ip6_packet'."
            ),
        )
        fresh_flow_id = IpFragFlowId(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            id=9999,
        )
        self.assertIn(
            fresh_flow_id,
            self._if._ip6_frag_table.flows,
            msg="The new fragment's flow must be admitted alongside the cleanup.",
        )
        self.assertEqual(
            len(self._if._ip6_frag_table.flows),
            1,
            msg="After cleanup the stale flow is gone and only the fresh flow remains.",
        )
