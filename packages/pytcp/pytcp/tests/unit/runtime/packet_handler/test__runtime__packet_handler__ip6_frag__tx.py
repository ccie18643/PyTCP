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
This module contains unit tests for the 'Ip6FragTxHandler' sub-handler.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__ip6_frag__tx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Ip6Assembler, Ip6FragAssembler, RawAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__ip6_frag__tx import (
    Ip6FragTxHandler,
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

    Carries the TX-stat counters and the interface MTU the
    IPv6-fragment TX sub-handler reaches through 'self._if', plus a
    '_phtx_ip6' spy that records each per-fragment call and returns a
    configurable 'TxStatus'. A purpose-built double is used rather than
    'create_autospec(PacketHandlerL2)' — the god-class still carries
    'TYPE_CHECKING'-only annotations 'inspect.signature' (which autospec
    walks) cannot evaluate at runtime.
    """

    def __init__(self, *, interface_mtu: int = 200, ip6_tx_status: TxStatus | None = None) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self._interface_mtu = interface_mtu

        self.ip6_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_status: TxStatus = ip6_tx_status or TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return self.ip6_tx_status


def _make_ip6_frag_tx(
    *,
    interface_mtu: int = 200,
    ip6_tx_status: TxStatus | None = None,
) -> tuple[Ip6FragTxHandler, _StubInterface]:
    """
    Build an 'Ip6FragTxHandler' over a fresh stub interface and return
    both — the handler to drive, the interface to assert spies on.
    """

    interface = _StubInterface(interface_mtu=interface_mtu, ip6_tx_status=ip6_tx_status)
    return (
        Ip6FragTxHandler(interface=cast("PacketHandlerL2 | PacketHandlerL3", interface)),
        interface,
    )


class TestPacketHandlerIp6FragTx(TestCase):
    """
    The 'Ip6FragTxHandler._phtx_ip6_frag' behaviour tests.
    """

    def _build_ip6_packet(self, *, payload_size: int) -> Ip6Assembler:
        """
        Build an 'Ip6Assembler' carrying 'payload_size' bytes of RAW data.
        """

        return Ip6Assembler(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(raw__payload=b"\x11" * payload_size),
        )

    def test__stack__packet_handler__ip6_frag__tx__frag_id_is_randomized_per_burst(self) -> None:
        """
        Ensure ten consecutive emit cycles produce Fragment
        Identification values that are not the predictable
        monotonic '+1' sequence the previous counter generated.
        Random 32-bit IDs make a ten-draw sequence with every
        delta exactly +1 vanishingly unlikely (~1 in 2^288),
        so the assertion is statistically robust.

        Reference: RFC 7739 §5 (cryptographic-quality random
        Fragment Identification values to defeat predictable-ID
        fragmentation attacks).
        """

        handler, iface = _make_ip6_frag_tx(interface_mtu=200)
        ip6_packet = self._build_ip6_packet(payload_size=400)

        ids: list[int] = []
        for _ in range(10):
            iface.ip6_tx_calls.clear()
            handler._phtx_ip6_frag(ip6_packet_tx=ip6_packet)
            # The Fragment Identification is now a loop-local rather
            # than a handler attribute, so read it back off the
            # emitted fragment instead of 'handler._ip6_id'.
            payload = iface.ip6_tx_calls[-1]["ip6__payload"]
            assert isinstance(payload, Ip6FragAssembler)
            ids.append(payload.id)

        deltas = [ids[i + 1] - ids[i] for i in range(9)]
        self.assertNotEqual(
            deltas,
            [1] * 9,
            msg=(
                "Fragment Identification values must not be the predictable "
                "monotonic '+1' sequence the legacy counter produced; RFC 7739 §5 "
                "requires randomization."
            ),
        )

    def test__stack__packet_handler__ip6_frag__tx__splits_into_multiple_fragments(self) -> None:
        """
        Ensure a payload that exceeds the per-fragment MTU is split into
        at least two fragments and each is forwarded to '_phtx_ip6'.

        Reference: RFC 8200 §4.5 (IPv6 fragmentation).
        """

        handler, iface = _make_ip6_frag_tx(interface_mtu=200)
        ip6_packet = self._build_ip6_packet(payload_size=400)

        status = handler._phtx_ip6_frag(ip6_packet_tx=ip6_packet)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Fragmentation with every fragment passing must return PASSED__ETHERNET__TO_TX_RING.",
        )
        self.assertEqual(
            iface._packet_stats_tx.ip6_frag__pre_assemble,
            1,
            msg="ip6_frag__pre_assemble must be incremented once per outbound packet.",
        )
        self.assertGreaterEqual(
            iface._packet_stats_tx.ip6_frag__send,
            2,
            msg="At least two fragments must be sent for a payload exceeding one MTU.",
        )
        self.assertGreaterEqual(
            len(iface.ip6_tx_calls),
            2,
            msg="At least two '_phtx_ip6' calls must be issued (one per fragment).",
        )
        for call in iface.ip6_tx_calls:
            self.assertIsInstance(
                call["ip6__payload"],
                Ip6FragAssembler,
                msg="Every per-fragment call must pass an Ip6FragAssembler payload.",
            )

    def test__stack__packet_handler__ip6_frag__tx__id_shared_within_burst(self) -> None:
        """
        Ensure every fragment of a single emit cycle reuses the
        same Fragment Identification value — the per-call random
        pick must not change between fragments of the same
        datagram or the receiver could not reassemble them.

        Reference: RFC 8200 §4.5 (all fragments of a datagram
        share one Fragment Identification value).
        Reference: RFC 7739 §5 (the value itself is randomized
        per-burst, not per-fragment).
        """

        handler, iface = _make_ip6_frag_tx(interface_mtu=200)

        handler._phtx_ip6_frag(ip6_packet_tx=self._build_ip6_packet(payload_size=400))

        ids_in_burst = [int(cast(Ip6FragAssembler, call["ip6__payload"]).id) for call in iface.ip6_tx_calls]
        self.assertGreater(
            len(ids_in_burst),
            1,
            msg="Test fixture must produce more than one fragment.",
        )
        self.assertEqual(
            len(set(ids_in_burst)),
            1,
            msg="Every fragment in a single burst must share one Fragment Identification.",
        )

    def test__stack__packet_handler__ip6_frag__tx__returns_worst_status(self) -> None:
        """
        Ensure the handler returns the most severe TX status when per-
        fragment results differ (documents the priority order).

        Reference: RFC 8200 §4.5 (IPv6 fragmentation).
        """

        handler, iface = _make_ip6_frag_tx(
            interface_mtu=200,
            ip6_tx_status=TxStatus.DROPPED__ETHERNET__DST_ND_CACHE_MISS,
        )
        status = handler._phtx_ip6_frag(ip6_packet_tx=self._build_ip6_packet(payload_size=400))

        self.assertEqual(
            status,
            TxStatus.DROPPED__ETHERNET__DST_ND_CACHE_MISS,
            msg="Worst per-fragment status must propagate to the caller.",
        )

    def test__stack__packet_handler__ip6_frag__tx__l3_reports_passed_to_tx_ring(self) -> None:
        """
        Ensure a fragmented send whose per-fragment status is
        PASSED__IP6__TO_TX_RING (the L3 / TUN direct-enqueue path)
        reports PASSED__IP6__TO_TX_RING to the caller rather than a
        spurious drop.

        Reference: RFC 8200 §4.5 (IPv6 fragmentation).
        """

        handler, iface = _make_ip6_frag_tx(
            interface_mtu=200,
            ip6_tx_status=TxStatus.PASSED__IP6__TO_TX_RING,
        )
        status = handler._phtx_ip6_frag(ip6_packet_tx=self._build_ip6_packet(payload_size=400))

        self.assertEqual(
            status,
            TxStatus.PASSED__IP6__TO_TX_RING,
            msg="L3 fragmented send with every fragment enqueued must return PASSED__IP6__TO_TX_RING.",
        )
