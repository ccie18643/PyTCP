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
End-to-end ARP resolution-flow integration tests.

Drives outbound IPv4 packets through the live Ethernet TX path
with a real 'ArpCache' (replacing the harness's mock) so the
RFC 1122 §2.3.2.1 outbound-Request rate-limit and §2.3.2.2
saved-unresolved-packet queue can be observed at the wire
level — complementing the unit-level tests at
'pytcp/tests/unit/stack/test__stack__arp_cache.py' which
exercise the rate-limit / queue logic in isolation.

pytcp/tests/integration/protocols/arp/test__arp__resolution_flow.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import ArpOperation, ArpParser, Ip4Assembler
from net_proto.lib.packet_rx import PacketRx
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.tests.lib.arp_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)

# Distinct peer for the per-IP-independence test.
_HOST_B__MAC = MacAddress("02:00:00:00:00:92")

# IPv4 'Identification' values used as per-packet markers so the
# wire log can be matched back to the original outbound packet.
# Each test uses unique IDs; the post-resolution flush MUST emit
# the LATEST queued packet, so the marker pins which packet was
# kept.
_IP4_ID__FIRST = 0x1111
_IP4_ID__SECOND = 0x2222
_IP4_ID__THIRD = 0x3333


class TestArpResolutionFlow(ArpTestCase):
    """
    End-to-end ARP resolution flow tests — RFC 1122 §2.3.2
    behaviour at the wire level.
    """

    @override
    def setUp(self) -> None:
        """
        Build the standard ARP harness, then replace the mock
        'ArpCache' with a real instance so the in-progress-
        resolution table and queued-packet flush behave as in
        production. Anchor the patched 'time.monotonic' clock
        at t=1000.0 so per-test 'advance_monotonic' arithmetic
        is unambiguous.
        """

        super().setUp()
        # The ARP cache is per-interface state on the handler now (the
        # global 'stack.arp_cache' singleton was retired); install a real
        # one in place of the harness mock so the in-progress-resolution
        # table and queued-packet flush behave as in production. The
        # reverse owner back-reference lets the cache's solicit / flush
        # callbacks route through this handler. The handler is rebuilt
        # per-test by the harness, so no restore is needed.
        self._real_cache = ArpCache()
        self._packet_handler._arp_cache = self._real_cache
        self._real_cache._owner = self._packet_handler
        self._set_monotonic(1000.0)

    # -- helpers ----------------------------------------------------------

    def _drive_outbound_ip4(
        self,
        *,
        dst: Ip4Address,
        ip4_id: int,
    ) -> None:
        """
        Drive an outbound IPv4 packet through the live Ethernet
        TX path. The Ethernet destination MAC is left
        unspecified, which forces the Ethernet TX handler to
        run the ARP cache lookup that the resolution flow
        exercises.
        """

        ip4 = Ip4Assembler(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=dst,
            ip4__id=ip4_id,
        )
        self._packet_handler._phtx_ethernet(ethernet__payload=ip4)

    def _drive_arp_reply(
        self,
        *,
        spa: Ip4Address,
        sha: MacAddress = HOST_A__MAC_ADDRESS,
    ) -> None:
        """
        Drive an inbound ARP Reply that resolves 'spa -> sha'.
        Routes through the live RX handler, which calls
        '__update_arp_cache' → 'ArpCache.add_entry', triggering
        the queued-packet flush.
        """

        self._drive_arp(
            ethernet_dst=STACK__MAC_ADDRESS,
            ethernet_src=sha,
            arp_oper=ArpOperation.REPLY,
            arp_sha=sha,
            arp_spa=spa,
            arp_tha=STACK__MAC_ADDRESS,
            arp_tpa=STACK__IP4_HOST.address,
        )

    def _arp_request_targets(self) -> list[Ip4Address]:
        """
        Walk '_frames_tx' and extract the 'tpa' field of every
        ARP Request frame the stack emitted. Lets tests assert
        on which destinations the rate-limit fired Requests for
        without comparing whole frames.
        """

        targets: list[Ip4Address] = []
        for frame in self._frames_tx:
            if frame[12:14] != b"\x08\x06":
                continue
            packet_rx = PacketRx(frame[14:])
            ArpParser(packet_rx)
            if packet_rx.arp.oper is ArpOperation.REQUEST:
                targets.append(packet_rx.arp.tpa)
        return targets

    def _flushed_ip4_ids(self) -> list[int]:
        """
        Walk '_frames_tx' and extract the IPv4 'Identification'
        field of every IPv4 frame on the wire. Lets tests
        identify which queued packet was actually flushed
        post-resolution.
        """

        ids: list[int] = []
        for frame in self._frames_tx:
            if frame[12:14] != b"\x08\x00":
                continue
            ids.append(int.from_bytes(frame[14 + 4 : 14 + 6], "big"))
        return ids

    # -- tests ------------------------------------------------------------

    def test__arp__resolution__rate_limit_at_wire_level(self) -> None:
        """
        Ensure three outbound IPv4 packets to the same
        unresolved destination within the rate-limit window
        produce exactly one ARP Request on the wire — the
        host MUST NOT flood the link with repeat Requests.

        Reference: RFC 1122 §2.3.2.1 (prevent ARP flooding).
        """

        self._drive_outbound_ip4(dst=HOST_B__IP4_ADDRESS, ip4_id=_IP4_ID__FIRST)
        self._advance_monotonic(0.3)
        self._drive_outbound_ip4(dst=HOST_B__IP4_ADDRESS, ip4_id=_IP4_ID__SECOND)
        self._advance_monotonic(0.3)
        self._drive_outbound_ip4(dst=HOST_B__IP4_ADDRESS, ip4_id=_IP4_ID__THIRD)

        self.assertEqual(
            self._arp_request_targets(),
            [HOST_B__IP4_ADDRESS],
            msg=(
                "Three back-to-back cache misses within the rate-limit "
                "window must produce exactly one ARP Request on the wire "
                f"(targeting {HOST_B__IP4_ADDRESS}). Got: "
                f"{self._arp_request_targets()!r}"
            ),
        )

    def test__arp__resolution__queued_packet_flushed_on_reply(self) -> None:
        """
        Ensure an outbound IPv4 packet that misses the ARP
        cache is queued, and a subsequent ARP Reply resolving
        the destination causes the queued packet to be
        re-emitted on the wire with the resolved Ethernet
        destination MAC.

        Reference: RFC 1122 §2.3.2.2 (transmit the saved packet on resolution).
        """

        self._drive_outbound_ip4(dst=HOST_A__IP4_ADDRESS, ip4_id=_IP4_ID__FIRST)

        # Before the Reply: only the ARP Request is on the wire.
        self.assertEqual(
            self._flushed_ip4_ids(),
            [],
            msg="Before resolution, the queued IPv4 packet must NOT be on the wire.",
        )

        self._drive_arp_reply(spa=HOST_A__IP4_ADDRESS, sha=HOST_A__MAC_ADDRESS)

        # After the Reply: the queued IPv4 packet is flushed.
        self.assertEqual(
            self._flushed_ip4_ids(),
            [_IP4_ID__FIRST],
            msg=(
                "Post-resolution, the queued IPv4 packet (id="
                f"{_IP4_ID__FIRST:#06x}) must appear on the wire. Got "
                f"flushed IDs: {[hex(i) for i in self._flushed_ip4_ids()]!r}"
            ),
        )

        # The Ethernet destination MAC of the flushed frame must
        # equal the resolved peer MAC.
        flushed = next(f for f in self._frames_tx if f[12:14] == b"\x08\x00")
        self.assertEqual(
            MacAddress(flushed[0:6]),
            HOST_A__MAC_ADDRESS,
            msg=(
                "Flushed packet's Ethernet 'dst' must equal the resolved "
                f"peer MAC ({HOST_A__MAC_ADDRESS}). Got: "
                f"{MacAddress(flushed[0:6])}"
            ),
        )

    def test__arp__resolution__all_queued_packets_flushed_in_fifo_order(self) -> None:
        """
        Ensure that when multiple outbound packets are queued
        against the same unresolved IP, every one is delivered
        in arrival order once the MAC resolves — not just the
        latest. A fragmented datagram is several link-layer
        packets, so keeping only the newest would lose it;
        PyTCP mirrors the Linux bounded per-neighbour queue,
        which exceeds the "save at least one" SHOULD floor.

        Reference: RFC 1122 §2.3.2.2 (save unresolved packets, transmit on resolution).
        """

        self._drive_outbound_ip4(dst=HOST_A__IP4_ADDRESS, ip4_id=_IP4_ID__FIRST)
        self._advance_monotonic(0.3)
        self._drive_outbound_ip4(dst=HOST_A__IP4_ADDRESS, ip4_id=_IP4_ID__SECOND)
        self._advance_monotonic(0.3)
        self._drive_outbound_ip4(dst=HOST_A__IP4_ADDRESS, ip4_id=_IP4_ID__THIRD)

        self._drive_arp_reply(spa=HOST_A__IP4_ADDRESS, sha=HOST_A__MAC_ADDRESS)

        self.assertEqual(
            self._flushed_ip4_ids(),
            [_IP4_ID__FIRST, _IP4_ID__SECOND, _IP4_ID__THIRD],
            msg=(
                "Post-resolution, every queued packet must be flushed in "
                "FIFO arrival order. Got flushed IDs: "
                f"{[hex(i) for i in self._flushed_ip4_ids()]!r}"
            ),
        )

    def test__arp__resolution__per_ip_independence(self) -> None:
        """
        Ensure outbound packets to two different unresolved
        destinations do NOT share a rate-limit bucket: each
        destination triggers its own ARP Request, and each
        independently queues its own packet, so a Reply for
        one IP flushes only that IP's queued packet.

        Reference: RFC 1122 §2.3.2.1 (1/sec/destination granularity).
        Reference: RFC 1122 §2.3.2.2 (per-IP queue).
        """

        self._drive_outbound_ip4(dst=HOST_A__IP4_ADDRESS, ip4_id=_IP4_ID__FIRST)
        self._advance_monotonic(0.1)
        self._drive_outbound_ip4(dst=HOST_B__IP4_ADDRESS, ip4_id=_IP4_ID__SECOND)

        self.assertEqual(
            self._arp_request_targets(),
            [HOST_A__IP4_ADDRESS, HOST_B__IP4_ADDRESS],
            msg=(
                "Misses on two different IPs within the same window must "
                "each fire their own ARP Request. Got: "
                f"{self._arp_request_targets()!r}"
            ),
        )

        # Resolve A only — packet A flushes; packet B remains queued.
        self._drive_arp_reply(spa=HOST_A__IP4_ADDRESS, sha=HOST_A__MAC_ADDRESS)
        self.assertEqual(
            self._flushed_ip4_ids(),
            [_IP4_ID__FIRST],
            msg=(
                "Reply for A must flush only A's queued packet (id="
                f"{_IP4_ID__FIRST:#06x}); B's packet remains queued. Got "
                f"flushed IDs: {[hex(i) for i in self._flushed_ip4_ids()]!r}"
            ),
        )

        # Resolve B — packet B now flushes too.
        self._drive_arp_reply(spa=HOST_B__IP4_ADDRESS, sha=_HOST_B__MAC)
        self.assertEqual(
            self._flushed_ip4_ids(),
            [_IP4_ID__FIRST, _IP4_ID__SECOND],
            msg=(
                "Reply for B must flush B's queued packet (id="
                f"{_IP4_ID__SECOND:#06x}). Got flushed IDs: "
                f"{[hex(i) for i in self._flushed_ip4_ids()]!r}"
            ),
        )
