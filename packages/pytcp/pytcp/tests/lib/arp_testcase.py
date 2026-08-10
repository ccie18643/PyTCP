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
Integration-test harness for ARP packet-handler tests.

Extends 'NetworkTestCase' with ARP-aware helpers:

  - '_build_arp_frame' / '_drive_arp' — construct an Ethernet+ARP
    frame from semantic kwargs (oper, sha, spa, tha, tpa, plus L2
    src/dst) and optionally drive it through the live packet
    handler. Replaces the hand-crafted 42-byte raw fixtures used
    by the legacy tests.

  - '_set_monotonic' / '_advance_monotonic' — control the
    'time.monotonic()' clock that the RFC 5227 §2.4(c) defense
    rate-limit reads. Lets DEFEND_INTERVAL behaviour be
    exercised deterministically.

  - '_drive_dad' — drive 'PacketHandlerL2._create_stack_ip4_addressing'
    synchronously with the per-candidate 'Ip4Acd' engine mocked
    out, so the static-host probe / announce glue is exercised
    without real RFC 5227 timing. The probe outcome (clean vs
    conflict) is set per call; the RFC 5227 §2.1.1 / §2.3 wire
    mechanics themselves are pinned by the 'Ip4Acd' engine tests.

pytcp/tests/lib/arp_testcase.py

ver 3.0.9
"""

from typing import cast, override
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp.protocols.ip4.acd.ip4_acd import AcdResult
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    HOST_C__IP4_ADDRESS,
    IP4__BROADCAST__LIMITED,
    IP4__MULTICAST__ALL_NODES,
    IP4__UNSPECIFIED,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_GATEWAY,
    STACK__IP4_GATEWAY_MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

__all__ = (
    "ArpTestCase",
    "HOST_A__IP4_ADDRESS",
    "HOST_A__MAC_ADDRESS",
    "HOST_B__IP4_ADDRESS",
    "HOST_C__IP4_ADDRESS",
    "IP4__BROADCAST__LIMITED",
    "IP4__MULTICAST__ALL_NODES",
    "IP4__UNSPECIFIED",
    "MAC__BROADCAST",
    "MAC__UNSPECIFIED",
    "STACK__IP4_GATEWAY",
    "STACK__IP4_GATEWAY_MAC_ADDRESS",
    "STACK__IP4_HOST",
    "STACK__IP4_HOST__CANDIDATE",
    "STACK__MAC_ADDRESS",
)


class ArpTestCase(NetworkTestCase):
    """
    Base case for ARP integration tests.
    """

    _monotonic_t: float
    _acd: MagicMock

    @override
    def setUp(self) -> None:
        """
        Install the ARP-specific patches: clock control for the
        ARP-cache rate-limit and an 'Ip4Acd' engine mock for the
        synchronous DAD driver.
        """

        super().setUp()

        # Clock for time-sensitive ARP behaviours. The ARP cache's
        # 'find_entry' reads 'time.monotonic' for the RFC 1122
        # §2.3.2.1 per-destination ARP-Request rate-limit; patch it
        # so '_set_monotonic' / '_advance_monotonic' drive that clock
        # deterministically. (The ARP RX path no longer reads the
        # clock — RFC 5227 §2.4 ongoing defense moved to the
        # userspace 'Ip4Acd' engine in Phase 4.)
        self._monotonic_t = 0.0

        def _read_monotonic() -> float:
            return self._monotonic_t

        # Register the stop via addCleanup (NOT tearDown): this patches
        # 'time.monotonic' on the SHARED 'time' module, so a leaked
        # patch is global. addCleanup runs even when a SUBCLASS setUp
        # raises after 'super().setUp()' — tearDown does not. Without
        # this a broken subclass setUp leaks a mocked 'time.monotonic'
        # into every later test in the suite (e.g. the DHCPv4
        # '_dnav4_probe' busy-loop spins unboundedly on a mock clock
        # and OOMs the run).
        self._arp_cache_monotonic_patch = patch(
            "pytcp.lib.neighbor.time.monotonic",
            side_effect=_read_monotonic,
        )
        self._arp_cache_monotonic_patch.start()
        self.addCleanup(self._arp_cache_monotonic_patch.stop)

        # Mock the per-candidate 'Ip4Acd' engine the static-host
        # path constructs. The static-host
        # '_create_stack_ip4_addressing' builds one engine per
        # candidate and calls 'probe' then (on a clean probe)
        # 'announce'; the engine class mock returns the same
        # instance for every construction, so 'self._acd.probe' /
        # '.announce' capture the calls across all candidates. The
        # real RFC 5227 timing / wire mechanics are covered by the
        # 'Ip4Acd' engine tests — here the engine is a synchronous
        # stub so the DAD glue runs without real sockets or sleeps.
        acd_class = self.enterContext(
            patch("pytcp.runtime.packet_handler.Ip4Acd", autospec=True),
        )
        self._acd = cast(MagicMock, acd_class.return_value)
        self._acd.probe.side_effect = lambda *, address: AcdResult(success=True, address=address)

    # -- clock control ----------------------------------------------------

    def _set_monotonic(self, t: float) -> None:
        """
        Set the patched 'time.monotonic()' return value to 't'.
        """

        self._monotonic_t = t

    def _advance_monotonic(self, dt: float) -> None:
        """
        Advance the patched 'time.monotonic()' return value by
        'dt' seconds.
        """

        self._monotonic_t += dt

    # -- frame helpers ----------------------------------------------------

    @staticmethod
    def _build_arp_frame(
        *,
        ethernet_dst: MacAddress,
        ethernet_src: MacAddress,
        arp_oper: ArpOperation,
        arp_sha: MacAddress,
        arp_spa: Ip4Address,
        arp_tpa: Ip4Address,
        arp_tha: MacAddress = MAC__UNSPECIFIED,
    ) -> bytes:
        """
        Build a 42-byte Ethernet II + ARP wire frame from semantic
        kwargs. The Ethernet 'type' field is derived from the
        payload via 'EtherType.from_proto(ArpAssembler)'.

        For tests that need an unknown ArpOperation (which the
        TX-strict assembler refuses to emit on principle), use
        '_build_arp_frame_with_raw_oper' below.
        """

        return bytes(
            EthernetAssembler(
                ethernet__dst=ethernet_dst,
                ethernet__src=ethernet_src,
                ethernet__payload=ArpAssembler(
                    arp__oper=arp_oper,
                    arp__sha=arp_sha,
                    arp__spa=arp_spa,
                    arp__tha=arp_tha,
                    arp__tpa=arp_tpa,
                ),
            )
        )

    @staticmethod
    def _build_arp_frame_with_raw_oper(
        *,
        ethernet_dst: MacAddress,
        ethernet_src: MacAddress,
        arp_oper_raw: int,
        arp_sha: MacAddress,
        arp_spa: Ip4Address,
        arp_tpa: Ip4Address,
        arp_tha: MacAddress = MAC__UNSPECIFIED,
    ) -> bytes:
        """
        Build a 42-byte Ethernet II + ARP wire frame with a raw
        uint16 'oper' value bypassing the TX-strict
        ArpAssembler closed-set check.

        Used by parser sanity tests that drive an unknown
        ArpOperation through the RX path — the assembler refuses
        to construct such a frame on principle (RFC 826 /
        RFC 5494 §3), so the test builds the bytes directly.
        """

        # Ethernet II header (14 bytes) + ARP fixed payload (28 bytes).
        ether_hdr = bytes(ethernet_dst) + bytes(ethernet_src) + b"\x08\x06"
        arp_payload = (
            b"\x00\x01"  # hrtype: ETHERNET
            b"\x08\x00"  # prtype: IPv4
            b"\x06"  # hrlen
            b"\x04"  # prlen
            + arp_oper_raw.to_bytes(2)
            + bytes(arp_sha)
            + bytes(arp_spa)
            + bytes(arp_tha)
            + bytes(arp_tpa)
        )
        return ether_hdr + arp_payload

    def _drive_arp(
        self,
        *,
        ethernet_dst: MacAddress,
        ethernet_src: MacAddress,
        arp_oper: ArpOperation,
        arp_sha: MacAddress,
        arp_spa: Ip4Address,
        arp_tpa: Ip4Address,
        arp_tha: MacAddress = MAC__UNSPECIFIED,
    ) -> None:
        """
        Build an Ethernet+ARP frame from the given fields and drive
        it through the packet handler's '_phrx_ethernet' entry
        point — the same entry the production RX ring uses.
        """

        frame = self._build_arp_frame(
            ethernet_dst=ethernet_dst,
            ethernet_src=ethernet_src,
            arp_oper=arp_oper,
            arp_sha=arp_sha,
            arp_spa=arp_spa,
            arp_tpa=arp_tpa,
            arp_tha=arp_tha,
        )
        self._packet_handler._phrx_ethernet(PacketRx(frame))

    # -- DAD flow driver --------------------------------------------------

    def _drive_dad(
        self,
        *,
        probe_success: bool = True,
        conflict_mac: MacAddress | None = None,
    ) -> None:
        """
        Drive 'PacketHandlerL2._create_stack_ip4_addressing'
        synchronously over the mocked 'Ip4Acd' engine. With
        'probe_success=True' (the default) every candidate's probe
        comes back clean, so the path announces and installs it;
        with 'probe_success=False' the probe reports a conflict
        (peer 'conflict_mac'), so the candidate is neither announced
        nor installed. The engine's real RFC 5227 §2.1.1 / §2.3
        wire mechanics are pinned by the 'Ip4Acd' engine tests.
        """

        self._acd.probe.side_effect = lambda *, address: AcdResult(
            success=probe_success,
            address=address,
            conflict_mac=conflict_mac,
        )
        self._packet_handler._create_stack_ip4_addressing()
