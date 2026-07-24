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
Smoke tests for the 'ArpTestCase' integration-test harness. The
goal is to pin that '_build_arp_frame', '_drive_arp', the
'_set_monotonic' / '_advance_monotonic' clock controls, and
'_drive_dad' (clean and conflict probe outcomes) compose correctly so
the migrated 'test__arp__rx.py' / 'test__arp__tx.py' tests, the
DAD-flow tests at 'test__arp__dad.py', and the DEFEND_INTERVAL
tests at 'test__arp__defend_interval.py' can rely on the
harness shape.

pytcp/tests/integration/protocols/arp/test__arp__harness_smoke.py

ver 3.0.9
"""

from net_proto import ArpOperation, ArpParser
from net_proto.lib.packet_rx import PacketRx
from pytcp.tests.lib.arp_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    MAC__BROADCAST,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)


class TestArpHarnessSmoke(ArpTestCase):
    """
    Smoke tests for 'ArpTestCase'.
    """

    def test__arp__harness__build_arp_frame_emits_42_bytes(self) -> None:
        """
        Ensure '_build_arp_frame' emits exactly 42 bytes — the
        Ethernet II header (14) plus the fixed Ethernet/IPv4
        ARP header (28). Pins the wire-frame size every
        downstream fixture relies on.

        Reference: RFC 826 (28-byte Ethernet/IPv4 ARP header).
        """

        frame = self._build_arp_frame(
            ethernet_dst=MAC__BROADCAST,
            ethernet_src=HOST_A__MAC_ADDRESS,
            arp_oper=ArpOperation.REQUEST,
            arp_sha=HOST_A__MAC_ADDRESS,
            arp_spa=HOST_A__IP4_ADDRESS,
            arp_tpa=STACK__IP4_HOST.address,
        )

        self.assertEqual(
            len(frame),
            42,
            msg=f"Expected 42-byte Ethernet+ARP frame; got {len(frame)} bytes.",
        )

    def test__arp__harness__build_arp_frame_round_trips_through_parser(self) -> None:
        """
        Ensure a frame produced by '_build_arp_frame' is parsable
        by 'ArpParser' and the parsed fields match the kwargs.
        Pins the harness's wire format against the production
        parser.

        Reference: RFC 826 (foundational ARP wire format).
        """

        frame = self._build_arp_frame(
            ethernet_dst=MAC__BROADCAST,
            ethernet_src=HOST_A__MAC_ADDRESS,
            arp_oper=ArpOperation.REQUEST,
            arp_sha=HOST_A__MAC_ADDRESS,
            arp_spa=HOST_A__IP4_ADDRESS,
            arp_tpa=STACK__IP4_HOST.address,
        )

        packet_rx = PacketRx(frame[14:])  # skip Ethernet header
        ArpParser(packet_rx)

        self.assertEqual(
            packet_rx.arp.oper,
            ArpOperation.REQUEST,
            msg="Round-trip 'oper' must equal the kwarg.",
        )
        self.assertEqual(
            packet_rx.arp.sha,
            HOST_A__MAC_ADDRESS,
            msg="Round-trip 'sha' must equal the kwarg.",
        )
        self.assertEqual(
            packet_rx.arp.spa,
            HOST_A__IP4_ADDRESS,
            msg="Round-trip 'spa' must equal the kwarg.",
        )
        self.assertEqual(
            packet_rx.arp.tpa,
            STACK__IP4_HOST.address,
            msg="Round-trip 'tpa' must equal the kwarg.",
        )

    def test__arp__harness__drive_arp_request_for_stack_ip_emits_one_reply(self) -> None:
        """
        Ensure '_drive_arp' on a broadcast ARP Request for the
        stack IP causes exactly one ARP Reply frame to appear in
        '_frames_tx' — the harness contract for "RX in, captured
        TX out" via the live 'PacketHandlerL2._phrx_ethernet'
        entry.

        Reference: RFC 826 (Packet Reception — respond to Request for our IP).
        Reference: RFC 5227 §2.5 (continuing operation: respond to ARP Requests for our IPs).
        """

        self._drive_arp(
            ethernet_dst=MAC__BROADCAST,
            ethernet_src=HOST_A__MAC_ADDRESS,
            arp_oper=ArpOperation.REQUEST,
            arp_sha=HOST_A__MAC_ADDRESS,
            arp_spa=HOST_A__IP4_ADDRESS,
            arp_tpa=STACK__IP4_HOST.address,
        )

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"Expected exactly one TX frame for the Request; got {len(self._frames_tx)}.",
        )

    def test__arp__harness__set_and_advance_monotonic_round_trip(self) -> None:
        """
        Ensure '_set_monotonic' overwrites the patched clock and
        '_advance_monotonic' adds to it. The ARP-cache rate-limit
        tests depend on both helpers behaving as a plain settable /
        addable float.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._set_monotonic(1000.0)
        self.assertEqual(
            self._monotonic_t,
            1000.0,
            msg="'_set_monotonic' must set the patched clock value verbatim.",
        )

        self._advance_monotonic(5.5)
        self.assertEqual(
            self._monotonic_t,
            1005.5,
            msg="'_advance_monotonic' must add 'dt' to the patched clock value.",
        )

    def test__arp__harness__monotonic_patch_visible_to_arp_cache_module(self) -> None:
        """
        Ensure the patched 'time.monotonic' is observed by the
        production code path that consumes it — the
        'pytcp.lib.neighbor' module's ARP-cache 'find_entry'
        rate-limit. Without this, the cache rate-limit tests would
        silently exercise the real clock and become flaky /
        non-deterministic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp.lib import neighbor as neighbor_module

        self._set_monotonic(42.0)
        self.assertEqual(
            neighbor_module.time.monotonic(),  # type: ignore[attr-defined]  # deliberate clock-patch introspection
            42.0,
            msg=(
                "The clock visible to the ARP-cache rate-limit must equal the "
                "harness's patched value; otherwise the rate-limit tests are unreliable."
            ),
        )

    def test__arp__harness__drive_dad_clean_probe_installs_candidate(self) -> None:
        """
        Ensure '_drive_dad' (default clean probe) drives the
        static-host path over the mocked 'Ip4Acd' engine: it
        calls 'probe' then 'announce' for the candidate and
        installs it into '_ip4_ifaddr'. Pins the harness's
        engine-mock wiring against the production glue.

        Reference: RFC 5227 §2.1 (MUST probe before use).
        Reference: RFC 5227 §2.3 (MUST announce after probe).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        self._drive_dad()

        self._acd.probe.assert_called_once_with(address=candidate_address)
        self._acd.announce.assert_called_once_with(address=candidate_address)
        addresses = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            candidate_address,
            addresses,
            msg="A clean probe must install the candidate into '_ip4_ifaddr'.",
        )

    def test__arp__harness__drive_dad_conflict_suppresses_install(self) -> None:
        """
        Ensure '_drive_dad(probe_success=False)' makes the mocked
        engine report a conflict, so the static-host path neither
        announces nor installs the candidate. Pins the harness's
        conflict-outcome control against the production glue.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        self._drive_dad(probe_success=False, conflict_mac=HOST_A__MAC_ADDRESS)

        self._acd.announce.assert_not_called()
        addresses = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses,
            msg="A conflicted probe must NOT install the candidate into '_ip4_ifaddr'.",
        )

    def test__arp__harness__network_test_case_state_intact(self) -> None:
        """
        Ensure 'ArpTestCase.setUp' does not perturb the
        addresses, MAC, or candidate state inherited from
        'NetworkTestCase'. Migrated tests depend on the same
        baseline they got under the legacy harness.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._packet_handler._mac_unicast,
            STACK__MAC_ADDRESS,
            msg="Inherited stack MAC must be unchanged.",
        )
        addresses = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            STACK__IP4_HOST.address,
            addresses,
            msg="Inherited stack IPv4 host must be present in '_ip4_ifaddr'.",
        )
        candidate_addresses = {host.address for host in self._packet_handler._ip4_ifaddr_candidate}
        self.assertIn(
            STACK__IP4_HOST__CANDIDATE.address,
            candidate_addresses,
            msg="Inherited candidate IPv4 host must be present in '_ip4_ifaddr_candidate'.",
        )
