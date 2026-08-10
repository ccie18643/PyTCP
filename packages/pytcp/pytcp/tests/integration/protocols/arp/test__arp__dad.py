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
End-to-end DAD-flow integration tests for the static-host claim
sequence. Drive 'PacketHandlerL2._create_stack_ip4_addressing'
synchronously through 'ArpTestCase._drive_dad', with the
per-candidate 'Ip4Acd' engine mocked so the probe / announce / install
glue is exercised without real RFC 5227 timing. The RFC 5227 §2.1.1
Probe / §2.3 Announce wire mechanics themselves are pinned by the
'Ip4Acd' engine tests (test__ip4__acd_engine.py /
test__ip4__acd__conflict.py); these tests pin only what the static
path does with the engine's verdict.

pytcp/tests/integration/protocols/arp/test__arp__dad.py

ver 3.0.10
"""

from pytcp.tests.lib.arp_testcase import (
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    ArpTestCase,
)


class TestArpDad(ArpTestCase):
    """
    The static-host DAD claim-flow tests — the RFC 5227 §2.1 /
    §2.3 probe-then-claim glue around the 'Ip4Acd' engine. Drives
    'PacketHandlerL2._create_stack_ip4_addressing' synchronously and
    observes the resulting '_ip4_ifaddr' state and engine calls.
    """

    def test__arp__dad__clean_probe_admits_candidate(self) -> None:
        """
        Ensure the static-host path admits the candidate IP to
        '_ip4_ifaddr' and drains the candidate list when the
        engine reports a clean probe.

        Reference: RFC 5227 §2.1 (MUST probe before use).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address
        addresses_before = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_before,
            msg="Pre-condition: candidate IP must not already be in '_ip4_ifaddr'.",
        )

        self._drive_dad()

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            candidate_address,
            addresses_after,
            msg="Candidate IP must be admitted to '_ip4_ifaddr' once the probe comes back clean.",
        )
        self.assertEqual(
            self._packet_handler._ip4_ifaddr_candidate,
            [],
            msg="'_ip4_ifaddr_candidate' must be drained once each candidate has been resolved.",
        )

    def test__arp__dad__clean_probe_announces_before_install(self) -> None:
        """
        Ensure a clean probe is followed by the gratuitous-ARP
        Announcement: the static path calls 'Ip4Acd.probe' then
        'Ip4Acd.announce' for the candidate it admits.

        Reference: RFC 5227 §2.3 (MUST announce after probe).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        self._drive_dad()

        self._acd.probe.assert_called_once_with(address=candidate_address)
        self._acd.announce.assert_called_once_with(address=candidate_address)

    def test__arp__dad__probe_conflict_aborts_claim(self) -> None:
        """
        Ensure a probe conflict reported by the engine prevents
        admission to '_ip4_ifaddr' and suppresses the §2.3
        Announcement — the static host yields the address rather
        than claiming a defended duplicate.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        self._drive_dad(probe_success=False, conflict_mac=HOST_A__MAC_ADDRESS)

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg="Candidate IP must NOT be admitted to '_ip4_ifaddr' when the probe reports a conflict.",
        )
        self.assertEqual(
            self._packet_handler._ip4_ifaddr_candidate,
            [],
            msg="A conflicted candidate must still be drained from the candidate list.",
        )
        self._acd.announce.assert_not_called()

    def test__arp__dad__candidate_already_in_ip4_host_unchanged(self) -> None:
        """
        Ensure DAD does not displace already-claimed addresses
        from '_ip4_ifaddr' regardless of probe outcome — the
        non-candidate stack IP set up by 'NetworkTestCase' must
        still be present after the static path runs.

        Reference: RFC 5227 §2.1 (probe scope is candidates only).
        """

        existing_address = STACK__IP4_HOST.address

        self._drive_dad()

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            existing_address,
            addresses_after,
            msg=(
                "Pre-existing stack IPs must remain in '_ip4_ifaddr' across the "
                "static-host run; only candidates participate in the probe loop."
            ),
        )

    def test__arp__dad__no_ongoing_defender_held(self) -> None:
        """
        Ensure a statically claimed address gets probe + announce
        only and NO ongoing §2.4 defender — matching a bare Linux
        'ip addr add', where ongoing conflict defense is a managing
        daemon's job, not part of static assignment. The engine's
        'claim' / 'poll_conflict' / 'defend' lifecycle is never
        entered for a static host.

        Reference: RFC 5227 §2.4 (ongoing defense is the address manager's role).
        """

        self._drive_dad()

        self._acd.claim.assert_not_called()
        self._acd.poll_conflict.assert_not_called()
        self._acd.defend.assert_not_called()

    def test__arp__dad__disables_ip4_when_no_address_claimed(self) -> None:
        """
        Ensure IPv4 support is turned off when the only static
        candidate loses its probe and DHCP is not running — the
        stack has no usable IPv4 address to listen on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._ip4_ifaddr = []
        self._packet_handler._ip4_ifaddr_candidate = [STACK__IP4_HOST__CANDIDATE]
        self._packet_handler._ip4_dhcp = False
        self._packet_handler._ip4_support = True

        self._drive_dad(probe_success=False, conflict_mac=HOST_A__MAC_ADDRESS)

        self.assertFalse(
            self._packet_handler._ip4_support,
            msg="IPv4 support must be disabled when no static address could be claimed and DHCP is off.",
        )
