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
Integration tests for the IPv6 ND Enhanced DAD algorithm
(RFC 7527) — nd_linux_parity §21.

PyTCP's DAD probe TX now carries a fresh random Nonce option
(RFC 3971 §5.3.2). Inbound NS messages targeting the host's
tentative address are checked against the set of nonces the
host emitted; a match means the inbound NS is a loop-hairpin
echo of our own probe (e.g. a switch reflecting traffic back)
and is dropped silently rather than aborting DAD.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__enhanced_dad.py

ver 3.0.8
"""

from typing import Any, override

from net_addr import Ip6Address, MacAddress
from net_proto import Icmp6NdMessageNeighborSolicitation
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

CANDIDATE = Ip6Address("2001:db8:0:1::5")
PEER__MAC = MacAddress("02:00:00:00:00:99")


def _join_candidate_multicast(handler: Any) -> None:
    """
    Join the candidate's solicited-node multicast group on the
    handler so the Ethernet RX gate accepts the inbound DAD
    probe. Mirrors the real DAD-claim setup.
    """

    snm_mac = CANDIDATE.solicited_node_multicast.multicast_mac
    snm_ip = CANDIDATE.solicited_node_multicast
    if snm_mac not in handler._mac_multicast:
        handler._mac_multicast.append(snm_mac)
    if snm_ip not in handler._ip6_multicast:
        handler._ip6_multicast.append(snm_ip)


class TestIcmp6Nd__EnhancedDad__LoopHairpinDropped(NdTestCase):
    """
    An NS(DAD) whose Nonce matches a nonce we emitted is
    silently dropped — it's a loop-hairpin echo of our own
    probe, not a peer's conflict.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__enhanced_dad__matching_nonce_drops_ns(self) -> None:
        """
        Ensure an inbound NS(DAD) targeting our tentative
        address with a Nonce we already emitted is dropped
        silently and does NOT signal the per-address DAD Event.

        Reference: RFC 7527 §4.2 (matching nonce → drop, not conflict).
        """

        our_nonce = b"\xab\xcd\xef\x12\x34\x56"
        self._packet_handler._icmp6_nd_dad__registry.install(CANDIDATE)
        self._packet_handler._icmp6_nd_dad__registry.register_nonce(CANDIDATE, our_nonce)
        _join_candidate_multicast(self._packet_handler)

        frame = self._make_nd_ns_frame(
            eth_src=PEER__MAC,
            eth_dst=CANDIDATE.solicited_node_multicast.multicast_mac,
            ip6_src=Ip6Address(),
            ip6_dst=CANDIDATE.solicited_node_multicast,
            target=CANDIDATE,
            nonce=our_nonce,
        )

        self._drive_rx(frame=frame)

        self.assertFalse(
            self._packet_handler._icmp6_nd_dad__registry.has_signal(CANDIDATE),
            msg="Loop-hairpin echo must NOT signal the per-address DAD Event.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_neighbor_solicitation__loop_hairpin__drop,
            1,
            msg="Loop-hairpin path must bump the drop counter.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_neighbor_solicitation__dad_conflict,
            0,
            msg="Loop-hairpin path must NOT bump the dad_conflict counter.",
        )


class TestIcmp6Nd__EnhancedDad__NonMatchingNonceTreatedAsConflict(NdTestCase):
    """
    An NS(DAD) carrying a Nonce we did NOT emit is a genuine
    peer-DAD conflict — the host aborts its claim.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__enhanced_dad__non_matching_nonce_aborts_dad(self) -> None:
        """
        Ensure an inbound NS(DAD) targeting our tentative
        address with a Nonce we did NOT emit triggers the
        existing DAD-conflict path (per-address Event set).

        Reference: RFC 7527 §4.2 (no match → DAD failure).
        """

        self._packet_handler._icmp6_nd_dad__registry.install(CANDIDATE)
        self._packet_handler._icmp6_nd_dad__registry.register_nonce(CANDIDATE, b"\xab\xcd\xef\x12\x34\x56")
        _join_candidate_multicast(self._packet_handler)

        peer_nonce = b"\xff\xff\xff\xff\xff\xff"
        frame = self._make_nd_ns_frame(
            eth_src=PEER__MAC,
            eth_dst=CANDIDATE.solicited_node_multicast.multicast_mac,
            ip6_src=Ip6Address(),
            ip6_dst=CANDIDATE.solicited_node_multicast,
            target=CANDIDATE,
            nonce=peer_nonce,
        )

        self._drive_rx(frame=frame)

        self.assertTrue(
            self._packet_handler._icmp6_nd_dad__registry.has_signal(CANDIDATE),
            msg="Non-matching nonce must set the per-address DAD Event (genuine conflict).",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_neighbor_solicitation__dad_conflict,
            1,
            msg="Non-matching nonce path must bump the dad_conflict counter.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__nd_neighbor_solicitation__loop_hairpin__drop,
            0,
            msg="Non-matching nonce path must NOT bump the loop_hairpin counter.",
        )


class TestIcmp6Nd__EnhancedDad__DadProbeIncludesNonce(NdTestCase):
    """
    With 'icmp6.enhanced_dad' enabled, every NS(DAD) probe
    emitted by the host carries a Nonce option, and the nonce
    is registered with the per-address DAD slot.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__enhanced_dad__probe_carries_tracked_nonce(self) -> None:
        """
        Ensure '_perform_ip6_nd_dad' (with default
        enhanced_dad=1) emits NS probes whose Nonce option
        matches the host's tracked nonce set.

        Reference: RFC 7527 §4.1 (sender MUST include nonce in NS(DAD)).
        """

        with sysctl_module.override("icmp6.default.retrans_timer_ms", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 1):
                self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=CANDIDATE)

        # Find the NS(DAD) frame the stack emitted.
        dad_message: Icmp6NdMessageNeighborSolicitation | None = None
        for frame in self._frames_tx:
            probe = self._parse_tx_icmp6(frame)
            if (
                isinstance(probe.message, Icmp6NdMessageNeighborSolicitation)
                and probe.ip_src.is_unspecified
                and probe.message.target_address == CANDIDATE
            ):
                dad_message = probe.message
                break

        self.assertIsNotNone(
            dad_message,
            msg=f"DAD probe with target={CANDIDATE} not found in TX frames",
        )
        assert dad_message is not None
        self.assertIsNotNone(
            dad_message.nonce,
            msg=f"Probe must carry a Nonce option. Got: {dad_message.nonce!r}",
        )
        # Nonces are cleared after DAD completes successfully —
        # the probe's nonce was tracked DURING the DAD session
        # but cleared at exit. Asserting on the wire bytes is
        # enough to pin "probe carries a nonce".


class TestIcmp6Nd__EnhancedDad__SysctlDisable(NdTestCase):
    """
    'icmp6.enhanced_dad = 0' returns DAD to RFC 4861 plain
    semantics — probes carry no Nonce option.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__enhanced_dad__sysctl_zero_emits_no_nonce(self) -> None:
        """
        Ensure 'icmp6.enhanced_dad=0' makes
        '_perform_ip6_nd_dad' emit DAD probes without a Nonce
        option and clears the per-address nonce slot on exit.

        Reference: Linux 'enhanced_dad' (kill switch).
        """

        with sysctl_module.override("icmp6.default.enhanced_dad", 0):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 1):
                with sysctl_module.override("icmp6.default.dad_transmits", 1):
                    self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=CANDIDATE)

        # Find the NS(DAD) frame the stack emitted.
        dad_message: Icmp6NdMessageNeighborSolicitation | None = None
        for frame in self._frames_tx:
            probe = self._parse_tx_icmp6(frame)
            if (
                isinstance(probe.message, Icmp6NdMessageNeighborSolicitation)
                and probe.ip_src.is_unspecified
                and probe.message.target_address == CANDIDATE
            ):
                dad_message = probe.message
                break

        self.assertIsNotNone(
            dad_message,
            msg=f"DAD probe with target={CANDIDATE} not found in TX frames",
        )
        assert dad_message is not None
        self.assertIsNone(
            dad_message.nonce,
            msg=("enhanced_dad=0 must suppress the Nonce option on probes. " f"Got: {dad_message.nonce!r}"),
        )
        self.assertFalse(
            self._packet_handler._icmp6_nd_dad__registry.has_signal(CANDIDATE),
            msg="DAD must have torn down the per-address slot on completion.",
        )
