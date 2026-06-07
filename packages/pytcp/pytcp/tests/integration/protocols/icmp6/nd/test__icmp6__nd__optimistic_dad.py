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
Integration tests for the IPv6 ND Optimistic Duplicate Address
Detection algorithm (RFC 4429) — nd_linux_parity §20.

When 'icmp6.optimistic_dad = 1' the host installs a tentative
address into '_ip6_ifaddr' as OPTIMISTIC immediately rather than
waiting for DAD to pass. The address is usable as outbound
source during the DAD probe period; Neighbor Advertisements
emitted while OPTIMISTIC clear the Override flag per §3.3 so
peers don't overwrite an existing cache entry on the basis of
an unverified address. On DAD success the state transitions to
VALID; on collision the optimistic entry is removed.

When 'icmp6.optimistic_dad = 0' (the default) PyTCP retains the
RFC 4862 §5.4 strict semantics: the address stays out of
'_ip6_ifaddr' until DAD passes; the state map records a TENTATIVE
entry only for the duration of the wait.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__optimistic_dad.py

ver 3.0.8
"""

import threading
from typing import override

from net_addr import Ip6Address, Ip6IfAddr
from net_proto import (
    EthernetParser,
    EtherType,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DadState
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import HOST_A__MAC_ADDRESS

_CANDIDATE_HOST = Ip6IfAddr("2001:db8:0:1::5/64")
_CANDIDATE = _CANDIDATE_HOST.address


def _last_na_flag_o(frames: list[bytes]) -> bool | None:
    """
    Inspect 'frames' (most-recent first) and return 'flag_o' on
    the first Neighbor Advertisement found, or None if no NA was
    emitted in the captured TX stream.
    """

    for frame in reversed(frames):
        prx = PacketRx(frame)
        EthernetParser(prx)
        if prx.ethernet.type is not EtherType.IP6:
            continue
        Ip6Parser(prx)
        Icmp6Parser(prx)
        msg = prx.icmp6.message
        if isinstance(msg, Icmp6NdMessageNeighborAdvertisement):
            return msg.flag_o
    return None


class TestIcmp6Nd__OptimisticDad__SysctlRegistration(NdTestCase):
    """
    The 'icmp6.optimistic_dad' sysctl is registered with default
    0 (off, matching Linux 'net.ipv6.conf.<iface>.optimistic_dad')
    and the validator rejects values outside {0, 1} including
    booleans.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__optimistic_dad__sysctl_default_zero(self) -> None:
        """
        Ensure the 'icmp6.optimistic_dad' sysctl is registered
        with the default value 0 (Optimistic DAD is opt-in).

        Reference: RFC 4429 §3.1 (host MAY use Optimistic DAD).
        Reference: RFC 8504 §6.3 (RFC 4429 remains optional).
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.optimistic_dad"),
            0,
            msg="'icmp6.optimistic_dad' must default to 0 (off).",
        )

    def test__icmp6__nd__optimistic_dad__sysctl_validator_rejects_two(self) -> None:
        """
        Ensure values outside {0, 1} are rejected by the
        validator.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.optimistic_dad", 2)

    def test__icmp6__nd__optimistic_dad__sysctl_validator_rejects_bool(self) -> None:
        """
        Ensure booleans are rejected even though Python admits
        'isinstance(True, int)'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.optimistic_dad", True)


class TestIcmp6Nd__OptimisticDad__StateAccessorUnknown(NdTestCase):
    """
    The state accessor returns None for an address with no
    DAD activity recorded.
    """

    def test__icmp6__nd__optimistic_dad__state_unknown_returns_none(self) -> None:
        """
        Ensure 'get_icmp6_dad_state' returns None for an
        address that has never been in DAD.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            self._packet_handler.get_icmp6_dad_state(address=Ip6Address("2001:db8::1234")),
            msg="Unknown address must yield None state.",
        )


class TestIcmp6Nd__OptimisticDad__SyncDad__StateLifecycle(NdTestCase):
    """
    With 'icmp6.optimistic_dad = 0' (default), '_perform_ip6_nd_dad'
    records TENTATIVE during the wait and transitions to VALID on
    success. The address is NOT installed into '_ip6_ifaddr' until
    after DAD passes.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__optimistic_dad__sync_state_valid_after_success(self) -> None:
        """
        Ensure the post-DAD state for a successful synchronous
        claim is VALID.

        Reference: RFC 4862 §5.4 (DAD passes → address VALID).
        """

        with sysctl_module.override("icmp6.default.retrans_timer_ms", 10):
            self.assertTrue(
                self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE),
                msg="Without a conflict, sync DAD must succeed.",
            )

        self.assertEqual(
            self._packet_handler.get_icmp6_dad_state(address=_CANDIDATE),
            Icmp6DadState.VALID,
            msg="Successful synchronous DAD must mark the address VALID.",
        )

    def test__icmp6__nd__optimistic_dad__sync_state_cleared_after_conflict(self) -> None:
        """
        Ensure a synchronous DAD failure clears the per-address
        state entry (the candidate is rejected, not parked in
        FAILED state).

        Reference: RFC 4862 §5.4.5 (duplicate detected → claim aborted).
        """

        def _trigger_conflict() -> None:
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
            threading.Timer(0.005, _trigger_conflict).start()
            self.assertFalse(
                self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE),
                msg="Released conflict event must mark sync DAD as failed.",
            )

        self.assertIsNone(
            self._packet_handler.get_icmp6_dad_state(address=_CANDIDATE),
            msg="Failed sync DAD must clear the per-address state entry.",
        )


class TestIcmp6Nd__OptimisticDad__OptimisticPath__PreClaim(NdTestCase):
    """
    With 'icmp6.optimistic_dad = 1', the candidate address is
    installed into '_ip6_ifaddr' as OPTIMISTIC BEFORE the DAD
    probe wait — so the address is usable as outbound source
    during the wait per RFC 4429 §3.3.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__optimistic_dad__optimistic_in_ip6_host_during_wait(self) -> None:
        """
        Ensure the candidate is in '_ip6_ifaddr' and marked
        OPTIMISTIC while the DAD wait is still running.

        Reference: RFC 4429 §3.3 (Optimistic Tentative Address usable
        during DAD).
        """

        captured: dict[str, object] = {}

        def _trigger_conflict() -> None:
            captured["addresses_during_wait"] = [host.address for host in self._packet_handler._ip6_ifaddr]
            captured["state_during_wait"] = self._packet_handler.get_icmp6_dad_state(address=_CANDIDATE)
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.optimistic_dad", 1):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
                threading.Timer(0.010, _trigger_conflict).start()
                self._packet_handler._claim_ip6_address_optimistic(ip6_host=_CANDIDATE_HOST)

        self.assertIn(
            _CANDIDATE,
            captured["addresses_during_wait"],  # type: ignore[arg-type]
            msg="Optimistic DAD must install the candidate before the wait.",
        )
        self.assertEqual(
            captured["state_during_wait"],
            Icmp6DadState.OPTIMISTIC,
            msg="State during wait must be OPTIMISTIC.",
        )

    def test__icmp6__nd__optimistic_dad__valid_and_assigned_after_success(self) -> None:
        """
        Ensure a successful Optimistic DAD claim transitions
        the state from OPTIMISTIC to VALID and leaves the
        address in '_ip6_ifaddr'.

        Reference: RFC 4429 §3.3 step 4 (DAD success → no Override
        flag suppression, address VALID).
        """

        with sysctl_module.override("icmp6.default.optimistic_dad", 1):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 10):
                self._packet_handler._claim_ip6_address_optimistic(ip6_host=_CANDIDATE_HOST)

        self.assertEqual(
            self._packet_handler.get_icmp6_dad_state(address=_CANDIDATE),
            Icmp6DadState.VALID,
            msg="Successful Optimistic DAD must transition state to VALID.",
        )
        self.assertIn(
            _CANDIDATE,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="Successful Optimistic DAD must keep the address in _ip6_ifaddr.",
        )

    def test__icmp6__nd__optimistic_dad__removed_on_conflict(self) -> None:
        """
        Ensure a failed Optimistic DAD claim removes the
        pre-claimed address from '_ip6_ifaddr' and clears the
        per-address state entry.

        Reference: RFC 4429 §3.3 (DAD failure must remove the
        Optimistic Tentative Address).
        """

        def _trigger_conflict() -> None:
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.optimistic_dad", 1):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
                threading.Timer(0.005, _trigger_conflict).start()
                self._packet_handler._claim_ip6_address_optimistic(ip6_host=_CANDIDATE_HOST)

        self.assertNotIn(
            _CANDIDATE,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="Failed Optimistic DAD must remove the address from _ip6_ifaddr.",
        )
        self.assertIsNone(
            self._packet_handler.get_icmp6_dad_state(address=_CANDIDATE),
            msg="Failed Optimistic DAD must clear the per-address state entry.",
        )


class TestIcmp6Nd__OptimisticDad__NaOverrideFlag(NdTestCase):
    """
    NAs emitted when our address is OPTIMISTIC must clear the
    Override (O) flag per RFC 4429 §3.3 so peers don't overwrite
    an existing cache entry on the basis of an unverified
    address. NAs emitted from a VALID address keep the caller-
    requested flag (regression check). The wire-form chosen here
    is a DAD-probe NS (src=:: → dst=solicited-node-multicast)
    because PyTCP's NS-RX handler asks for flag_o=True on that
    branch — so the Override-suppression is observable as a
    differential between OPTIMISTIC and VALID source state.
    """

    @override
    def setUp(self) -> None:
        """
        Install the candidate as a regular '_ip6_ifaddr' entry
        and prepare the solicited-node multicast group so the
        Ethernet RX gate accepts an inbound NS for the candidate.
        """

        super().setUp()
        self._packet_handler._ip6_ifaddr.append(_CANDIDATE_HOST)
        snm_mac = _CANDIDATE.solicited_node_multicast.multicast_mac
        snm_ip = _CANDIDATE.solicited_node_multicast
        if snm_mac not in self._packet_handler._mac_multicast:
            self._packet_handler._mac_multicast.append(snm_mac)
        if snm_ip not in self._packet_handler._ip6_multicast:
            self._packet_handler._ip6_multicast.append(snm_ip)

    def test__icmp6__nd__optimistic_dad__na_clears_override_for_optimistic(self) -> None:
        """
        Ensure an NA emitted in response to an inbound DAD-form
        NS targeting an OPTIMISTIC address has the Override flag
        cleared even though the RX handler requested flag_o=True.

        Reference: RFC 4429 §3.3 (Override flag SHOULD be cleared
        for Optimistic addresses).
        """

        self._packet_handler._icmp6_dad__states[_CANDIDATE] = Icmp6DadState.OPTIMISTIC

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=_CANDIDATE.solicited_node_multicast.multicast_mac,
            ip6_src=Ip6Address("::"),
            ip6_dst=_CANDIDATE.solicited_node_multicast,
            target=_CANDIDATE,
            slla=None,
        )

        emitted = self._drive_rx(frame=frame)

        flag_o = _last_na_flag_o(emitted)
        self.assertIsNotNone(flag_o, msg="An NA must be emitted in response to the NS.")
        self.assertFalse(
            flag_o,
            msg="OPTIMISTIC source address must clear the NA Override flag.",
        )

    def test__icmp6__nd__optimistic_dad__na_keeps_override_for_valid(self) -> None:
        """
        Ensure an NA emitted in response to an inbound DAD-form
        NS targeting a VALID address keeps the caller-requested
        Override flag (regression check).

        Reference: RFC 4861 §4.4 (NA flag semantics for non-OPTIMISTIC
        addresses).
        """

        self._packet_handler._icmp6_dad__states[_CANDIDATE] = Icmp6DadState.VALID

        frame = self._make_nd_ns_frame(
            eth_src=HOST_A__MAC_ADDRESS,
            eth_dst=_CANDIDATE.solicited_node_multicast.multicast_mac,
            ip6_src=Ip6Address("::"),
            ip6_dst=_CANDIDATE.solicited_node_multicast,
            target=_CANDIDATE,
            slla=None,
        )

        emitted = self._drive_rx(frame=frame)

        flag_o = _last_na_flag_o(emitted)
        self.assertIsNotNone(flag_o, msg="An NA must be emitted in response to the NS.")
        self.assertTrue(
            flag_o,
            msg="VALID source address must keep the caller-requested Override flag.",
        )


class TestIcmp6Nd__OptimisticDad__SysctlOff__NoPreClaim(NdTestCase):
    """
    With 'icmp6.optimistic_dad = 0' (default) the address is NOT
    installed into '_ip6_ifaddr' before DAD completes — RFC 4862
    §5.4 strict semantics.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__optimistic_dad__off_no_pre_claim(self) -> None:
        """
        Ensure the candidate is NOT in '_ip6_ifaddr' while
        synchronous DAD is in flight when the sysctl is off.

        Reference: RFC 4862 §5.4 (default DAD: address tentative
        until claim succeeds).
        """

        captured: dict[str, object] = {}

        def _trigger_conflict() -> None:
            captured["addresses_during_wait"] = [host.address for host in self._packet_handler._ip6_ifaddr]
            captured["state_during_wait"] = self._packet_handler.get_icmp6_dad_state(address=_CANDIDATE)
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
            threading.Timer(0.010, _trigger_conflict).start()
            self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE)

        self.assertNotIn(
            _CANDIDATE,
            captured["addresses_during_wait"],  # type: ignore[arg-type]
            msg="Sync DAD with optimistic_dad=0 must NOT install the address before completion.",
        )
        self.assertEqual(
            captured["state_during_wait"],
            Icmp6DadState.TENTATIVE,
            msg="Sync DAD with optimistic_dad=0 must mark the address TENTATIVE during the wait.",
        )
