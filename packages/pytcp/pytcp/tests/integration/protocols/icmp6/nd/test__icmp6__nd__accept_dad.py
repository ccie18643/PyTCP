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
Integration tests for the 'icmp6.accept_dad' sysctl —
nd_linux_parity §20.4.

Linux exposes 'net.ipv6.conf.<iface>.accept_dad' as a tristate:
  0 = skip DAD entirely (no probes; address goes straight to
      VALID).
  1 = normal DAD (default). Failure removes the candidate
      from the host's address list.
  2 = strict DAD. Any DAD failure additionally disables IPv6
      on the interface ('_ip6_support = False'). Used by
      paranoid deployments where conflicting addresses are
      treated as a security incident.

PyTCP mirrors the tristate. The =0 short-circuit lives at
the top of '_perform_ip6_nd_dad'; the =2 disable-on-failure
lives in the async claim worker.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__accept_dad.py

ver 3.0.9
"""

import threading
import time
from typing import override

from net_addr import Ip6Address, Ip6IfAddr
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

_CANDIDATE = Ip6Address("2001:db8:0:1::5")
_CANDIDATE_HOST = Ip6IfAddr("2001:db8:0:1::5/64")


class TestIcmp6Nd__AcceptDad__SysctlRegistration(NdTestCase):
    """
    'icmp6.accept_dad' is registered with default 1 (normal
    DAD, Linux parity); validator accepts the tristate
    {0, 1, 2}.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__accept_dad__default_one(self) -> None:
        """
        Ensure 'icmp6.accept_dad' defaults to 1 (normal DAD).

        Reference: Linux 'net.ipv6.conf.<iface>.accept_dad' default.
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.accept_dad"),
            1,
            msg="Default must be 1 (normal DAD).",
        )

    def test__icmp6__nd__accept_dad__validator_accepts_tristate(self) -> None:
        """
        Ensure validator admits the tristate {0, 1, 2}.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (0, 1, 2):
            sysctl_module.set("icmp6.default.accept_dad", value)
            self.assertEqual(sysctl_module.get("icmp6.default.accept_dad"), value)

    def test__icmp6__nd__accept_dad__validator_rejects_three(self) -> None:
        """
        Ensure values outside {0, 1, 2} are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.accept_dad", 3)

    def test__icmp6__nd__accept_dad__validator_rejects_bool(self) -> None:
        """
        Ensure boolean values are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.accept_dad", True)


class TestIcmp6Nd__AcceptDad__ZeroSkipsDad(NdTestCase):
    """
    With 'accept_dad=0' '_perform_ip6_nd_dad' short-circuits:
    no probes are sent, no initial delay is taken, the
    candidate state is set to VALID, and the function
    returns True.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__accept_dad__zero_returns_true_no_probes(self) -> None:
        """
        Ensure 'accept_dad=0' makes '_perform_ip6_nd_dad'
        return True without emitting any DAD probe frames.

        Reference: Linux 'accept_dad=0' (skip DAD).
        """

        before_tx = len(self._frames_tx)

        with sysctl_module.override("icmp6.default.accept_dad", 0):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                ok = self._packet_handler._perform_ip6_nd_dad(ip6_unicast_candidate=_CANDIDATE)

        self.assertTrue(ok, msg="accept_dad=0 must short-circuit DAD as success.")
        # No TX frames — neither probes nor gratuitous NA.
        self.assertEqual(
            len(self._frames_tx),
            before_tx,
            msg=f"accept_dad=0 must not emit any TX frames. New: {self._frames_tx[before_tx:]!r}",
        )


class TestIcmp6Nd__AcceptDad__TwoDisablesIp6OnFailure(NdTestCase):
    """
    With 'accept_dad=2' a DAD failure disables IPv6 on the
    interface ('_ip6_support = False'). The async-claim
    worker is the hook point.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__accept_dad__two_disables_ipv6_on_collision(self) -> None:
        """
        Ensure a DAD failure with 'accept_dad=2' flips
        '_ip6_support' to False — the interface-wide IPv6
        kill switch.

        Reference: Linux 'accept_dad=2' fail-hard semantics.
        """

        # Trigger DAD failure mid-loop.
        def _trigger_conflict() -> None:
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE_HOST.address,
                peer_info=None,
                inbound_nonce=None,
            )

        self.assertTrue(
            self._packet_handler._ip6_support,
            msg="Pre-condition: _ip6_support must be True before the test.",
        )

        with sysctl_module.override("icmp6.default.accept_dad", 2):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
                    threading.Timer(0.005, _trigger_conflict).start()
                    thread = self._packet_handler.claim_ip6_address_async(ip6_host=_CANDIDATE_HOST)
                    thread.join(timeout=5.0)

        self.assertFalse(
            self._packet_handler._ip6_support,
            msg="accept_dad=2 + DAD failure must flip _ip6_support to False.",
        )
        self.assertNotIn(
            _CANDIDATE_HOST.address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="DAD failure must still remove the address from _ip6_ifaddr.",
        )

    def test__icmp6__nd__accept_dad__one_does_not_disable_ipv6(self) -> None:
        """
        Ensure with the default 'accept_dad=1' a DAD failure
        does NOT flip '_ip6_support' (regression check).

        Reference: Linux 'accept_dad=1' (standard DAD).
        """

        def _trigger_conflict() -> None:
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE_HOST.address,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
                threading.Timer(0.005, _trigger_conflict).start()
                thread = self._packet_handler.claim_ip6_address_async(ip6_host=_CANDIDATE_HOST)
                thread.join(timeout=5.0)

        self.assertTrue(
            self._packet_handler._ip6_support,
            msg="accept_dad=1 + DAD failure must leave _ip6_support True.",
        )

    def test__icmp6__nd__accept_dad__two_no_effect_on_success(self) -> None:
        """
        Ensure with 'accept_dad=2' a SUCCESSFUL DAD does NOT
        flip '_ip6_support' — the disable-on-failure rule
        only fires on failure.

        Reference: Linux 'accept_dad=2' (failure-only side effect).
        """

        with sysctl_module.override("icmp6.default.accept_dad", 2):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                with sysctl_module.override("icmp6.default.dad_transmits", 0):
                    thread = self._packet_handler.claim_ip6_address_async(ip6_host=_CANDIDATE_HOST)
                    thread.join(timeout=5.0)

        self.assertTrue(
            self._packet_handler._ip6_support,
            msg="accept_dad=2 + DAD success must leave _ip6_support True.",
        )
        # Address must be in _ip6_ifaddr (DAD passed).
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if _CANDIDATE_HOST.address in [h.address for h in self._packet_handler._ip6_ifaddr]:
                break
            time.sleep(0.005)
        self.assertIn(
            _CANDIDATE_HOST.address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="Successful DAD with accept_dad=2 must still install the address.",
        )
