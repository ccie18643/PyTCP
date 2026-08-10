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
Integration tests for the 'claim_ip6_address_async' 'on_conflict'
callback — the DAD-failure hook the DHCPv6 client (via the Address
API's DAD-checked 'add') registers to learn that a leased address is
a duplicate and must be DECLINEd (RFC 8415 §18.2.8).

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__dad_conflict_callback.py

ver 3.0.10
"""

import threading
from typing import override

from net_addr import Ip6Address, Ip6IfAddr
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

_CANDIDATE = Ip6Address("2001:db8:0:1::5")
_CANDIDATE_HOST = Ip6IfAddr("2001:db8:0:1::5/64")


class TestIcmp6Nd__DadConflictCallback(NdTestCase):
    """
    The 'claim_ip6_address_async' 'on_conflict' callback fires with
    the conflicting address on DAD failure, and stays silent on DAD
    success.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__dad_conflict_callback__fires_on_collision(self) -> None:
        """
        Ensure the 'on_conflict' callback is invoked with the
        conflicting address when DAD fails for a claimed host.

        Reference: RFC 8415 §18.2.8 (DECLINE a duplicate leased address).
        """

        conflicts: list[Ip6Address] = []

        def _on_conflict(address: Ip6Address) -> None:
            conflicts.append(address)

        def _trigger_conflict() -> None:
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE_HOST.address,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
                threading.Timer(0.005, _trigger_conflict).start()
                thread = self._packet_handler.claim_ip6_address_async(
                    ip6_host=_CANDIDATE_HOST,
                    on_conflict=_on_conflict,
                )
                thread.join(timeout=5.0)

        self.assertEqual(
            conflicts,
            [_CANDIDATE],
            msg="on_conflict must fire once with the conflicting address on DAD failure.",
        )

    def test__icmp6__nd__dad_conflict_callback__silent_on_success(self) -> None:
        """
        Ensure the 'on_conflict' callback is not invoked when DAD
        succeeds (no peer conflict during the probe window).

        Reference: RFC 8415 §18.2.8 (no DECLINE when the address is unique).
        """

        conflicts: list[Ip6Address] = []

        def _on_conflict(address: Ip6Address) -> None:
            conflicts.append(address)

        with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 10):
                thread = self._packet_handler.claim_ip6_address_async(
                    ip6_host=_CANDIDATE_HOST,
                    on_conflict=_on_conflict,
                )
                thread.join(timeout=5.0)

        self.assertEqual(conflicts, [], msg="on_conflict must stay silent when DAD succeeds.")
        self.assertIn(
            _CANDIDATE_HOST.address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="A successful DAD claim must install the address.",
        )
