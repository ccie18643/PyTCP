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
Integration tests for the RFC 6724 default source-address
selection rule 7 (prefer temporary addresses).

Exercises 'Ip6TxHandler._select_ip6_source' in the presence
of '_icmp6_temp_addresses' under the three values of the
'icmp6.use_tempaddr' sysctl: 0 (disabled), 1 (enabled, no
preference), 2 (enabled, prefer temporary).

pytcp/tests/integration/protocols/ip6/test__ip6__rfc6724_source_selection_rule_7.py

ver 3.0.10
"""

import time
from typing import override

from net_addr import Ip6Address, Ip6IfAddr, Ip6Network
from pytcp.protocols.icmp6.nd.nd__router_state import (
    Icmp6SlaacAddress,
    Icmp6TempAddress,
)
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.ip6_testcase import Ip6TestCase

# Two stable SLAAC hosts on adjacent /64s plus a temporary
# address derived from each prefix. The temp addresses have
# obviously different IIDs from the stable addresses so the
# selector outcome is unambiguously visible in the assertion.
_HOST_STABLE_A = Ip6IfAddr("2001:db8:0:1::7/64")
_HOST_STABLE_B = Ip6IfAddr("2001:db8:0:2::7/64")
_HOST_TEMP_A = Ip6IfAddr("2001:db8:0:1::abcd:1/64")
_HOST_TEMP_B = Ip6IfAddr("2001:db8:0:2::abcd:2/64")

_PREFIX_A = Ip6Network("2001:db8:0:1::/64")
_PREFIX_B = Ip6Network("2001:db8:0:2::/64")
_ROUTER = Ip6Address("fe80::1")

_DST_IN_A = Ip6Address("2001:db8:0:1::99")
_DST_IN_B = Ip6Address("2001:db8:0:2::99")


def _slaac(host: Ip6IfAddr, prefix: Ip6Network, *, deprecated: bool = False) -> Icmp6SlaacAddress:
    """
    Build an 'Icmp6SlaacAddress' record placing the host in either
    the PREFERRED or DEPRECATED state at 'time.monotonic()' now.
    """

    now = time.monotonic()
    return Icmp6SlaacAddress(
        address=host.address,
        prefix=prefix,
        preferred_until=now - 1.0 if deprecated else now + 3600.0,
        valid_until=now + 7200.0,
        router_address=_ROUTER,
    )


def _temp(host: Ip6IfAddr, prefix: Ip6Network, *, deprecated: bool = False) -> Icmp6TempAddress:
    """
    Build an 'Icmp6TempAddress' record. RFC 8981 temp addresses
    use the same PREFERRED/DEPRECATED semantics as their stable
    siblings — encoded here by shifting the preferred_until
    deadline.
    """

    now = time.monotonic()
    return Icmp6TempAddress(
        address=host.address,
        prefix=prefix,
        preferred_until=now - 1.0 if deprecated else now + 3600.0,
        valid_until=now + 7200.0,
        created_at=now,
        router_address=_ROUTER,
    )


class TestRfc6724Rule7TempPreferenceEnabled(Ip6TestCase):
    """
    The 'icmp6.use_tempaddr=2' rule-7 preference tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides do not
        leak across tests.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__ip6__rfc6724_rule7__prefer_temp_when_both_in_dst_prefix(self) -> None:
        """
        Ensure a temp address is preferred over a stable address
        when both are in the destination's prefix and the
        'use_tempaddr' policy says to prefer temp — the headline
        privacy benefit of RFC 8981 becoming observable on the
        wire.

        Reference: RFC 6724 §5 rule 7 (Prefer temporary addresses).
        Reference: RFC 8981 §3.3 (Generation and lifetime of temporary addresses).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_STABLE_A, _HOST_TEMP_A]
        self._packet_handler._icmp6_slaac_addresses = [_slaac(_HOST_STABLE_A, _PREFIX_A)]
        self._packet_handler._icmp6_temp_addresses = [_temp(_HOST_TEMP_A, _PREFIX_A)]

        with sysctl_module.override("icmp6.default.use_tempaddr", 2):
            result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_IN_A)

        self.assertEqual(
            result,
            _HOST_TEMP_A.address,
            msg="Rule 7 must prefer the temp address when both candidates match the destination's prefix.",
        )

    def test__ip6__rfc6724_rule7__temp_preference_outranks_rule_8(self) -> None:
        """
        Ensure rule 7 outranks rule 8: a temp address in a
        different prefix wins over a stable address whose
        prefix matches the destination, because rule 7 sits
        above rule 8 in priority order.

        Reference: RFC 6724 §5 (rule 7 ordered before rule 8).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_STABLE_A, _HOST_TEMP_B]
        self._packet_handler._icmp6_slaac_addresses = [_slaac(_HOST_STABLE_A, _PREFIX_A)]
        self._packet_handler._icmp6_temp_addresses = [_temp(_HOST_TEMP_B, _PREFIX_B)]

        with sysctl_module.override("icmp6.default.use_tempaddr", 2):
            result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_IN_A)

        self.assertEqual(
            result,
            _HOST_TEMP_B.address,
            msg="Rule 7 must outrank rule 8: temp address wins even when its prefix is farther from destination.",
        )

    def test__ip6__rfc6724_rule7__deprecated_temp_loses_to_preferred_stable(self) -> None:
        """
        Ensure rule 3 outranks rule 7: a DEPRECATED temp
        address loses to a PREFERRED stable address even when
        the policy says "prefer temp", because rule 3 sits
        above rule 7 in priority order.

        Reference: RFC 6724 §5 (rule 3 ordered before rule 7).
        Reference: RFC 4862 §5.5.4 (PREFERRED / DEPRECATED state).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_STABLE_A, _HOST_TEMP_A]
        self._packet_handler._icmp6_slaac_addresses = [_slaac(_HOST_STABLE_A, _PREFIX_A)]
        self._packet_handler._icmp6_temp_addresses = [
            _temp(_HOST_TEMP_A, _PREFIX_A, deprecated=True),
        ]

        with sysctl_module.override("icmp6.default.use_tempaddr", 2):
            result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_IN_A)

        self.assertEqual(
            result,
            _HOST_STABLE_A.address,
            msg="Rule 3 must outrank rule 7: PREFERRED stable beats DEPRECATED temp.",
        )


class TestRfc6724Rule7TempNoPreference(Ip6TestCase):
    """
    The 'icmp6.use_tempaddr=1' rule-7 no-preference tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides do not
        leak across tests.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__ip6__rfc6724_rule7__no_preference_rule_8_decides(self) -> None:
        """
        Ensure rule 7 produces no preference under
        'use_tempaddr=1' — the temp address in prefix B does
        not win over the stable address in prefix A when the
        destination is in prefix A; rule 8 (longest matching
        prefix) decides.

        Reference: RFC 6724 §5 rule 7 (no preference under use_tempaddr=1).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_STABLE_A, _HOST_TEMP_B]
        self._packet_handler._icmp6_slaac_addresses = [_slaac(_HOST_STABLE_A, _PREFIX_A)]
        self._packet_handler._icmp6_temp_addresses = [_temp(_HOST_TEMP_B, _PREFIX_B)]

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_IN_A)

        self.assertEqual(
            result,
            _HOST_STABLE_A.address,
            msg="Under use_tempaddr=1, rule 8 must decide; stable address with matching prefix wins.",
        )


class TestRfc6724Rule7TempDisabled(Ip6TestCase):
    """
    The 'icmp6.use_tempaddr=0' rule-7 disabled tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides do not
        leak across tests.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__ip6__rfc6724_rule7__disabled_no_preference_when_temp_present(self) -> None:
        """
        Ensure rule 7 is a no-op under 'use_tempaddr=0' even if
        temp addresses are somehow present — the policy
        suppresses any preference, leaving rule 8 to decide.
        Rule 7 must never push a temp address ahead of a stable
        one when the operator has explicitly disabled the
        feature.

        Reference: RFC 6724 §5 rule 7 (no-op when use_tempaddr=0).
        """

        self._packet_handler._ip6_ifaddr = [_HOST_STABLE_B, _HOST_TEMP_A]
        self._packet_handler._icmp6_slaac_addresses = [_slaac(_HOST_STABLE_B, _PREFIX_B)]
        self._packet_handler._icmp6_temp_addresses = [_temp(_HOST_TEMP_A, _PREFIX_A)]

        with sysctl_module.override("icmp6.default.use_tempaddr", 0):
            result = self._packet_handler._ip6_tx._select_ip6_source(ip6__dst=_DST_IN_B)

        self.assertEqual(
            result,
            _HOST_STABLE_B.address,
            msg="Under use_tempaddr=0, rule 7 must not bump the temp address; rule 8 picks the stable match.",
        )
