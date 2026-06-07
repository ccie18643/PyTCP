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
Integration tests for the RFC 8981 temp-address cleanup
sweep — nd_linux_parity §18c.1.

When a temp address's 'valid_until' deadline passes, the
sweep removes it from both '_icmp6_temp_addresses' and
'_ip6_ifaddr'. Until §18c.2 ships the regeneration logic,
the sweep is cleanup-only — expired temps simply disappear
without replacement.

Linux's regen+cleanup machinery lives in
'addrconf.c::manage_tempaddrs' and is driven by the
'addr_chk_timer'. PyTCP's sweep is invoked from the
PacketHandler subsystem loop, rate-limited by the
'icmp6.temp_addr_sweep_interval_s' sysctl.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__temp_addr_sweep.py

ver 3.0.8
"""

import time
from typing import override

from net_addr import Ip6Address, Ip6IfAddr, Ip6Network
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6TempAddress
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

PREFIX_A = Ip6Network("2001:db8:0:1::/64")
PREFIX_B = Ip6Network("2001:db8:0:2::/64")
ROUTER__LINK_LOCAL = Ip6Address("fe80::1")


class TestIcmp6Nd__TempAddrSweep__SysctlRegistration(NdTestCase):
    """
    'icmp6.temp_addr_sweep_interval_s' is registered with a
    sensible default; validator accepts positive ints.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__temp_addr_sweep__sysctl_default_60s(self) -> None:
        """
        Ensure 'icmp6.temp_addr_sweep_interval_s' defaults
        to 60 seconds — a reasonable trade-off between
        cleanup latency and CPU overhead.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.temp_addr_sweep_interval_s"),
            60,
            msg="Default must be 60 seconds.",
        )

    def test__icmp6__nd__temp_addr_sweep__sysctl_validator_rejects_zero(self) -> None:
        """
        Ensure 0 is rejected — a zero-interval sweep would
        tight-loop the subsystem.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.temp_addr_sweep_interval_s", 0)

    def test__icmp6__nd__temp_addr_sweep__sysctl_validator_rejects_negative(self) -> None:
        """
        Ensure negative integers are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.temp_addr_sweep_interval_s", -1)

    def test__icmp6__nd__temp_addr_sweep__sysctl_validator_rejects_bool(self) -> None:
        """
        Ensure booleans are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.temp_addr_sweep_interval_s", True)


class TestIcmp6Nd__TempAddrSweep__RemovesExpired(NdTestCase):
    """
    '_icmp6_sweep_temp_addresses()' removes entries whose
    'valid_until' deadline has passed from BOTH
    '_icmp6_temp_addresses' AND '_ip6_ifaddr'.
    """

    def _make_temp(
        self,
        *,
        address: str,
        prefix: Ip6Network,
        offset_valid: float,
    ) -> Icmp6TempAddress:
        """
        Build an 'Icmp6TempAddress' with 'valid_until = now +
        offset_valid'. Use a negative offset to simulate an
        expired entry.
        """

        now = time.monotonic()
        return Icmp6TempAddress(
            address=Ip6Address(address),
            prefix=prefix,
            preferred_until=now + offset_valid - 1.0,
            valid_until=now + offset_valid,
            created_at=now - 100.0,
            router_address=ROUTER__LINK_LOCAL,
        )

    def test__icmp6__nd__temp_addr_sweep__removes_expired_from_temp_table(self) -> None:
        """
        Ensure the sweep drops entries past 'valid_until'
        from '_icmp6_temp_addresses'.

        Reference: RFC 8981 §3.4 (temp address removed when valid_lifetime expires).
        """

        expired = self._make_temp(address="2001:db8:0:1::dead", prefix=PREFIX_A, offset_valid=-1.0)
        active = self._make_temp(address="2001:db8:0:2::abcd", prefix=PREFIX_B, offset_valid=86400)
        self._packet_handler._icmp6_temp_addresses = [expired, active]

        self._packet_handler._icmp6_sweep_temp_addresses()

        addrs = [t.address for t in self._packet_handler._icmp6_temp_addresses]
        self.assertNotIn(
            expired.address,
            addrs,
            msg=f"Expired temp must be removed from _icmp6_temp_addresses. Got: {addrs!r}",
        )
        self.assertIn(
            active.address,
            addrs,
            msg=f"Active temp must remain in _icmp6_temp_addresses. Got: {addrs!r}",
        )

    def test__icmp6__nd__temp_addr_sweep__removes_expired_from_ip6_host(self) -> None:
        """
        Ensure the sweep removes the expired temp address
        from '_ip6_ifaddr' (the hot list of addresses the
        stack listens on).

        Reference: RFC 8981 §3.4 (expired temp must not be
                                  used for new traffic).
        """

        expired_addr = "2001:db8:0:1::dead"
        expired = self._make_temp(address=expired_addr, prefix=PREFIX_A, offset_valid=-1.0)
        # Insert into both tables so the sweep can find &
        # remove from each.
        self._packet_handler._icmp6_temp_addresses = [expired]
        self._packet_handler._ip6_ifaddr.append(Ip6IfAddr(f"{expired_addr}/64"))

        self.assertIn(
            Ip6Address(expired_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Pre-condition: expired temp must be in _ip6_ifaddr before the sweep.",
        )

        self._packet_handler._icmp6_sweep_temp_addresses()

        self.assertNotIn(
            Ip6Address(expired_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Sweep must remove expired temp from _ip6_ifaddr.",
        )

    def test__icmp6__nd__temp_addr_sweep__preserves_non_expired(self) -> None:
        """
        Ensure the sweep leaves entries with future
        'valid_until' deadlines untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        active_addr = "2001:db8:0:1::cafe"
        active = self._make_temp(address=active_addr, prefix=PREFIX_A, offset_valid=86400)
        self._packet_handler._icmp6_temp_addresses = [active]
        self._packet_handler._ip6_ifaddr.append(Ip6IfAddr(f"{active_addr}/64"))

        self._packet_handler._icmp6_sweep_temp_addresses()

        self.assertIn(
            active.address,
            [t.address for t in self._packet_handler._icmp6_temp_addresses],
            msg="Active temp must remain in _icmp6_temp_addresses after sweep.",
        )
        self.assertIn(
            Ip6Address(active_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Active temp must remain in _ip6_ifaddr after sweep.",
        )

    def test__icmp6__nd__temp_addr_sweep__no_op_when_no_expired(self) -> None:
        """
        Ensure the sweep is a no-op when no entries have
        expired — '_icmp6_temp_addresses' length is unchanged
        and no '_ip6_ifaddr' entries are removed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        active = self._make_temp(address="2001:db8:0:1::1234", prefix=PREFIX_A, offset_valid=3600)
        self._packet_handler._icmp6_temp_addresses = [active]
        ip6_host_count_before = len(self._packet_handler._ip6_ifaddr)

        self._packet_handler._icmp6_sweep_temp_addresses()

        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            1,
            msg="No-op sweep must preserve all temp entries.",
        )
        self.assertEqual(
            len(self._packet_handler._ip6_ifaddr),
            ip6_host_count_before,
            msg="No-op sweep must not touch _ip6_ifaddr.",
        )

    def test__icmp6__nd__temp_addr_sweep__handles_temp_only_in_ip6_host(self) -> None:
        """
        Ensure the sweep does NOT remove an _ip6_ifaddr entry
        that has no matching '_icmp6_temp_addresses' record
        — e.g. the stable SLAAC address. The sweep is
        scoped to the temp-address table.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Stable address present in _ip6_ifaddr but NOT in
        # the temp table.
        stable_addr = "2001:db8:0:9::1"
        self._packet_handler._ip6_ifaddr.append(Ip6IfAddr(f"{stable_addr}/64"))

        # An expired temp tracks a DIFFERENT address.
        expired = self._make_temp(address="2001:db8:0:1::dead", prefix=PREFIX_A, offset_valid=-1.0)
        self._packet_handler._icmp6_temp_addresses = [expired]

        self._packet_handler._icmp6_sweep_temp_addresses()

        self.assertIn(
            Ip6Address(stable_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Stable (non-temp) addresses in _ip6_ifaddr must NOT be touched by the temp sweep.",
        )
