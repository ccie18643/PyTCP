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
Integration tests for the RFC 8981 temp-address
regeneration cycle — nd_linux_parity §18c.2.

The host periodically inspects '_icmp6_temp_addresses'
and, for each prefix whose newest entry is approaching
'preferred_until - REGEN_ADVANCE', mints a fresh random
IID alongside the existing one. Both temps coexist during
the rotation-overlap window. The §18c.1 cleanup sweep
removes the older entry once its 'valid_until' passes.

REGEN_ADVANCE defaults to 5 seconds (RFC 8981 §3.8 formula
2 + TEMP_IDGEN_RETRIES * RetransTimer ≈ 5).

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__temp_addr_regen.py

ver 3.0.9
"""

import time
from typing import override

from net_addr import Ip6Address, Ip6Network
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6TempAddress
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase

PREFIX_A = Ip6Network("2001:db8:0:1::/64")
PREFIX_B = Ip6Network("2001:db8:0:2::/64")
ROUTER__LINK_LOCAL = Ip6Address("fe80::1")


class TestIcmp6Nd__TempAddrRegen__SysctlRegistration(NdTestCase):
    """
    'icmp6.regen_advance_s' is registered with default 5
    (RFC 8981 §3.8); validator accepts non-negative ints.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__temp_addr_regen__sysctl_default_five(self) -> None:
        """
        Ensure 'icmp6.regen_advance_s' defaults to 5 seconds
        — the spec formula yields ~5s for default DAD
        parameters.

        Reference: RFC 8981 §3.8 (REGEN_ADVANCE default formula).
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.regen_advance_s"),
            5,
            msg="Default must be 5 seconds (RFC 8981 §3.8).",
        )

    def test__icmp6__nd__temp_addr_regen__validator_accepts_zero(self) -> None:
        """
        Ensure 0 is admitted (regen exactly at expiry, no
        advance window).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("icmp6.default.regen_advance_s", 0)
        self.assertEqual(sysctl_module.get("icmp6.default.regen_advance_s"), 0)

    def test__icmp6__nd__temp_addr_regen__validator_rejects_negative(self) -> None:
        """
        Ensure negative integers are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.regen_advance_s", -1)

    def test__icmp6__nd__temp_addr_regen__validator_rejects_bool(self) -> None:
        """
        Ensure booleans are rejected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.regen_advance_s", True)


class TestIcmp6Nd__TempAddrRegen__Regenerates(NdTestCase):
    """
    '_icmp6_regen_temp_addresses()' adds a new temp entry
    for any prefix whose newest entry is approaching
    'preferred_until - REGEN_ADVANCE'.
    """

    def _make_temp(
        self,
        *,
        address: str,
        prefix: Ip6Network,
        preferred_offset: float,
        valid_offset: float,
    ) -> Icmp6TempAddress:
        """
        Build an 'Icmp6TempAddress' with deadlines relative
        to the current monotonic clock.
        """

        now = time.monotonic()
        return Icmp6TempAddress(
            address=Ip6Address(address),
            prefix=prefix,
            preferred_until=now + preferred_offset,
            valid_until=now + valid_offset,
            created_at=now - 100.0,
            router_address=ROUTER__LINK_LOCAL,
        )

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__temp_addr_regen__sysctl_off_no_regen(self) -> None:
        """
        Ensure regen is a no-op when 'icmp6.use_tempaddr=0'
        — even an entry past its regen-advance threshold is
        not regenerated.

        Reference: RFC 8981 §3.1 (use_tempaddr=0 disables).
        """

        # Approaching deprecation in 1 second (well under
        # the 5s REGEN_ADVANCE default).
        about_to_deprecate = self._make_temp(
            address="2001:db8:0:1::dead",
            prefix=PREFIX_A,
            preferred_offset=1.0,
            valid_offset=86400,
        )
        self._packet_handler._icmp6_temp_addresses = [about_to_deprecate]

        # Default sysctl (use_tempaddr=0).
        self._packet_handler._icmp6_regen_temp_addresses()

        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            1,
            msg="use_tempaddr=0 must NOT regenerate temp addresses.",
        )

    def test__icmp6__nd__temp_addr_regen__creates_second_entry(self) -> None:
        """
        Ensure regen mints a new temp entry alongside the
        existing one when the existing entry is approaching
        deprecation.

        Reference: RFC 8981 §3.4 (regenerate REGEN_ADVANCE
                                  before preferred lifetime
                                  expires).
        """

        about_to_deprecate = self._make_temp(
            address="2001:db8:0:1::dead",
            prefix=PREFIX_A,
            preferred_offset=1.0,
            valid_offset=86400,
        )
        self._packet_handler._icmp6_temp_addresses = [about_to_deprecate]

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._packet_handler._icmp6_regen_temp_addresses()

        entries = self._packet_handler._icmp6_temp_addresses
        # Two entries for the same prefix now.
        self.assertEqual(
            len(entries),
            2,
            msg=f"Regen must add a second entry. Got: {entries!r}",
        )
        prefixes = {entry.prefix for entry in entries}
        self.assertEqual(
            prefixes,
            {PREFIX_A},
            msg="Both entries must share the same prefix.",
        )
        # Different IIDs.
        addresses = {entry.address for entry in entries}
        self.assertEqual(
            len(addresses),
            2,
            msg=f"Regen must produce a different IID. Got: {addresses!r}",
        )
        self.assertIn(
            about_to_deprecate.address,
            addresses,
            msg="Original (about-to-deprecate) entry must remain.",
        )

    def test__icmp6__nd__temp_addr_regen__does_not_regen_fresh(self) -> None:
        """
        Ensure regen is a no-op when the newest entry for a
        prefix is far from its REGEN_ADVANCE threshold.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Fresh entry — preferred_until is 1 hour from now,
        # much greater than REGEN_ADVANCE=5.
        fresh = self._make_temp(
            address="2001:db8:0:1::cafe",
            prefix=PREFIX_A,
            preferred_offset=3600,
            valid_offset=86400,
        )
        self._packet_handler._icmp6_temp_addresses = [fresh]

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            self._packet_handler._icmp6_regen_temp_addresses()

        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            1,
            msg="Fresh temp must NOT be regenerated.",
        )

    def test__icmp6__nd__temp_addr_regen__skips_when_already_fresh_sibling(self) -> None:
        """
        Ensure regen does NOT add a third entry when a
        prefix already has both an old (about-to-deprecate)
        and a fresh entry — the regen has already happened
        for this prefix.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        about_to_deprecate = self._make_temp(
            address="2001:db8:0:1::dead",
            prefix=PREFIX_A,
            preferred_offset=1.0,
            valid_offset=86400,
        )
        already_regenned = self._make_temp(
            address="2001:db8:0:1::cafe",
            prefix=PREFIX_A,
            preferred_offset=3600,
            valid_offset=86400 * 7,
        )
        self._packet_handler._icmp6_temp_addresses = [about_to_deprecate, already_regenned]

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            self._packet_handler._icmp6_regen_temp_addresses()

        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            2,
            msg="Regen must not pile up entries when a fresh sibling already exists.",
        )

    def test__icmp6__nd__temp_addr_regen__multiple_prefixes_independent(self) -> None:
        """
        Ensure regen handles each prefix independently — a
        prefix that needs regen gets one, a prefix that
        doesn't is left alone.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        about_to_deprecate_a = self._make_temp(
            address="2001:db8:0:1::dead",
            prefix=PREFIX_A,
            preferred_offset=1.0,
            valid_offset=86400,
        )
        fresh_b = self._make_temp(
            address="2001:db8:0:2::cafe",
            prefix=PREFIX_B,
            preferred_offset=3600,
            valid_offset=86400,
        )
        self._packet_handler._icmp6_temp_addresses = [about_to_deprecate_a, fresh_b]

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._packet_handler._icmp6_regen_temp_addresses()

        # PREFIX_A got a regen (now 2 entries).
        a_entries = [t for t in self._packet_handler._icmp6_temp_addresses if t.prefix == PREFIX_A]
        b_entries = [t for t in self._packet_handler._icmp6_temp_addresses if t.prefix == PREFIX_B]
        self.assertEqual(
            len(a_entries),
            2,
            msg=f"PREFIX_A must be regenerated (1→2 entries). Got: {a_entries!r}",
        )
        self.assertEqual(
            len(b_entries),
            1,
            msg=f"PREFIX_B must be untouched (still 1 entry). Got: {b_entries!r}",
        )
