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
Integration tests for the RFC 8981 SLAAC temporary-address
integration — nd_linux_parity §18b.

The host's PI-admit path now mints a per-prefix temporary
address (random IID via 'Ip6IfAddr.from_rfc8981_temp') in
addition to the stable RFC 7217 / EUI-64 address whenever
'icmp6.use_tempaddr' is non-zero. Lifetimes are clamped to
TEMP_PREFERRED_LIFETIME / TEMP_VALID_LIFETIME (RFC 8981 §3.4).
The DAD claim runs in a §20.1 worker thread, so the RX thread
is not blocked.

Regeneration before lifetime expiry (RFC 8981 §3.4 cycle) is
deferred to §18c; source-address selection (RFC 6724 rule 7
"prefer temporary addresses") is deferred to §18d / §12c. The
§18b commit pins only the wire-state machinery and the
boot-time / RX-driven claim path.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc8981_temp.py

ver 3.0.10
"""

import time
from typing import override

from net_addr import Ip6Address, Ip6Network, MacAddress
from net_proto import Icmp6NdOptionPi
from pytcp.protocols.icmp6.nd import nd__constants
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")

PREFIX_A = Ip6Network("2001:db8:0:1::/64")
PREFIX_B = Ip6Network("2001:db8:0:2::/64")


def _pi_option(
    *,
    prefix: Ip6Network,
    valid_lifetime: int,
    preferred_lifetime: int,
    flag_a: bool = True,
    flag_l: bool = True,
) -> Icmp6NdOptionPi:
    """
    Build a Prefix-Information option with autoconfiguration enabled.
    """

    return Icmp6NdOptionPi(
        flag_l=flag_l,
        flag_a=flag_a,
        flag_r=False,
        valid_lifetime=valid_lifetime,
        preferred_lifetime=preferred_lifetime,
        prefix=prefix,
    )


class TestIcmp6Nd__Rfc8981Temp__SysctlRegistration(NdTestCase):
    """
    The 'icmp6.use_tempaddr' sysctl is registered with default
    0 (Linux 'net.ipv6.conf.<iface>.use_tempaddr' default for
    privacy-conservative deployments) and accepts the Linux
    tristate {0, 1, 2}. The lifetime knobs and DESYNC factor
    are also exposed.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rfc8981__use_tempaddr_default_zero(self) -> None:
        """
        Ensure 'icmp6.use_tempaddr' defaults to 0 (off,
        privacy-conservative).

        Reference: RFC 8981 §3.1 (host MAY use temporary addresses).
        """

        self.assertEqual(
            sysctl_module.get("icmp6.default.use_tempaddr"),
            0,
            msg="'icmp6.use_tempaddr' must default to 0.",
        )

    def test__icmp6__nd__rfc8981__use_tempaddr_validator_accepts_tristate(self) -> None:
        """
        Ensure the validator accepts the Linux tristate
        {0, 1, 2} and rejects values outside it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for value in (0, 1, 2):
            sysctl_module.set("icmp6.default.use_tempaddr", value)
            self.assertEqual(
                sysctl_module.get("icmp6.default.use_tempaddr"),
                value,
                msg=f"Validator must accept tristate value {value}.",
            )

        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.use_tempaddr", 3)
        with self.assertRaises(ValueError):
            sysctl_module.set("icmp6.default.use_tempaddr", True)

    def test__icmp6__nd__rfc8981__lifetime_constants(self) -> None:
        """
        Ensure the lifetime constants are registered with the
        spec-recommended defaults (TEMP_VALID_LIFETIME=7 days,
        TEMP_PREFERRED_LIFETIME=1 day, MAX_DESYNC_FACTOR=10
        minutes).

        Reference: RFC 8981 §3.8 (default lifetimes).
        """

        self.assertEqual(
            nd__constants.ICMP6__TEMP_VALID_LIFETIME_S["default"],
            604800,
            msg="TEMP_VALID_LIFETIME default must be 7 days (604800s).",
        )
        self.assertEqual(
            nd__constants.ICMP6__TEMP_PREFERRED_LIFETIME_S["default"],
            86400,
            msg="TEMP_PREFERRED_LIFETIME default must be 1 day (86400s).",
        )
        self.assertEqual(
            nd__constants.ICMP6__MAX_DESYNC_FACTOR_S["default"],
            600,
            msg="MAX_DESYNC_FACTOR default must be 10 minutes (600s).",
        )


class TestIcmp6Nd__Rfc8981Temp__MutatorWireState(NdTestCase):
    """
    The '_update_icmp6_temp_address' mutator manages the
    per-prefix temp-address table. Tested in isolation
    (without RX-driven DAD) so the lifetime / table-state
    invariants are pinnable without timing concerns.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rfc8981__sysctl_zero_no_entry(self) -> None:
        """
        Ensure the mutator is a no-op when
        'icmp6.use_tempaddr=0' — no temp-address table entry
        created.

        Reference: RFC 8981 §3.1 (use_tempaddr=0 disables the feature).
        """

        # Default sysctl (0) — call mutator and verify table empty.
        self._packet_handler._update_icmp6_temp_address(
            prefix=PREFIX_A,
            valid_lifetime=2592000,
            preferred_lifetime=604800,
            router_address=ROUTER__LINK_LOCAL,
        )

        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            0,
            msg="use_tempaddr=0 must NOT install a temp-address entry.",
        )

    def test__icmp6__nd__rfc8981__creates_entry_with_random_iid(self) -> None:
        """
        Ensure the mutator with sysctl=1 installs a temp-address
        entry whose address shares the /64 prefix but has a
        random IID different from the EUI-64 / RFC 7217 stable
        derivation.

        Reference: RFC 8981 §3.3.2 (random IID generation).
        """

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._packet_handler._update_icmp6_temp_address(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                    router_address=ROUTER__LINK_LOCAL,
                )

        entries = self._packet_handler._icmp6_temp_addresses
        self.assertEqual(len(entries), 1, msg=f"Expected one temp entry. Got: {entries!r}")
        entry = entries[0]
        self.assertEqual(
            entry.prefix,
            PREFIX_A,
            msg=f"Temp entry must record the source prefix. Got: {entry!r}",
        )
        # The address must lie within the /64.
        self.assertTrue(
            int(entry.address) >> 64 == int(PREFIX_A.address) >> 64,
            msg=f"Temp address must be within {PREFIX_A}. Got: {entry.address!r}",
        )
        # And it must NOT match the stable RFC 7217 derivation.
        stable = self._packet_handler._derive_ip6_host(ip6_network=PREFIX_A).address
        self.assertNotEqual(
            entry.address,
            stable,
            msg="Temp address IID must differ from the stable derivation.",
        )

    def test__icmp6__nd__rfc8981__lifetime_clamps_to_temp_constants(self) -> None:
        """
        Ensure the entry's preferred_until and valid_until
        deadlines are clamped to TEMP_PREFERRED_LIFETIME /
        TEMP_VALID_LIFETIME when the PI advertises a longer
        window.

        Reference: RFC 8981 §3.4 (lifetimes clamped at creation).
        """

        before = time.monotonic()
        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._packet_handler._update_icmp6_temp_address(
                    prefix=PREFIX_A,
                    valid_lifetime=99999999,
                    preferred_lifetime=99999999,
                    router_address=ROUTER__LINK_LOCAL,
                )

        entry = self._packet_handler._icmp6_temp_addresses[0]
        # Valid lifetime clamped to TEMP_VALID_LIFETIME = 7 days.
        self.assertLessEqual(
            entry.valid_until,
            before + nd__constants.ICMP6__TEMP_VALID_LIFETIME_S["default"] + 1.0,
            msg=f"valid_until must clamp to TEMP_VALID_LIFETIME. Got: {entry.valid_until - before}s",
        )
        # Preferred lifetime clamped to TEMP_PREFERRED_LIFETIME -
        # DESYNC margin; allow up to MAX_DESYNC slack.
        self.assertLessEqual(
            entry.preferred_until,
            before + nd__constants.ICMP6__TEMP_PREFERRED_LIFETIME_S["default"] + 1.0,
            msg=f"preferred_until must clamp to TEMP_PREFERRED_LIFETIME. Got: {entry.preferred_until - before}s",
        )

    def test__icmp6__nd__rfc8981__zero_valid_removes_entry(self) -> None:
        """
        Ensure a subsequent PI with valid_lifetime=0 removes
        the temp-address entry — same removal rule the stable
        SLAAC table applies.

        Reference: RFC 4862 §5.5.3 (e)(4) (zero-lifetime PI removes entry).
        """

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._packet_handler._update_icmp6_temp_address(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                    router_address=ROUTER__LINK_LOCAL,
                )
                self.assertEqual(len(self._packet_handler._icmp6_temp_addresses), 1)

                self._packet_handler._update_icmp6_temp_address(
                    prefix=PREFIX_A,
                    valid_lifetime=0,
                    preferred_lifetime=0,
                    router_address=ROUTER__LINK_LOCAL,
                )

        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            0,
            msg="valid_lifetime=0 PI must remove the temp-address entry.",
        )

    def test__icmp6__nd__rfc8981__refresh_preserves_address(self) -> None:
        """
        Ensure a subsequent PI for the same prefix refreshes
        lifetimes but preserves the existing temp address —
        regeneration is §18c, not §18b.

        Reference: RFC 8981 §3.4 (lifetime refresh on PI update).
        """

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._packet_handler._update_icmp6_temp_address(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                    router_address=ROUTER__LINK_LOCAL,
                )
                first_address = self._packet_handler._icmp6_temp_addresses[0].address

                self._packet_handler._update_icmp6_temp_address(
                    prefix=PREFIX_A,
                    valid_lifetime=2592000,
                    preferred_lifetime=604800,
                    router_address=ROUTER__LINK_LOCAL,
                )

        entries = self._packet_handler._icmp6_temp_addresses
        self.assertEqual(
            len(entries),
            1,
            msg=f"Refresh must NOT add a second entry. Got: {entries!r}",
        )
        self.assertEqual(
            entries[0].address,
            first_address,
            msg="Refresh must preserve the temp address (no regeneration in §18b).",
        )

    def test__icmp6__nd__rfc8981__lazy_aged_accessor(self) -> None:
        """
        Ensure 'get_icmp6_temp_addresses' filters out entries
        whose 'valid_until' deadline has passed — same lazy-
        ageing pattern as the stable SLAAC accessor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Synthesise an expired entry directly in the table so we
        # don't have to wait for time to pass.
        from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6TempAddress

        now = time.monotonic()
        self._packet_handler._icmp6_temp_addresses.append(
            Icmp6TempAddress(
                address=Ip6Address("2001:db8:0:1::dead:beef"),
                prefix=PREFIX_A,
                preferred_until=now - 1.0,
                valid_until=now - 0.5,
                created_at=now - 100.0,
                router_address=ROUTER__LINK_LOCAL,
            ),
        )

        active = self._packet_handler.get_icmp6_temp_addresses()
        self.assertEqual(
            active,
            [],
            msg=f"Expired temp entry must be lazy-aged out. Got: {active!r}",
        )


class TestIcmp6Nd__Rfc8981Temp__RxDrivenClaim(NdTestCase):
    """
    Driving an RA via the RX path with sysctl=1 admits the PI,
    invokes the SLAAC mutator (existing §12a behaviour), and
    ALSO invokes the §18b temp-address mutator. The temp
    address ends up in '_icmp6_temp_addresses' and (after the
    §20.1 DAD worker thread completes) in '_ip6_ifaddr'.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rfc8981__ra_drives_temp_address_creation(self) -> None:
        """
        Ensure an RA with a single PI option creates one
        stable SLAAC entry AND one temp-address entry (under
        sysctl=1).

        Reference: RFC 8981 §3.3 (per-PI temp-address creation).
        """

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._drive_rx(
                    frame=self._make_nd_ra_frame(
                        eth_src=ROUTER__MAC,
                        eth_dst=STACK__MAC_ADDRESS,
                        ip6_src=ROUTER__LINK_LOCAL,
                        ip6_dst=STACK__IP6_ADDRESS,
                        router_lifetime=1800,
                        options=[
                            _pi_option(
                                prefix=PREFIX_A,
                                valid_lifetime=2592000,
                                preferred_lifetime=604800,
                            ),
                        ],
                    ),
                )

        # SLAAC table got the stable entry.
        slaac_entries = self._packet_handler._icmp6_slaac_addresses
        self.assertEqual(
            len(slaac_entries),
            1,
            msg=f"Expected one stable SLAAC entry. Got: {slaac_entries!r}",
        )

        # Temp table got the privacy entry.
        temp_entries = self._packet_handler._icmp6_temp_addresses
        self.assertEqual(
            len(temp_entries),
            1,
            msg=f"Expected one temp-address entry. Got: {temp_entries!r}",
        )
        self.assertEqual(
            temp_entries[0].prefix,
            PREFIX_A,
            msg="Temp entry must record the advertised prefix.",
        )
        self.assertNotEqual(
            temp_entries[0].address,
            slaac_entries[0].address,
            msg="Temp address IID must differ from the stable SLAAC address.",
        )

    def test__icmp6__nd__rfc8981__ra_with_sysctl_zero_no_temp(self) -> None:
        """
        Ensure an RA with sysctl=0 (default) creates only the
        stable SLAAC entry — no temp-address entry, no temp
        DAD claim.

        Reference: RFC 8981 §3.1 (use_tempaddr=0 disables).
        """

        with sysctl_module.override("icmp6.default.dad_transmits", 0):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(
                            prefix=PREFIX_A,
                            valid_lifetime=2592000,
                            preferred_lifetime=604800,
                        ),
                    ],
                ),
            )

        self.assertEqual(
            len(self._packet_handler._icmp6_slaac_addresses),
            1,
            msg="Stable SLAAC entry must still be created (sysctl=0 only suppresses temp).",
        )
        self.assertEqual(
            len(self._packet_handler._icmp6_temp_addresses),
            0,
            msg="use_tempaddr=0 must NOT create a temp-address entry.",
        )

    def test__icmp6__nd__rfc8981__claim_worker_assigns_temp_to_ip6_host(self) -> None:
        """
        Ensure the DAD worker spawned for the temp address
        eventually installs it into '_ip6_ifaddr' (DAD passes
        when 'icmp6.dad_transmits=0' so the worker
        immediately considers the claim successful).

        Reference: RFC 8981 §3.3 (temp address installed after DAD).
        """

        with sysctl_module.override("icmp6.default.use_tempaddr", 1):
            with sysctl_module.override("icmp6.default.dad_transmits", 0):
                self._drive_rx(
                    frame=self._make_nd_ra_frame(
                        eth_src=ROUTER__MAC,
                        eth_dst=STACK__MAC_ADDRESS,
                        ip6_src=ROUTER__LINK_LOCAL,
                        ip6_dst=STACK__IP6_ADDRESS,
                        router_lifetime=1800,
                        options=[
                            _pi_option(
                                prefix=PREFIX_A,
                                valid_lifetime=2592000,
                                preferred_lifetime=604800,
                            ),
                        ],
                    ),
                )

                # Wait briefly for the DAD worker to finish — under
                # 'dad_transmits=0' it returns almost immediately.
                temp_address = self._packet_handler._icmp6_temp_addresses[0].address
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    if temp_address in [host.address for host in self._packet_handler._ip6_ifaddr]:
                        break
                    time.sleep(0.005)

        self.assertIn(
            temp_address,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="DAD worker must install the temp address into '_ip6_ifaddr' after DAD passes.",
        )
