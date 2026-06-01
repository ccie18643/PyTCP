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
Integration tests for runtime SLAAC stable-address lifecycle —
post-boot PI admission triggers a fresh claim, and a periodic
sweep removes expired entries from both the tracking table and
'_ip6_ifaddr'.

PyTCP previously claimed stable SLAAC addresses only during the
boot-time '_create_stack_ip6_addressing' loop; a brand-new
prefix arriving at runtime would update '_icmp6_slaac_addresses'
lifetime tracking but never produce a host address. The §18b
RFC 8981 temp-address path was already runtime-dynamic (per
nd_linux_parity §18b); this commit closes the asymmetry for
the stable address. The §18c.1 sweep is extended with an
'_icmp6_sweep_slaac_addresses' counterpart so expired stable
entries also get pruned from '_ip6_ifaddr', not just from the
lifetime table.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__slaac_runtime_claim.py

ver 3.0.8
"""

import time

from net_addr import Ip6Address, Ip6IfAddr, Ip6Network, MacAddress
from net_proto import Icmp6NdOptionPi
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddress
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
PREFIX_NEW = Ip6Network("2001:db8:0:9::/64")


def _pi_option(
    *,
    prefix: Ip6Network,
    valid_lifetime: int,
    preferred_lifetime: int,
) -> Icmp6NdOptionPi:
    """
    Build an autoconfig-eligible PI option.
    """

    return Icmp6NdOptionPi(
        flag_l=True,
        flag_a=True,
        flag_r=False,
        valid_lifetime=valid_lifetime,
        preferred_lifetime=preferred_lifetime,
        prefix=prefix,
    )


class TestIcmp6Nd__SlaacRuntimeClaim__PostBootClaims(NdTestCase):
    """
    With '_ip6_addressing_complete = True' (post-boot), a PI
    for a brand-new prefix triggers a stable-address DAD claim
    via '_claim_ip6_address_async'. The address ends up in
    '_ip6_ifaddr' once the worker completes.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__slaac_runtime__new_prefix_claims(self) -> None:
        """
        Ensure a post-boot RA carrying a new prefix admits the
        prefix to the SLAAC table AND triggers a stable-address
        claim that lands in '_ip6_ifaddr'.

        Reference: RFC 4862 §5.5.3 (e)(4) (autoconfig form
                                           address from PI).
        """

        self._packet_handler._ip6_addressing_complete = True

        with sysctl_module.override("icmp6.default.dad_transmits", 0):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                self._drive_rx(
                    frame=self._make_nd_ra_frame(
                        eth_src=ROUTER__MAC,
                        eth_dst=STACK__MAC_ADDRESS,
                        ip6_src=ROUTER__LINK_LOCAL,
                        ip6_dst=STACK__IP6_ADDRESS,
                        router_lifetime=1800,
                        options=[
                            _pi_option(
                                prefix=PREFIX_NEW,
                                valid_lifetime=2592000,
                                preferred_lifetime=604800,
                            ),
                        ],
                    ),
                )

                # Wait briefly for the DAD worker to finish
                # (dad_transmits=0 makes it return almost
                # immediately).
                expected = self._packet_handler._derive_ip6_host(ip6_network=PREFIX_NEW).address
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    if expected in [host.address for host in self._packet_handler._ip6_ifaddr]:
                        break
                    time.sleep(0.005)

        self.assertIn(
            expected,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="Post-boot PI for a new prefix must produce a stable address in _ip6_ifaddr.",
        )

    def test__icmp6__nd__slaac_runtime__pre_boot_no_claim(self) -> None:
        """
        Ensure a PI processed during the boot window
        ('_ip6_addressing_complete = False') does NOT trigger
        an RX-path claim — the boot loop owns the claim
        ordering during boot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # The default state — flag is False until
        # '_create_stack_ip6_addressing' completes.
        self._packet_handler._ip6_addressing_complete = False

        with sysctl_module.override("icmp6.default.dad_transmits", 0):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                self._drive_rx(
                    frame=self._make_nd_ra_frame(
                        eth_src=ROUTER__MAC,
                        eth_dst=STACK__MAC_ADDRESS,
                        ip6_src=ROUTER__LINK_LOCAL,
                        ip6_dst=STACK__IP6_ADDRESS,
                        router_lifetime=1800,
                        options=[
                            _pi_option(
                                prefix=PREFIX_NEW,
                                valid_lifetime=2592000,
                                preferred_lifetime=604800,
                            ),
                        ],
                    ),
                )
                time.sleep(0.05)  # generous slack for any (illicit) worker to land

        # Expected stable address must NOT be in _ip6_ifaddr —
        # boot loop hasn't run yet.
        expected = self._packet_handler._derive_ip6_host(ip6_network=PREFIX_NEW).address
        self.assertNotIn(
            expected,
            [host.address for host in self._packet_handler._ip6_ifaddr],
            msg="Pre-boot RX-path PI must NOT claim the stable address; that's the boot loop's job.",
        )
        # But the SLAAC tracking table did update.
        self.assertIn(
            PREFIX_NEW,
            [a.prefix for a in self._packet_handler._icmp6_slaac_addresses],
            msg="Pre-boot PI must still update the SLAAC tracking table.",
        )

    def test__icmp6__nd__slaac_runtime__refresh_no_double_claim(self) -> None:
        """
        Ensure a post-boot PI for an EXISTING prefix only
        refreshes lifetimes — no fresh claim is spawned. The
        existing address must remain in '_ip6_ifaddr'; no
        duplicate appears.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._packet_handler._ip6_addressing_complete = True

        with sysctl_module.override("icmp6.default.dad_transmits", 0):
            with sysctl_module.override("icmp6.default.max_rtr_solicitation_delay_ms", 0):
                # First PI installs the entry.
                self._drive_rx(
                    frame=self._make_nd_ra_frame(
                        eth_src=ROUTER__MAC,
                        eth_dst=STACK__MAC_ADDRESS,
                        ip6_src=ROUTER__LINK_LOCAL,
                        ip6_dst=STACK__IP6_ADDRESS,
                        router_lifetime=1800,
                        options=[
                            _pi_option(prefix=PREFIX_NEW, valid_lifetime=2592000, preferred_lifetime=604800),
                        ],
                    ),
                )
                expected = self._packet_handler._derive_ip6_host(ip6_network=PREFIX_NEW).address
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    if expected in [h.address for h in self._packet_handler._ip6_ifaddr]:
                        break
                    time.sleep(0.005)

                ip6_host_count_after_first = sum(1 for h in self._packet_handler._ip6_ifaddr if h.address == expected)
                self.assertEqual(
                    ip6_host_count_after_first,
                    1,
                    msg="First PI must install exactly one host entry.",
                )

                # Second PI for SAME prefix — refresh only.
                self._drive_rx(
                    frame=self._make_nd_ra_frame(
                        eth_src=ROUTER__MAC,
                        eth_dst=STACK__MAC_ADDRESS,
                        ip6_src=ROUTER__LINK_LOCAL,
                        ip6_dst=STACK__IP6_ADDRESS,
                        router_lifetime=1800,
                        options=[
                            _pi_option(prefix=PREFIX_NEW, valid_lifetime=2592000, preferred_lifetime=604800),
                        ],
                    ),
                )
                time.sleep(0.05)

        ip6_host_count_after_second = sum(1 for h in self._packet_handler._ip6_ifaddr if h.address == expected)
        self.assertEqual(
            ip6_host_count_after_second,
            1,
            msg="Refresh PI must NOT add a duplicate host entry.",
        )


class TestIcmp6Nd__SlaacRuntimeSweep__RemovesExpired(NdTestCase):
    """
    '_icmp6_sweep_slaac_addresses()' removes entries past
    'valid_until' from BOTH '_icmp6_slaac_addresses' AND
    '_ip6_ifaddr'.
    """

    def _make_slaac(
        self,
        *,
        address: str,
        prefix: Ip6Network,
        offset_valid: float,
    ) -> Icmp6SlaacAddress:
        """
        Build a stable SLAAC entry with 'valid_until = now +
        offset_valid'. Negative offset → expired.
        """

        now = time.monotonic()
        return Icmp6SlaacAddress(
            address=Ip6Address(address),
            prefix=prefix,
            preferred_until=now + offset_valid - 1.0,
            valid_until=now + offset_valid,
            router_address=ROUTER__LINK_LOCAL,
        )

    def test__icmp6__nd__slaac_sweep__removes_expired_from_table(self) -> None:
        """
        Ensure expired entries are dropped from
        '_icmp6_slaac_addresses'.

        Reference: RFC 4862 §5.5.3 (e)(7) (address removed
                                           when valid lifetime
                                           expires).
        """

        expired = self._make_slaac(address="2001:db8:0:1::dead", prefix=PREFIX_A, offset_valid=-1.0)
        active = self._make_slaac(address="2001:db8:0:2::abcd", prefix=PREFIX_B, offset_valid=86400)
        self._packet_handler._icmp6_slaac_addresses = [expired, active]

        self._packet_handler._icmp6_sweep_slaac_addresses()

        addrs = [a.address for a in self._packet_handler._icmp6_slaac_addresses]
        self.assertNotIn(
            expired.address,
            addrs,
            msg=f"Expired SLAAC entry must be removed. Got: {addrs!r}",
        )
        self.assertIn(
            active.address,
            addrs,
            msg=f"Active SLAAC entry must remain. Got: {addrs!r}",
        )

    def test__icmp6__nd__slaac_sweep__removes_expired_from_ip6_host(self) -> None:
        """
        Ensure expired stable SLAAC addresses are removed
        from '_ip6_ifaddr'.

        Reference: RFC 4862 §5.5.3 (e)(7) (expired stable
                                           address must not
                                           be used).
        """

        expired_addr = "2001:db8:0:1::dead"
        expired = self._make_slaac(address=expired_addr, prefix=PREFIX_A, offset_valid=-1.0)
        self._packet_handler._icmp6_slaac_addresses = [expired]
        self._packet_handler._ip6_ifaddr.append(Ip6IfAddr(f"{expired_addr}/64"))

        self.assertIn(
            Ip6Address(expired_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Pre-condition: expired SLAAC addr must be in _ip6_ifaddr before sweep.",
        )

        self._packet_handler._icmp6_sweep_slaac_addresses()

        self.assertNotIn(
            Ip6Address(expired_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Sweep must remove expired SLAAC addr from _ip6_ifaddr.",
        )

    def test__icmp6__nd__slaac_sweep__preserves_non_expired(self) -> None:
        """
        Ensure entries with future 'valid_until' deadlines
        are untouched.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        active_addr = "2001:db8:0:1::cafe"
        active = self._make_slaac(address=active_addr, prefix=PREFIX_A, offset_valid=86400)
        self._packet_handler._icmp6_slaac_addresses = [active]
        self._packet_handler._ip6_ifaddr.append(Ip6IfAddr(f"{active_addr}/64"))

        self._packet_handler._icmp6_sweep_slaac_addresses()

        self.assertIn(
            active.address,
            [a.address for a in self._packet_handler._icmp6_slaac_addresses],
            msg="Active SLAAC entry must remain in _icmp6_slaac_addresses.",
        )
        self.assertIn(
            Ip6Address(active_addr),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Active SLAAC addr must remain in _ip6_ifaddr.",
        )

    def test__icmp6__nd__slaac_sweep__does_not_touch_non_slaac(self) -> None:
        """
        Ensure '_ip6_ifaddr' entries that aren't backed by a
        SLAAC table record are NOT removed — the sweep is
        scoped to the SLAAC tracking table.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Address present in _ip6_ifaddr but NOT in the
        # SLAAC table.
        statically_configured = "2001:db8:0:9::1"
        self._packet_handler._ip6_ifaddr.append(Ip6IfAddr(f"{statically_configured}/64"))

        # An expired SLAAC entry references a different
        # address.
        expired = self._make_slaac(address="2001:db8:0:1::dead", prefix=PREFIX_A, offset_valid=-1.0)
        self._packet_handler._icmp6_slaac_addresses = [expired]

        self._packet_handler._icmp6_sweep_slaac_addresses()

        self.assertIn(
            Ip6Address(statically_configured),
            [h.address for h in self._packet_handler._ip6_ifaddr],
            msg="Statically-configured (non-SLAAC) addresses must NOT be touched by the sweep.",
        )
