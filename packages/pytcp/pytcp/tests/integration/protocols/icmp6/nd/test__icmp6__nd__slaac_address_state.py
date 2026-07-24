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
Integration tests for the IPv6 Neighbor Discovery SLAAC per-address
state machine and the RFC 4862 §5.5.3 (e)(6) 2-hour rule —
nd_linux_parity §12b.

State machine: an admitted Prefix-Information option implies an
SLAAC address whose state is computed lazily from
'time.monotonic()':

    now < preferred_until : PREFERRED
    preferred_until <= now < valid_until : DEPRECATED
    valid_until <= now : (filtered from the table)

The 2-hour rule (§5.5.3 (e)(6) (b)/(c)) protects an existing
autoconfigured address from a router that advertises a short
remaining lifetime: an attacker on the link cannot shrink an
address's valid lifetime below 2 hours unless the existing
remaining is already <= 2 hours.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__slaac_address_state.py

ver 3.0.8
"""

from unittest.mock import patch

from net_addr import Ip6Address, Ip6Network, MacAddress
from net_proto import Icmp6NdOptionPi
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddressState
from pytcp.tests.lib.nd_testcase import NdTestCase
from pytcp.tests.lib.network_testcase import (
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

STACK__IP6_ADDRESS = STACK__IP6_HOST.address

ROUTER__LINK_LOCAL = Ip6Address("fe80::1")
ROUTER__MAC = MacAddress("02:00:00:00:00:01")

PREFIX = Ip6Network("2001:db8:0:1::/64")

# RFC 4862 §5.5.3 (e)(6) 2-hour constant.
TWO_HOURS = 7200


def _pi_option(
    *,
    valid_lifetime: int,
    preferred_lifetime: int,
) -> Icmp6NdOptionPi:
    """
    Build an autoconf-eligible PI option for PREFIX with the given
    lifetimes.
    """

    return Icmp6NdOptionPi(
        flag_l=True,
        flag_a=True,
        flag_r=False,
        valid_lifetime=valid_lifetime,
        preferred_lifetime=preferred_lifetime,
        prefix=PREFIX,
    )


class TestIcmp6Nd__SlaacAddressState__StateMachine(NdTestCase):
    """
    The per-address state machine derives its phase from
    'time.monotonic()' against the entry's preferred / valid
    deadlines (no background sweep — lazy computation).
    """

    def test__icmp6__nd__slaac__state_preferred_within_preferred_lifetime(self) -> None:
        """
        Ensure 'get_icmp6_slaac_address_state(prefix)' returns
        PREFERRED while now is below the entry's preferred_until.

        Reference: RFC 4862 §5.5.4 (PREFERRED state — usable for new
        and existing connections).
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(valid_lifetime=2592000, preferred_lifetime=604800),
                    ],
                ),
            )

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0 + 60,
        ):
            state = self._packet_handler.get_icmp6_slaac_address_state(prefix=PREFIX)

        self.assertEqual(
            state,
            Icmp6SlaacAddressState.PREFERRED,
            msg=f"Within preferred_until window the address must be PREFERRED. Got: {state!r}",
        )

    def test__icmp6__nd__slaac__state_deprecated_after_preferred_expires(self) -> None:
        """
        Ensure 'get_icmp6_slaac_address_state(prefix)' returns
        DEPRECATED once 'now' has crossed the entry's
        preferred_until but is still below valid_until.

        Reference: RFC 4862 §5.5.4 (DEPRECATED state — existing connections only).
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(valid_lifetime=2592000, preferred_lifetime=300),
                    ],
                ),
            )

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0 + 301,
        ):
            state = self._packet_handler.get_icmp6_slaac_address_state(prefix=PREFIX)

        self.assertEqual(
            state,
            Icmp6SlaacAddressState.DEPRECATED,
            msg=f"After preferred_until the address must be DEPRECATED. Got: {state!r}",
        )

    def test__icmp6__nd__slaac__state_none_after_valid_expires(self) -> None:
        """
        Ensure 'get_icmp6_slaac_address_state(prefix)' returns
        None once 'now' has crossed the entry's valid_until —
        the entry is filtered (REMOVED).

        Reference: RFC 4862 §5.5.4 (valid_lifetime expiry implies removal).
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(valid_lifetime=120, preferred_lifetime=60),
                    ],
                ),
            )

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=1000.0 + 121,
        ):
            state = self._packet_handler.get_icmp6_slaac_address_state(prefix=PREFIX)

        self.assertIsNone(
            state,
            msg=f"After valid_until the entry must be filtered (state None). Got: {state!r}",
        )

    def test__icmp6__nd__slaac__state_unknown_prefix_returns_none(self) -> None:
        """
        Ensure querying a prefix that has never been advertised
        returns None — the accessor is total.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        state = self._packet_handler.get_icmp6_slaac_address_state(prefix=PREFIX)

        self.assertIsNone(
            state,
            msg=f"Unknown prefix must return None. Got: {state!r}",
        )


class TestIcmp6Nd__SlaacAddressState__TwoHourRule(NdTestCase):
    """
    RFC 4862 §5.5.3 (e)(6) 2-hour rule on an existing
    autoconfigured address's lifetime updates. Sub-rules:
      (a) advertised > 2hrs OR advertised > remaining
          → accept the advertised lifetime.
      (b) remaining ≤ 2hrs (and (a) does not apply)
          → IGNORE the prefix entirely (without SEND auth).
      (c) otherwise → CLAMP the new valid_lifetime to 2hrs.
    """

    def _install_initial_entry(
        self,
        *,
        at_time: float,
        valid_lifetime: int,
        preferred_lifetime: int,
    ) -> None:
        """
        Drive an initial RA at 'at_time' so the host has an
        existing SLAAC entry to refresh.
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=at_time,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(
                            valid_lifetime=valid_lifetime,
                            preferred_lifetime=preferred_lifetime,
                        ),
                    ],
                ),
            )

    def _refresh(
        self,
        *,
        at_time: float,
        valid_lifetime: int,
        preferred_lifetime: int,
    ) -> None:
        """
        Drive a second RA at 'at_time' carrying a refresh PI.
        """

        with patch(
            "pytcp.runtime.packet_handler.time.monotonic",
            return_value=at_time,
        ):
            self._drive_rx(
                frame=self._make_nd_ra_frame(
                    eth_src=ROUTER__MAC,
                    eth_dst=STACK__MAC_ADDRESS,
                    ip6_src=ROUTER__LINK_LOCAL,
                    ip6_dst=STACK__IP6_ADDRESS,
                    router_lifetime=1800,
                    options=[
                        _pi_option(
                            valid_lifetime=valid_lifetime,
                            preferred_lifetime=preferred_lifetime,
                        ),
                    ],
                ),
            )

    def test__icmp6__nd__pi__2hour_rule_long_advertised_lifetime_accepts(self) -> None:
        """
        Ensure case (a) — when the advertised valid lifetime is
        greater than 2 hours, the host accepts it regardless of
        the existing remaining lifetime.

        Reference: RFC 4862 §5.5.3 (e)(6)(a) (advertised > 2h accepted).
        """

        self._install_initial_entry(
            at_time=1000.0,
            valid_lifetime=900,
            preferred_lifetime=600,
        )

        # 30s after install: remaining = 870s (< 2h, would trigger (b)
        # if (a) didn't kick in). Advertise > 2h → (a) accepts.
        self._refresh(
            at_time=1030.0,
            valid_lifetime=2 * TWO_HOURS,
            preferred_lifetime=2 * TWO_HOURS,
        )

        entry = self._packet_handler._icmp6_slaac_addresses[0]
        self.assertGreaterEqual(
            entry.valid_until,
            1030.0 + 2 * TWO_HOURS,
            msg=("Case (a) — advertised > 2h must overwrite valid_until " f"to now + advertised. Got: {entry!r}"),
        )

    def test__icmp6__nd__pi__2hour_rule_advertised_gt_remaining_accepts(self) -> None:
        """
        Ensure case (a) — when the advertised valid lifetime is
        greater than the existing remaining lifetime, the host
        accepts it even if it is below 2 hours.

        Reference: RFC 4862 §5.5.3 (e)(6)(a) (advertised > remaining accepted).
        """

        # remaining = 60s after install + advance.
        self._install_initial_entry(
            at_time=1000.0,
            valid_lifetime=300,
            preferred_lifetime=300,
        )

        self._refresh(
            at_time=1240.0,
            valid_lifetime=600,
            preferred_lifetime=600,
        )

        entry = self._packet_handler._icmp6_slaac_addresses[0]
        self.assertGreaterEqual(
            entry.valid_until,
            1240.0 + 600,
            msg=("Case (a) — advertised > remaining must overwrite " f"valid_until. Got: {entry!r}"),
        )

    def test__icmp6__nd__pi__2hour_rule_short_remaining_ignores_short(self) -> None:
        """
        Ensure case (b) — remaining ≤ 2h AND advertised ≤ remaining
        AND advertised ≤ 2h leaves the entry untouched (the prefix
        is ignored without SEND auth).

        Reference: RFC 4862 §5.5.3 (e)(6)(b) (RemainingLifetime ≤ 2h, ignore PI without authentication).
        """

        # Install with valid=600. Refresh 60s later (remaining=540).
        # Advertise valid=120 (≤ remaining, ≤ 2h) → (b) ignore.
        self._install_initial_entry(
            at_time=1000.0,
            valid_lifetime=600,
            preferred_lifetime=600,
        )
        original_valid_until = self._packet_handler._icmp6_slaac_addresses[0].valid_until

        self._refresh(
            at_time=1060.0,
            valid_lifetime=120,
            preferred_lifetime=60,
        )

        entry = self._packet_handler._icmp6_slaac_addresses[0]
        self.assertEqual(
            entry.valid_until,
            original_valid_until,
            msg=(
                "Case (b) — remaining ≤ 2h with short advertised must " f"leave valid_until untouched. Got: {entry!r}"
            ),
        )

    def test__icmp6__nd__pi__2hour_rule_clamps_to_2_hours(self) -> None:
        """
        Ensure case (c) — remaining > 2h AND advertised ≤ 2h AND
        advertised ≤ remaining causes the new valid_lifetime to
        clamp to 2 hours.

        Reference: RFC 4862 §5.5.3 (e)(6)(c) (clamp to 2 hours).
        """

        # Install with valid=2 days. Refresh 1h later — remaining=23h.
        # Advertise valid=600s (≤ remaining, ≤ 2h) → (c) clamp to 2h.
        self._install_initial_entry(
            at_time=1000.0,
            valid_lifetime=2 * 86400,
            preferred_lifetime=2 * 86400,
        )

        self._refresh(
            at_time=1000.0 + 3600,
            valid_lifetime=600,
            preferred_lifetime=600,
        )

        entry = self._packet_handler._icmp6_slaac_addresses[0]
        self.assertEqual(
            entry.valid_until,
            1000.0 + 3600 + TWO_HOURS,
            msg=(
                "Case (c) — short advertised with safe remaining must "
                f"clamp valid_until to now + 2 hours. Got: {entry!r}"
            ),
        )
