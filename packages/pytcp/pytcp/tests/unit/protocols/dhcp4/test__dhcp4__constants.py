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
This module contains tests for the DHCPv4 runtime configuration
sysctls under 'pytcp/protocols/dhcp4/dhcp4__constants.py'.

pytcp/tests/unit/protocols/dhcp4/test__dhcp4__constants.py

ver 3.0.9
"""

from typing import override
from unittest import TestCase

from pytcp.protocols.dhcp4 import dhcp4__constants
from pytcp.stack import sysctl


class TestDhcp4ConstantsDefaults(TestCase):
    """
    Defaults for every DHCPv4 sysctl knob registered by
    'dhcp4__constants.py'.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default so a knob mutated
        by a sibling test does not leak into the next test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp4_constants__retrans_initial_ms_default(self) -> None:
        """
        Ensure 'dhcp.retrans_initial_ms' defaults to 4000 ms — the
        canonical first-retransmit interval.

        Reference: RFC 2131 §4.1 (4-second initial retransmission delay).
        """

        self.assertEqual(
            sysctl.get("dhcp.retrans_initial_ms"),
            4000,
            msg="dhcp.retrans_initial_ms must default to 4000 ms per RFC 2131 §4.1.",
        )
        self.assertEqual(
            dhcp4__constants.DHCP4__RETRANS_INITIAL_MS,
            4000,
            msg="The DHCP4__RETRANS_INITIAL_MS module attribute must match the sysctl default.",
        )

    def test__dhcp4_constants__retrans_max_ms_default(self) -> None:
        """
        Ensure 'dhcp.retrans_max_ms' defaults to 64000 ms — the
        ceiling on the doubled retransmission interval.

        Reference: RFC 2131 §4.1 (retransmission delay doubled up to 64 s).
        """

        self.assertEqual(
            sysctl.get("dhcp.retrans_max_ms"),
            64000,
            msg="dhcp.retrans_max_ms must default to 64000 ms per RFC 2131 §4.1.",
        )

    def test__dhcp4_constants__retrans_max_attempts_default(self) -> None:
        """
        Ensure 'dhcp.retrans_max_attempts' defaults to 5 attempts
        (5 recv waits with delays 4/8/16/32/64 s ≈ 124 s budget).

        Reference: RFC 2131 §4.1 (give adequate probability of reaching the server).
        """

        self.assertEqual(
            sysctl.get("dhcp.retrans_max_attempts"),
            5,
            msg="dhcp.retrans_max_attempts must default to 5 per the Phase 1 retransmission budget.",
        )

    def test__dhcp4_constants__retrans_jitter_ms_default(self) -> None:
        """
        Ensure 'dhcp.retrans_jitter_ms' defaults to 1000 ms — the
        ±1 s randomization window around each retransmit delay.

        Reference: RFC 2131 §4.1 (retransmission delay randomized by ±1 second).
        """

        self.assertEqual(
            sysctl.get("dhcp.retrans_jitter_ms"),
            1000,
            msg="dhcp.retrans_jitter_ms must default to 1000 ms per RFC 2131 §4.1.",
        )

    def test__dhcp4_constants__nak_max_restarts_default(self) -> None:
        """
        Ensure 'dhcp.nak_max_restarts' defaults to 3 — bounded
        restart loop budget for 'fetch()' after DHCPNAK.

        Reference: RFC 2131 §3.1 step 4 (NAK → restart from DISCOVER; bounded to prevent loops).
        """

        self.assertEqual(
            sysctl.get("dhcp.nak_max_restarts"),
            3,
            msg="dhcp.nak_max_restarts must default to 3 (initial + 3 restarts = 4 attempts).",
        )

    def test__dhcp4_constants__init_delay_min_ms_default(self) -> None:
        """
        Ensure 'dhcp.init_delay_min_ms' defaults to 1000 ms — the
        lower bound of the "between one and ten seconds" startup
        desynchronisation window.

        Reference: RFC 2131 §4.4.1 (client SHOULD wait a random time between one and ten seconds).
        """

        self.assertEqual(
            sysctl.get("dhcp.init_delay_min_ms"),
            1000,
            msg="dhcp.init_delay_min_ms must default to 1000 ms per RFC 2131 §4.4.1.",
        )

    def test__dhcp4_constants__init_delay_max_ms_default(self) -> None:
        """
        Ensure 'dhcp.init_delay_max_ms' defaults to 10000 ms — the
        upper bound of the startup desynchronisation window.

        Reference: RFC 2131 §4.4.1 (client SHOULD wait a random time between one and ten seconds).
        """

        self.assertEqual(
            sysctl.get("dhcp.init_delay_max_ms"),
            10000,
            msg="dhcp.init_delay_max_ms must default to 10000 ms per RFC 2131 §4.4.1.",
        )

    def test__dhcp4_constants__decline_backoff_ms_default(self) -> None:
        """
        Ensure 'dhcp.decline_backoff_ms' defaults to 10000 ms — the
        minimum wait after a DHCPDECLINE before restarting from
        DISCOVER, per the §3.1 step 5 "minimum of ten seconds"
        SHOULD.

        Reference: RFC 2131 §3.1 step 5 (client SHOULD wait a minimum of ten seconds before restarting).
        """

        self.assertEqual(
            sysctl.get("dhcp.decline_backoff_ms"),
            10000,
            msg="dhcp.decline_backoff_ms must default to 10000 ms per RFC 2131 §3.1 step 5.",
        )

    def test__dhcp4_constants__t1_factor_default(self) -> None:
        """
        Ensure 'dhcp.t1_factor' defaults to 0.5 — the canonical
        "RENEW at half the lease" fraction.

        Reference: RFC 2131 §4.4.5 (T1 = 0.5 × lease default).
        """

        self.assertAlmostEqual(
            sysctl.get("dhcp.t1_factor"),
            0.5,
            places=4,
            msg="dhcp.t1_factor must default to 0.5 per RFC 2131 §4.4.5.",
        )

    def test__dhcp4_constants__abort_sessions_on_lease_change_default(self) -> None:
        """
        Ensure 'dhcp.abort_sessions_on_lease_change' defaults to
        1 — the deliberate deviation from Linux's silent-rot
        behaviour.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset connections on relinquished addresses).
        """

        self.assertEqual(
            sysctl.get("dhcp.abort_sessions_on_lease_change"),
            1,
            msg="dhcp.abort_sessions_on_lease_change must default to 1 per the RFC 5227 §2.4-final SHOULD.",
        )

    def test__dhcp4_constants__abort_sessions_on_lease_change_accepts_zero(self) -> None:
        """
        Ensure 'dhcp.abort_sessions_on_lease_change' accepts 0
        — operators can opt into Linux-parity silent-rot
        behaviour.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.abort_sessions_on_lease_change", 0)
        self.assertEqual(
            sysctl.get("dhcp.abort_sessions_on_lease_change"),
            0,
            msg="dhcp.abort_sessions_on_lease_change must accept 0 to disable active abort.",
        )

    def test__dhcp4_constants__abort_sessions_on_lease_change_rejects_other_values(self) -> None:
        """
        Ensure 'dhcp.abort_sessions_on_lease_change' rejects
        every value outside {0, 1} — booleans, negatives,
        floats, multi-valued ints.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad_value in (2, -1, True, False, 1.0):
            with self.assertRaises(
                ValueError,
                msg=f"dhcp.abort_sessions_on_lease_change must reject {bad_value!r}",
            ):
                sysctl.set("dhcp.abort_sessions_on_lease_change", bad_value)

    def test__dhcp4_constants__t2_factor_default(self) -> None:
        """
        Ensure 'dhcp.t2_factor' defaults to 0.875 — the canonical
        "REBIND at 7/8 of the lease" fraction.

        Reference: RFC 2131 §4.4.5 (T2 = 0.875 × lease default).
        """

        self.assertAlmostEqual(
            sysctl.get("dhcp.t2_factor"),
            0.875,
            places=4,
            msg="dhcp.t2_factor must default to 0.875 per RFC 2131 §4.4.5.",
        )

    def test__dhcp4_constants__duid_default_empty_string(self) -> None:
        """
        Ensure 'dhcp.duid' defaults to an empty string — the
        "auto-derive DUID-LL from MAC" signal consumed by
        'pytcp.protocols.dhcp4.dhcp4__uid.get_duid'.

        Reference: RFC 4361 §6.1 (client MAY use an externally-configured DUID; default is derived).
        """

        self.assertEqual(
            sysctl.get("dhcp.duid"),
            "",
            msg="dhcp.duid must default to the empty string (auto-derive from MAC).",
        )


class TestDhcp4ConstantsValidators(TestCase):
    """
    Validator rejection cases for the DHCPv4 sysctl knobs.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default after each test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp4_constants__retrans_initial_ms_rejects_zero(self) -> None:
        """
        Ensure 'dhcp.retrans_initial_ms' rejects 0 — a 0-ms retrans
        interval would loop without bound.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.retrans_initial_ms", 0)

    def test__dhcp4_constants__retrans_initial_ms_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.retrans_initial_ms' rejects negative values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.retrans_initial_ms", -1)

    def test__dhcp4_constants__retrans_initial_ms_rejects_bool(self) -> None:
        """
        Ensure 'dhcp.retrans_initial_ms' rejects booleans even though
        'isinstance(True, int)' is True in Python.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.retrans_initial_ms", True)

    def test__dhcp4_constants__retrans_jitter_ms_accepts_zero(self) -> None:
        """
        Ensure 'dhcp.retrans_jitter_ms' accepts 0 so tests can disable
        jitter for deterministic backoff behaviour.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.retrans_jitter_ms", 0)
        self.assertEqual(
            sysctl.get("dhcp.retrans_jitter_ms"),
            0,
            msg="dhcp.retrans_jitter_ms must accept 0 to disable jitter.",
        )

    def test__dhcp4_constants__retrans_jitter_ms_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.retrans_jitter_ms' rejects negative values — the
        jitter is a magnitude, drawn from [-J, +J].

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.retrans_jitter_ms", -1)

    def test__dhcp4_constants__retrans_jitter_ms_rejects_bool(self) -> None:
        """
        Ensure 'dhcp.retrans_jitter_ms' rejects booleans.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.retrans_jitter_ms", False)

    def test__dhcp4_constants__retrans_max_attempts_rejects_zero(self) -> None:
        """
        Ensure 'dhcp.retrans_max_attempts' rejects 0 — at least one
        recv attempt must be made before giving up.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.retrans_max_attempts", 0)

    def test__dhcp4_constants__nak_max_restarts_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.nak_max_restarts' rejects negative values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.nak_max_restarts", -1)

    def test__dhcp4_constants__init_delay_min_ms_accepts_zero(self) -> None:
        """
        Ensure 'dhcp.init_delay_min_ms' accepts 0 — both min and max
        set to 0 must be a valid "disable the desync delay" pairing
        for deterministic tests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.init_delay_min_ms", 0)
        self.assertEqual(
            sysctl.get("dhcp.init_delay_min_ms"),
            0,
            msg="dhcp.init_delay_min_ms must accept 0 to permit a disable-delay configuration.",
        )

    def test__dhcp4_constants__init_delay_min_ms_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.init_delay_min_ms' rejects negative values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.init_delay_min_ms", -1)

    def test__dhcp4_constants__init_delay_max_ms_accepts_zero(self) -> None:
        """
        Ensure 'dhcp.init_delay_max_ms' accepts 0 — the canonical
        disable signal for the desynchronisation delay.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Both bounds need to be 0 for finalize to accept; first
        # collapse the upper, then the lower.
        sysctl.set("dhcp.init_delay_min_ms", 0)
        sysctl.set("dhcp.init_delay_max_ms", 0)
        self.assertEqual(
            sysctl.get("dhcp.init_delay_max_ms"),
            0,
            msg="dhcp.init_delay_max_ms must accept 0 to disable the desync delay.",
        )

    def test__dhcp4_constants__init_delay_max_ms_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.init_delay_max_ms' rejects negative values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.init_delay_max_ms", -1)

    def test__dhcp4_constants__decline_backoff_ms_accepts_zero(self) -> None:
        """
        Ensure 'dhcp.decline_backoff_ms' accepts 0 — disables the
        wait for deterministic tests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.decline_backoff_ms", 0)
        self.assertEqual(
            sysctl.get("dhcp.decline_backoff_ms"),
            0,
            msg="dhcp.decline_backoff_ms must accept 0 to disable the post-DECLINE wait.",
        )

    def test__dhcp4_constants__decline_backoff_ms_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.decline_backoff_ms' rejects negative values.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.decline_backoff_ms", -1)

    def test__dhcp4_constants__duid_accepts_compact_hex(self) -> None:
        """
        Ensure 'dhcp.duid' accepts the canonical compact-hex
        representation operators paste into config files
        ("000300010200000000fe" form).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.duid", "0003000102000000000a")
        self.assertEqual(
            sysctl.get("dhcp.duid"),
            "0003000102000000000a",
            msg="dhcp.duid must accept compact-hex strings verbatim.",
        )

    def test__dhcp4_constants__duid_accepts_colon_separated_hex(self) -> None:
        """
        Ensure 'dhcp.duid' accepts the operator-friendly colon-
        separated hex representation ("00:03:00:01:..." form).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.duid", "00:03:00:01:02:00:00:00:00:0a")
        self.assertEqual(
            sysctl.get("dhcp.duid"),
            "00:03:00:01:02:00:00:00:00:0a",
            msg="dhcp.duid must accept colon-separated hex strings verbatim.",
        )

    def test__dhcp4_constants__duid_rejects_non_hex(self) -> None:
        """
        Ensure 'dhcp.duid' rejects strings that are not valid hex.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.duid", "not-a-hex-string")

    def test__dhcp4_constants__duid_rejects_odd_length_hex(self) -> None:
        """
        Ensure 'dhcp.duid' rejects odd-length hex strings — every
        hex byte requires two characters.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.duid", "000300010a0")

    def test__dhcp4_constants__duid_rejects_non_string(self) -> None:
        """
        Ensure 'dhcp.duid' rejects non-string types.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.duid", 0x1234)


class TestDhcp4ConstantsLiveModuleReadthrough(TestCase):
    """
    Setting a sysctl must update the underlying module attribute so
    code that imports and reads 'dhcp4__constants.XYZ' picks up the
    operator override per pytcp.md §2.1 (qualified module access).
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default after each test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp4_constants__sysctl_set_updates_module_attribute(self) -> None:
        """
        Ensure 'sysctl.set("dhcp.retrans_initial_ms", N)' updates
        'dhcp4__constants.DHCP4__RETRANS_INITIAL_MS' so qualified-
        module reads see the override.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.retrans_initial_ms", 2000)
        self.assertEqual(
            dhcp4__constants.DHCP4__RETRANS_INITIAL_MS,
            2000,
            msg="sysctl.set must update the module attribute so qualified reads see the override.",
        )


class TestDhcp4ConstantsFinalizeValidator(TestCase):
    """
    Cross-knob finalize validator — 'dhcp.retrans_initial_ms' must be
    no greater than 'dhcp.retrans_max_ms'.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default after each test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp4_constants__finalize_rejects_initial_greater_than_max(self) -> None:
        """
        Ensure 'finalize_validators()' raises when the operator
        configures 'retrans_initial_ms' larger than 'retrans_max_ms';
        a doubled-and-capped backoff with that pairing would never
        actually double.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.retrans_initial_ms", 70000)

        with self.assertRaises(ValueError):
            sysctl.finalize_validators()

    def test__dhcp4_constants__finalize_accepts_equal_initial_and_max(self) -> None:
        """
        Ensure 'finalize_validators()' accepts the boundary case
        'retrans_initial_ms == retrans_max_ms' — operator wants a
        fixed retransmit interval with no doubling.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.retrans_initial_ms", 4000)
        sysctl.set("dhcp.retrans_max_ms", 4000)
        sysctl.finalize_validators()  # must not raise

    def test__dhcp4_constants__finalize_rejects_init_min_greater_than_max(self) -> None:
        """
        Ensure 'finalize_validators()' raises when 'init_delay_min_ms'
        exceeds 'init_delay_max_ms' — 'random.uniform(min, max)' with
        min > max is undefined.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.init_delay_min_ms", 5000)
        sysctl.set("dhcp.init_delay_max_ms", 2000)

        with self.assertRaises(ValueError):
            sysctl.finalize_validators()

    def test__dhcp4_constants__t1_factor_rejects_negative(self) -> None:
        """
        Ensure 'dhcp.t1_factor' rejects negative values — T1
        cannot occur before lease acquisition.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.t1_factor", -0.1)

    def test__dhcp4_constants__t1_factor_rejects_above_one(self) -> None:
        """
        Ensure 'dhcp.t1_factor' rejects values above 1.0 — T1
        cannot occur after lease expiry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.t1_factor", 1.5)

    def test__dhcp4_constants__t1_factor_rejects_bool(self) -> None:
        """
        Ensure 'dhcp.t1_factor' rejects booleans even though
        'isinstance(True, int)' is True and 'True' satisfies
        '0.0 <= True <= 1.0' numerically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp.t1_factor", True)

    def test__dhcp4_constants__finalize_rejects_t1_factor_above_t2_factor(self) -> None:
        """
        Ensure the cross-knob finalize validator rejects an
        operator configuration where 'dhcp.t1_factor' exceeds
        'dhcp.t2_factor' — RENEWING must precede REBINDING.

        Reference: RFC 2131 §4.4.5 (T1 MUST be earlier than T2).
        """

        sysctl.set("dhcp.t1_factor", 0.9)
        sysctl.set("dhcp.t2_factor", 0.6)

        with self.assertRaises(ValueError):
            sysctl.finalize_validators()

    def test__dhcp4_constants__finalize_accepts_equal_init_min_and_max(self) -> None:
        """
        Ensure 'finalize_validators()' accepts the boundary case
        'init_delay_min_ms == init_delay_max_ms' — operator wants a
        fixed (zero-jitter) startup delay, including the
        disable-delay pairing (0, 0).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl.set("dhcp.init_delay_min_ms", 0)
        sysctl.set("dhcp.init_delay_max_ms", 0)
        sysctl.finalize_validators()  # must not raise
