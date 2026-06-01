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
This module contains integration tests for the TCP policy sysctls
('tcp.rto.initial_ms', 'tcp.retransmit.max_count', 'tcp.time_wait.delay_ms',
'tcp.delayed_ack.delay_ms', 'tcp.challenge_ack.rate_limit_ms',
'tcp.persist.timeout_max_ms', 'tcp.keepalive.idle_time_ms',
'tcp.keepalive.probe_interval_ms', 'tcp.keepalive.probe_max_count',
'tcp.ts_recent.outdated_threshold_ms').

The full TCP integration suite is the behavioural regression net —
every test that depends on the renamed module attributes continues
passing because the registry writes through to the backing attribute.
This file is the registration / validator / override-round-trip pin
for the ten knobs themselves.

pytcp/tests/integration/protocols/tcp/test__tcp__sysctls.py

ver 3.0.8
"""

from typing import override

from pytcp.protocols.tcp import tcp__constants
from pytcp.stack import sysctl
from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestTcpSysctlDefaults(NetworkTestCase):
    """
    The TCP policy-sysctl default-registration tests.
    """

    def test__tcp__sysctl__rto_initial_default_registered(self) -> None:
        """
        Ensure 'tcp.rto.initial_ms' registers with the
        initial RTO default of 1000 ms.

        Reference: RFC 6298 §2.1 (initial RTO 1 second).
        """

        self.assertEqual(
            sysctl.get("tcp.rto.initial_ms"),
            1000,
            msg="tcp.rto.initial_ms must default to 1000 ms (RFC 6298 §2.1).",
        )

    def test__tcp__sysctl__retransmit_max_count_default_registered(self) -> None:
        """
        Ensure 'tcp.retransmit.max_count' registers with the
        default retry budget of 6 that lands the R2 abort
        timeout just past the 100 s floor.

        Reference: RFC 1122 §4.2.3.5 (R2 ≥ 100 s retransmit abort).
        """

        self.assertEqual(
            sysctl.get("tcp.retransmit.max_count"),
            6,
            msg="tcp.retransmit.max_count must default to 6.",
        )

    def test__tcp__sysctl__time_wait_delay_default_registered(self) -> None:
        """
        Ensure 'tcp.time_wait.delay_ms' registers with the
        canonical 30 000 ms (2*MSL) TIME-WAIT default.

        Reference: RFC 9293 §3.10.1 (TIME-WAIT = 2*MSL).
        """

        self.assertEqual(
            sysctl.get("tcp.time_wait.delay_ms"),
            30000,
            msg="tcp.time_wait.delay_ms must default to 30000 ms.",
        )

    def test__tcp__sysctl__delayed_ack_delay_default_registered(self) -> None:
        """
        Ensure 'tcp.delayed_ack.delay_ms' registers with the
        RFC 1122 / RFC 9293 100 ms default (well under the
        500 ms cap).

        Reference: RFC 1122 §4.2.3.2 (delayed-ACK ≤ 500 ms).
        """

        self.assertEqual(
            sysctl.get("tcp.delayed_ack.delay_ms"),
            100,
            msg="tcp.delayed_ack.delay_ms must default to 100 ms.",
        )

    def test__tcp__sysctl__challenge_ack_rate_limit_default_registered(self) -> None:
        """
        Ensure 'tcp.challenge_ack.rate_limit_ms' registers with
        the default 1000 ms sliding window.

        Reference: RFC 5961 §3 (challenge ACK rate limiting).
        """

        self.assertEqual(
            sysctl.get("tcp.challenge_ack.rate_limit_ms"),
            1000,
            msg="tcp.challenge_ack.rate_limit_ms must default to 1000 ms.",
        )

    def test__tcp__sysctl__persist_timeout_max_default_registered(self) -> None:
        """
        Ensure 'tcp.persist.timeout_max_ms' registers with the
        60 000 ms persist-timer ceiling.

        Reference: RFC 9293 §3.8.6.1 (persist-timer maximum).
        Reference: RFC 1122 §4.2.2.17 (persist back-off).
        """

        self.assertEqual(
            sysctl.get("tcp.persist.timeout_max_ms"),
            60_000,
            msg="tcp.persist.timeout_max_ms must default to 60000 ms.",
        )

    def test__tcp__sysctl__keepalive_idle_time_default_registered(self) -> None:
        """
        Ensure 'tcp.keepalive.idle_time_ms' registers with the
        floor of 7 200 000 ms (2 hours), matching the Linux
        default.

        Reference: RFC 1122 §4.2.3.6 (keep-alive idle ≥ 2 h).
        """

        self.assertEqual(
            sysctl.get("tcp.keepalive.idle_time_ms"),
            7_200_000,
            msg="tcp.keepalive.idle_time_ms must default to 7200000 ms.",
        )

    def test__tcp__sysctl__keepalive_probe_interval_default_registered(self) -> None:
        """
        Ensure 'tcp.keepalive.probe_interval_ms' registers with
        the Linux-compatible 75 000 ms inter-probe spacing.

        Reference: RFC 1122 §4.2.3.6 (keep-alive probe interval).
        """

        self.assertEqual(
            sysctl.get("tcp.keepalive.probe_interval_ms"),
            75_000,
            msg="tcp.keepalive.probe_interval_ms must default to 75000 ms.",
        )

    def test__tcp__sysctl__keepalive_probe_max_count_default_registered(self) -> None:
        """
        Ensure 'tcp.keepalive.probe_max_count' registers with the
        Linux-compatible 9-probe ceiling.

        Reference: RFC 1122 §4.2.3.6 (keep-alive probe count).
        """

        self.assertEqual(
            sysctl.get("tcp.keepalive.probe_max_count"),
            9,
            msg="tcp.keepalive.probe_max_count must default to 9.",
        )

    def test__tcp__sysctl__ts_recent_outdated_threshold_default_registered(self) -> None:
        """
        Ensure 'tcp.ts_recent.outdated_threshold_ms' registers
        with the 24-day window converted to milliseconds.

        Reference: RFC 7323 §5.5 (outdated-timestamps mitigation).
        """

        self.assertEqual(
            sysctl.get("tcp.ts_recent.outdated_threshold_ms"),
            24 * 86_400 * 1_000,
            msg="tcp.ts_recent.outdated_threshold_ms must default to 24*86400*1000 ms.",
        )


class TestTcpSysctlOverrides(NetworkTestCase):
    """
    The TCP policy-sysctl runtime-override write-through tests.
    """

    def test__tcp__sysctl__rto_initial_override_updates_attr(self) -> None:
        """
        Ensure overriding 'tcp.rto.initial_ms' updates the
        backing module attribute that runtime code paths read
        via qualified module access.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl.override("tcp.rto.initial_ms", 500):
            self.assertEqual(
                tcp__constants.TCP__RTO__INITIAL_MS,
                500,
                msg="Override must write through to the backing attribute.",
            )

        self.assertEqual(
            tcp__constants.TCP__RTO__INITIAL_MS,
            1000,
            msg="Override exit must restore the registered default.",
        )

    def test__tcp__sysctl__keepalive_idle_override_updates_attr(self) -> None:
        """
        Ensure overriding 'tcp.keepalive.idle_time_ms' writes
        through to the backing module attribute the session
        keep-alive arm path reads via qualified access.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_value = 7_200_000 * 2
        with sysctl.override("tcp.keepalive.idle_time_ms", new_value):
            self.assertEqual(
                tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS,
                new_value,
                msg="Override must write through to TCP__KEEPALIVE__IDLE_TIME_MS.",
            )


class TestTcpSysctlValidators(NetworkTestCase):
    """
    The TCP policy-sysctl validator-rejection tests.
    """

    def test__tcp__sysctl__rto_initial_rejects_zero(self) -> None:
        """
        Ensure 'tcp.rto.initial_ms' rejects zero — a zero RTO
        would make the retransmit loop spin.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("tcp.rto.initial_ms", 0)

    def test__tcp__sysctl__rto_initial_rejects_negative(self) -> None:
        """
        Ensure 'tcp.rto.initial_ms' rejects a negative value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("tcp.rto.initial_ms", -10)

    def test__tcp__sysctl__retransmit_max_count_rejects_non_int(self) -> None:
        """
        Ensure 'tcp.retransmit.max_count' rejects non-int types
        (strings, floats, booleans).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for bad in ("5", 5.0, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sysctl.set("tcp.retransmit.max_count", bad)

    def test__tcp__sysctl__delayed_ack_rejects_over_500_ms(self) -> None:
        """
        Ensure 'tcp.delayed_ack.delay_ms' rejects values above
        the 500 ms ceiling — a delayed ACK that lingers longer
        than this violates the spec.

        Reference: RFC 1122 §4.2.3.2 (delayed-ACK ≤ 500 ms).
        Reference: RFC 9293 §3.8.6.3 (delayed-ACK upper bound).
        """

        with self.assertRaises(ValueError):
            sysctl.set("tcp.delayed_ack.delay_ms", 501)

    def test__tcp__sysctl__delayed_ack_accepts_exactly_500_ms(self) -> None:
        """
        Ensure 'tcp.delayed_ack.delay_ms' accepts the boundary
        value 500 — the RFC inclusive cap.

        Reference: RFC 1122 §4.2.3.2 (delayed-ACK ≤ 500 ms).
        """

        with sysctl.override("tcp.delayed_ack.delay_ms", 500):
            self.assertEqual(
                tcp__constants.TCP__DELAYED_ACK__DELAY_MS,
                500,
                msg="500 ms must be accepted (inclusive RFC cap).",
            )

    def test__tcp__sysctl__keepalive_idle_rejects_below_2h_floor(self) -> None:
        """
        Ensure 'tcp.keepalive.idle_time_ms' rejects values below
        the 2-hour hard floor (7 200 000 ms).

        Reference: RFC 1122 §4.2.3.6 (keep-alive idle floor 2 h).
        """

        with self.assertRaises(ValueError):
            sysctl.set("tcp.keepalive.idle_time_ms", 7_200_000 - 1)

    def test__tcp__sysctl__keepalive_idle_accepts_exactly_2h(self) -> None:
        """
        Ensure 'tcp.keepalive.idle_time_ms' accepts the boundary
        value 2 hours exactly (the RFC inclusive floor).

        Reference: RFC 1122 §4.2.3.6 (keep-alive idle floor 2 h).
        """

        with sysctl.override("tcp.keepalive.idle_time_ms", 7_200_000):
            self.assertEqual(
                tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS,
                7_200_000,
                msg="2 h exactly must be accepted (inclusive RFC floor).",
            )


class TestTcpSysctlCrossKnobConstraints(NetworkTestCase):
    """
    The TCP cross-knob finalize-validator tests.
    """

    @override
    def tearDown(self) -> None:
        """
        Reset every sysctl to its registered default so a
        cross-knob constraint violated in one test does not
        leak into the next.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__tcp__sysctl__persist_max_ge_rto_initial_pass(self) -> None:
        """
        Ensure 'tcp.persist.timeout_max_ms ≥ tcp.rto.initial_ms'
        passes finalize-validation when both knobs are at their
        defaults (60000 ms ≥ 1000 ms).

        Reference: RFC 9293 §3.8.6.1 (persist back-off bounded by initial RTO).
        """

        sysctl.finalize_validators()

    def test__tcp__sysctl__persist_max_lt_rto_initial_rejected(self) -> None:
        """
        Ensure 'finalize_validators' rejects a combination
        where 'tcp.persist.timeout_max_ms' is set below
        'tcp.rto.initial_ms' — the back-off ceiling cannot be
        lower than the initial floor.

        Reference: RFC 9293 §3.8.6.1 (persist back-off bounded by initial RTO).
        """

        sysctl.set("tcp.rto.initial_ms", 5000)
        sysctl.set("tcp.persist.timeout_max_ms", 1000)
        with self.assertRaises(ValueError) as ctx:
            sysctl.finalize_validators()
        self.assertIn(
            "tcp.persist.timeout_max_ms",
            str(ctx.exception),
            msg="The cross-knob rejection must surface the offending key.",
        )


class TestTcpSysctlBaseMss(NetworkTestCase):
    """
    The 'tcp.base_mss' per-interface sysctl tests — the
    Linux-parity cold-start MSS seed knob the PLPMTUD
    close-out reads when 'tcp.mtu_probing' enables active
    probing. Per-iface storage; bare base key rejected.
    """

    @override
    def tearDown(self) -> None:
        """
        Clear every per-iface slot and reset the template so
        a write in one test cannot leak into the next.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__tcp__sysctl__base_mss_default_is_1024(self) -> None:
        """
        Ensure 'tcp.base_mss' registers with the Linux-parity
        default of 1024 in the '"default"' template slot.

        Reference: Linux net.ipv4.tcp_base_mss (default 1024).
        """

        self.assertEqual(
            sysctl.get("tcp.default.base_mss"),
            1024,
            msg="tcp.base_mss must default to 1024 in the 'default' template (Linux parity).",
        )

    def test__tcp__sysctl__base_mss_per_iface_override(self) -> None:
        """
        Ensure writing 'tcp.<ifname>.base_mss' lands in the
        per-interface slot only — the '"default"' template
        stays at 1024 and an unconfigured interface continues
        to resolve through the template.

        Reference: Linux net.ipv4.tcp_base_mss per-iface override.
        """

        sysctl.set("tcp.tap_x.base_mss", 576)

        self.assertEqual(
            sysctl.get("tcp.tap_x.base_mss"),
            576,
            msg="Per-iface write must surface on the same key.",
        )
        self.assertEqual(
            sysctl.get("tcp.default.base_mss"),
            1024,
            msg="Per-iface write must NOT mutate the 'default' template.",
        )
        self.assertEqual(
            sysctl.get("tcp.tap_y.base_mss"),
            1024,
            msg="Unconfigured ifaces must fall back to the 'default' template.",
        )

    def test__tcp__sysctl__base_mss_rejects_below_min_mss(self) -> None:
        """
        Ensure 'tcp.base_mss' rejects 87 — one below the
        Linux 'TCP_MIN_MSS = 88' floor (include/net/tcp.h).
        A base MSS below this floor would size a cold-start
        probe so small that no useful headway is gained and
        would also slip below the IPv4 minimum-MTU arithmetic
        safety margin.

        Reference: Linux include/net/tcp.h TCP_MIN_MSS=88.
        Reference: RFC 791 §3.1 (IPv4 minimum host-handle MTU).
        """

        with self.assertRaises(ValueError):
            sysctl.set("tcp.default.base_mss", 87)
