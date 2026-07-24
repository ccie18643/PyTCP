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
This module contains unit tests for the RFC 6528 §3 Initial Sequence
Number generator in 'pytcp/lib/tcp_iss.py'.

RFC 6528 §3 mandates a hash-based ISN to defend against blind
sequence-number prediction attacks:

    ISN = M + F(localip, localport, remoteip, remoteport, secretkey)

Reference RFCs:
    RFC 6528 §3   Defending Against Sequence Number Attacks
    RFC 1948      Defending Against Sequence Number Attacks (orig)

pytcp/tests/unit/protocols/tcp/test__tcp__iss.py

ver 3.0.8
"""

import inspect
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__iss import ISS_CLOCK_RATE_US, compute_iss
from pytcp.stack import TCP__ISS_SECRET

# A fixed test secret (NOT for production; tests pin a known value
# so outputs are deterministic and known-vector tests are
# reproducible across runs).
TEST_SECRET: bytes = b"\x00" * 16

# Two arbitrary 4-tuples used across the test class to vary one
# component at a time. The fixed shape:
#   local 10.0.0.1:12345 <-> remote 10.0.0.2:80
TEST_LOCAL_IP4: Ip4Address = Ip4Address("10.0.0.1")
TEST_LOCAL_PORT: int = 12345
TEST_REMOTE_IP4: Ip4Address = Ip4Address("10.0.0.2")
TEST_REMOTE_PORT: int = 80


class TestComputeIss(TestCase):
    """
    Unit tests for 'compute_iss' covering the RFC 6528 §3
    determinism, distinguishability, time-driven, and bit-range
    invariants.
    """

    def test__compute_iss__same_args_same_iss(self) -> None:
        """
        Ensure 'compute_iss' is deterministic: identical inputs
        produce identical outputs. The hash component F must be
        a pure function of its arguments; without determinism,
        blind-attack defence is no stronger than the legacy
        'random.randint' approach because peer retransmits
        couldn't even reach a stable target.

        Reference: RFC 6528 §3 (hash-based ISN generator).
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertEqual(
            first,
            second,
            msg="compute_iss must be deterministic for identical inputs.",
        )

    def test__compute_iss__different_local_address__different_iss(self) -> None:
        """
        Ensure changing the local address changes the ISS. The
        ISN is bound to the full 4-tuple so an attacker who
        learns one ISN cannot predict ISNs for any other 4-tuple.

        Reference: RFC 6528 §3 (4-tuple binding).
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            Ip4Address("10.0.0.99"),
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg=("compute_iss must distinguish different local addresses " "(RFC 6528 §3 4-tuple binding)."),
        )

    def test__compute_iss__different_remote_address__different_iss(self) -> None:
        """
        Ensure changing the remote address changes the ISS.
        Symmetric to the local-address case.

        Reference: RFC 6528 §3 (4-tuple binding).
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            Ip4Address("10.0.0.99"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg=("compute_iss must distinguish different remote addresses " "(RFC 6528 §3 4-tuple binding)."),
        )

    def test__compute_iss__different_local_port__different_iss(self) -> None:
        """
        Ensure changing the local port changes the ISS.

        Reference: RFC 6528 §3 (4-tuple binding).
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            54321,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg="compute_iss must distinguish different local ports.",
        )

    def test__compute_iss__different_remote_port__different_iss(self) -> None:
        """
        Ensure changing the remote port changes the ISS.

        Reference: RFC 6528 §3 (4-tuple binding).
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            8080,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg="compute_iss must distinguish different remote ports.",
        )

    def test__compute_iss__different_secret__different_iss(self) -> None:
        """
        Ensure changing the secret changes the ISS. The secret
        is the load-bearing keying material for the PRF F;
        without secret-dependence an attacker could compute
        ISNs for any 4-tuple just by knowing the algorithm.

        Reference: RFC 6528 §3 (secret-keyed PRF).
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            b"\x00" * 16,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            b"\xff" * 16,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg=(
                "compute_iss must distinguish different secrets - the "
                "PRF F's keying material is load-bearing for RFC 6528 §3."
            ),
        )

    def test__compute_iss__output_is_uint32(self) -> None:
        """
        Ensure 'compute_iss' returns a value within the 32-bit
        unsigned integer range '[0, 2**32 - 1]'. TCP sequence
        numbers are 32-bit; a return value outside the range
        would corrupt outbound segment construction.

        Reference: RFC 9293 §3.4 (32-bit sequence-number space).
        """

        result = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertGreaterEqual(
            result,
            0,
            msg="compute_iss output must be >= 0 (32-bit unsigned).",
        )
        self.assertLess(
            result,
            2**32,
            msg=f"compute_iss output must be < 2**32; got {result}.",
        )

    def test__compute_iss__monotonic_in_clock_us(self) -> None:
        """
        Ensure the time-driven 'M' component of the ISN advances
        with 'clock_us'. Specifically, two ISN values for the
        same 4-tuple computed at clocks differing by 'delta_us'
        must differ by 'delta_us / ISS_CLOCK_RATE_US' (modulo
        the 32-bit wrap), because M advances one tick per
        ISS_CLOCK_RATE_US µs and F is identical for identical
        4-tuples.

        The delta uses 32 ticks so the test is robust to the M
        component's resolution while still well below the
        32-bit wrap window (~4.77 h).

        Reference: RFC 6528 §3 (time-driven M component).
        """

        delta_ticks = 32
        delta_us = delta_ticks * ISS_CLOCK_RATE_US

        iss_t0 = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        iss_t1 = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=delta_us,
        )

        observed_delta = (iss_t1 - iss_t0) & 0xFFFF_FFFF

        self.assertEqual(
            observed_delta,
            delta_ticks,
            msg=(
                f"compute_iss M-component must advance one tick per "
                f"{ISS_CLOCK_RATE_US} µs of 'clock_us'; expected delta of "
                f"{delta_ticks} ticks for {delta_us} µs of clock advance, "
                f"got {observed_delta}."
            ),
        )

    def test__compute_iss__different_4tuple_at_same_clock_yields_different_iss(self) -> None:
        """
        Ensure that for a SAME clock value, two unrelated
        4-tuples produce different ISN values. This is the
        4-tuple-binding property in aggregate: the F component
        must dominate the ISN bits (the M component is
        identical when clocks match, so any difference between
        two ISNs at the same clock comes entirely from F).

        Reference: RFC 6528 §3 (F-component 4-tuple distinguishability).
        """

        iss_a = compute_iss(
            Ip4Address("10.0.0.1"),
            11111,
            Ip4Address("10.0.0.2"),
            22222,
            TEST_SECRET,
            clock_us=1234,
        )
        iss_b = compute_iss(
            Ip4Address("10.0.0.3"),
            33333,
            Ip4Address("10.0.0.4"),
            44444,
            TEST_SECRET,
            clock_us=1234,
        )

        self.assertNotEqual(
            iss_a,
            iss_b,
            msg=("Two distinct 4-tuples at the same clock must yield " "different ISN values (F component must vary)."),
        )

    def test__compute_iss__ip6_addresses_supported(self) -> None:
        """
        Ensure 'compute_iss' accepts IPv6 addresses for both
        local and remote endpoints. PyTCP supports both
        address families; the ISN generator must too.

        Reference: RFC 6528 §3 (works on any address-family 4-tuple).
        """

        result = compute_iss(
            Ip6Address("2001:db8::1"),
            TEST_LOCAL_PORT,
            Ip6Address("2001:db8::2"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 2**32)

    def test__compute_iss__ip4_and_ip6_for_same_logical_4tuple_differ(self) -> None:
        """
        Ensure an IPv4 4-tuple and a (notional) IPv6 4-tuple
        with the "same" port shape produce different ISNs. The
        binding includes the address bytes, not just an
        abstract identity, so a host running parallel IPv4 /
        IPv6 services on the same port pair MUST get different
        ISNs per address family.

        Reference: RFC 6528 §3 (address bytes in PRF input).
        """

        iss_v4 = compute_iss(
            Ip4Address("10.0.0.1"),
            TEST_LOCAL_PORT,
            Ip4Address("10.0.0.2"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        iss_v6 = compute_iss(
            Ip6Address("2001:db8::1"),
            TEST_LOCAL_PORT,
            Ip6Address("2001:db8::2"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            iss_v4,
            iss_v6,
            msg=(
                "IPv4 and IPv6 'same-shape' 4-tuples must produce "
                "different ISNs - the binding includes address bytes."
            ),
        )

    def test__compute_iss__same_4tuple_post_msl_yields_different_iss(self) -> None:
        """
        Ensure that PyTCP skips the literal MSL Quiet Time
        wait on startup (the spec explicitly allows this as a
        MAY) and relies on the hashed ISS for the equivalent
        collision-resistance guarantee.

        Specifically, after one MSL has elapsed (PyTCP's
        TCP__TIME_WAIT__DELAY_MS = 30 s = 30_000_000 µs), an ISS for
        the SAME 4-tuple computed at the post-MSL clock is
        guaranteed to differ from the pre-MSL ISS by
        '30_000_000 / ISS_CLOCK_RATE_US = 7_500_000' ticks.
        That delta is far larger than any plausible in-flight
        sequence-window, so a delayed segment from a prior
        incarnation cannot collide with a fresh ISN.

        Reference: RFC 9293 §3.4.3 (Quiet Time MAY-skip alternative).
        """

        msl_us = 30_000_000  # PyTCP's TCP__TIME_WAIT__DELAY_MS in microseconds.
        expected_delta_ticks = msl_us // ISS_CLOCK_RATE_US

        iss_pre = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        iss_post = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=msl_us,
        )

        observed_delta = (iss_post - iss_pre) & 0xFFFF_FFFF
        self.assertEqual(
            observed_delta,
            expected_delta_ticks,
            msg=(
                f"RFC 9293 §3.4.3 Quiet Time alternative: same-4-"
                f"tuple ISS post-MSL ({msl_us} µs) MUST differ "
                f"from pre-MSL ISS by exactly {expected_delta_ticks} "
                f"ticks (M-component advance). Got delta="
                f"{observed_delta} ticks."
            ),
        )
        self.assertNotEqual(
            iss_pre,
            iss_post,
            msg=(
                "RFC 9293 §3.4.3: same-4-tuple ISS pre/post MSL "
                "MUST differ. The M-component advance prevents a "
                "delayed segment from a prior incarnation from "
                "colliding with a fresh ISS."
            ),
        )


class TestTcpIssSecret(TestCase):
    """
    Unit tests pinning the ISS secret bootstrap-rotation contract
    described in RFC 6528 §3.
    """

    def test__tcp__iss__secret_length_is_128_bits(self) -> None:
        """
        Ensure the bootstrap-generated ISS secret is exactly 128
        bits (16 bytes) wide. A regression that shortened the
        secret would weaken the off-path threat model the
        algorithm targets.

        Reference: RFC 6528 §3 (key lengths of 128 bits should be adequate).
        """

        self.assertEqual(
            len(TCP__ISS_SECRET),
            16,
            msg=("RFC 6528 §3: the ISS secret MUST be 128 bits " f"(16 bytes). Got: {len(TCP__ISS_SECRET)} bytes."),
        )

    def test__tcp__iss__secret_is_bytes(self) -> None:
        """
        Ensure the bootstrap-generated ISS secret is a bytes
        object, the input shape consumed by 'compute_iss'.

        Reference: RFC 6528 §3 (secret as opaque keying material).
        """

        self.assertIsInstance(
            TCP__ISS_SECRET,
            bytes,
            msg=(
                "RFC 6528 §3: the ISS secret MUST be opaque keying " f"material. Got: {type(TCP__ISS_SECRET).__name__}."
            ),
        )


class TestComputeIssMutationGoldens(TestCase):
    """
    Deterministic exact-output goldens for compute_iss with a fixed
    4-tuple / secret / clock, closing the hash and M-component
    arithmetic mutation survivors. Any change to the port encoding,
    digest truncation, clock rate, or the M+F combination moves the
    output away from the literal.
    """

    _LOCAL = Ip4Address("10.0.0.1")
    _REMOTE = Ip4Address("10.0.0.2")
    _SECRET = bytes(16)

    def test__tcp__iss__exact_value_at_clock_zero(self) -> None:
        """
        Ensure compute_iss with clock_us=0 returns the exact SHA-256
        F component, pinning the secret / address / port hashing.

        Reference: RFC 6528 §3 (ISN = M + F, F = hash of the 4-tuple + secret).
        """

        self.assertEqual(
            compute_iss(self._LOCAL, 12345, self._REMOTE, 80, self._SECRET, clock_us=0),
            1878479098,
            msg="compute_iss at clock_us=0 must equal the exact F = 1878479098.",
        )

    def test__tcp__iss__clock_advances_m_at_4us_per_tick(self) -> None:
        """
        Ensure the M component is clock_us // 4 added to F: clock_us=40
        adds 10 and clock_us=400000 adds 100000, pinning the clock
        rate and the M+F combination.

        Reference: RFC 6528 §3 (M = clock / 4 us, ISN = M + F).
        """

        self.assertEqual(
            compute_iss(self._LOCAL, 12345, self._REMOTE, 80, self._SECRET, clock_us=40),
            1878479108,
            msg="clock_us=40 must add M=10 to F (1878479108).",
        )
        self.assertEqual(
            compute_iss(self._LOCAL, 12345, self._REMOTE, 80, self._SECRET, clock_us=400000),
            1878579098,
            msg="clock_us=400000 must add M=100000 to F (1878579098).",
        )

    def test__tcp__iss__port_change_changes_output(self) -> None:
        """
        Ensure the local port participates in the hash via its exact
        2-byte big-endian encoding: a one-unit port change yields a
        wholly different ISN.

        Reference: RFC 6528 §3 (F depends on every 4-tuple field).
        """

        self.assertEqual(
            compute_iss(self._LOCAL, 12346, self._REMOTE, 80, self._SECRET, clock_us=0),
            3565056387,
            msg="local port 12346 must yield the exact ISN 3565056387.",
        )

    def test__tcp__iss__clock_us_is_keyword_only(self) -> None:
        """
        Ensure clock_us is a keyword-only parameter so a caller cannot
        pass it positionally (kills the '*'→'/' separator mutation).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(compute_iss).parameters["clock_us"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="clock_us must be keyword-only.",
        )

    def test__tcp__iss__clock_rate_constant_is_four(self) -> None:
        """
        Ensure the RFC 6528 M clock rate is exactly 4 microseconds per
        tick.

        Reference: RFC 6528 §3 (M increments once every 4 us).
        """

        self.assertEqual(
            ISS_CLOCK_RATE_US,
            4,
            msg="ISS_CLOCK_RATE_US must be 4 us per tick.",
        )
