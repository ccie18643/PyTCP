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
This module contains tests for the TCP modular sequence-number arithmetic
helpers in 'pytcp.protocols.tcp.tcp__seq', covering RFC 9293 §3.4 comparison semantics
and the wrap-aware add/sub/in-range utilities.

pytcp/tests/unit/protocols/tcp/test__tcp__seq.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto.lib.int_checks import UINT_32__MAX
from pytcp.protocols.tcp.tcp__seq import (
    SEQ32__HALF,
    add32,
    ge32,
    gt32,
    in_range32,
    le32,
    lt32,
    sub32,
)
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Equal at zero - no ordering, equality only.",
            "_a": 0x0000_0000,
            "_b": 0x0000_0000,
            "_results": {"lt": False, "le": True, "gt": False, "ge": True},
        },
        {
            "_description": "Equal at the 32-bit ceiling.",
            "_a": UINT_32__MAX,
            "_b": UINT_32__MAX,
            "_results": {"lt": False, "le": True, "gt": False, "ge": True},
        },
        {
            "_description": "Equal at the modular midpoint 2**31.",
            "_a": SEQ32__HALF,
            "_b": SEQ32__HALF,
            "_results": {"lt": False, "le": True, "gt": False, "ge": True},
        },
        {
            "_description": "'a' is exactly one byte before 'b'.",
            "_a": 0x0000_0000,
            "_b": 0x0000_0001,
            "_results": {"lt": True, "le": True, "gt": False, "ge": False},
        },
        {
            "_description": "'a' is exactly one byte after 'b'.",
            "_a": 0x0000_0001,
            "_b": 0x0000_0000,
            "_results": {"lt": False, "le": False, "gt": True, "ge": True},
        },
        {
            "_description": "'a' is well before 'b' within the forward half.",
            "_a": 0x0000_0000,
            "_b": 0x0000_03E8,
            "_results": {"lt": True, "le": True, "gt": False, "ge": False},
        },
        {
            "_description": "'a' is just under 2**31 byte before 'b'.",
            "_a": 0x0000_0000,
            "_b": SEQ32__HALF - 1,
            "_results": {"lt": True, "le": True, "gt": False, "ge": False},
        },
        {
            "_description": "'a' is exactly 2**31 before 'b' - tiebreak by numerical order (RFC 9293 §3.4).",
            "_a": 0x0000_0000,
            "_b": SEQ32__HALF,
            "_results": {"lt": True, "le": True, "gt": False, "ge": False},
        },
        {
            "_description": "'a' is 2**31+1 before 'b' - closer in backward direction, so resolves as 'after'.",
            "_a": 0x0000_0000,
            "_b": SEQ32__HALF + 1,
            "_results": {"lt": False, "le": False, "gt": True, "ge": True},
        },
        {
            "_description": "Forward-direction wrap - 'a' near 2**32-1, 'b' small.",
            "_a": UINT_32__MAX - 1,
            "_b": 0x0000_0010,
            "_results": {"lt": True, "le": True, "gt": False, "ge": False},
        },
        {
            "_description": "Backward-direction wrap - 'a' small, 'b' near 2**32-1.",
            "_a": 0x0000_0010,
            "_b": UINT_32__MAX - 1,
            "_results": {"lt": False, "le": False, "gt": True, "ge": True},
        },
        {
            "_description": "Adjacent across wrap - 'a' at 2**32-1, 'b' at zero.",
            "_a": UINT_32__MAX,
            "_b": 0x0000_0000,
            "_results": {"lt": True, "le": True, "gt": False, "ge": False},
        },
        {
            "_description": "Adjacent across wrap reversed - 'a' at zero, 'b' at 2**32-1.",
            "_a": 0x0000_0000,
            "_b": UINT_32__MAX,
            "_results": {"lt": False, "le": False, "gt": True, "ge": True},
        },
    ]
)
class TestTcpSeq__Comparators(TestCase):
    """
    The 'lt32' / 'le32' / 'gt32' / 'ge32' modular-comparator matrix.
    """

    _description: str
    _a: int
    _b: int
    _results: dict[str, Any]

    def test__lib__tcp_seq__lt32(self) -> None:
        """
        Ensure 'lt32(a, b)' is True iff 'a' is strictly before 'b'
        in modular 32-bit sequence-number space.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        self.assertEqual(
            lt32(self._a, self._b),
            self._results["lt"],
            msg=f"Unexpected 'lt32' result for case: {self._description}",
        )

    def test__lib__tcp_seq__le32(self) -> None:
        """
        Ensure 'le32(a, b)' is True iff 'a' is before or equal to 'b'
        in modular 32-bit sequence-number space.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        self.assertEqual(
            le32(self._a, self._b),
            self._results["le"],
            msg=f"Unexpected 'le32' result for case: {self._description}",
        )

    def test__lib__tcp_seq__gt32(self) -> None:
        """
        Ensure 'gt32(a, b)' is True iff 'a' is strictly after 'b'
        in modular 32-bit sequence-number space.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        self.assertEqual(
            gt32(self._a, self._b),
            self._results["gt"],
            msg=f"Unexpected 'gt32' result for case: {self._description}",
        )

    def test__lib__tcp_seq__ge32(self) -> None:
        """
        Ensure 'ge32(a, b)' is True iff 'a' is after or equal to 'b'
        in modular 32-bit sequence-number space.

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        self.assertEqual(
            ge32(self._a, self._b),
            self._results["ge"],
            msg=f"Unexpected 'ge32' result for case: {self._description}",
        )

    def test__lib__tcp_seq__total_ordering_invariant(self) -> None:
        """
        Ensure for any two 32-bit values exactly one of (a<b, a==b, a>b)
        holds and 'le32' / 'ge32' agree with their strict counterparts
        plus equality.

        Reference: RFC 9293 §3.4 (modular sequence-number ordering).
        """

        is_lt = lt32(self._a, self._b)
        is_gt = gt32(self._a, self._b)
        is_eq = self._a == self._b

        self.assertEqual(
            (is_lt, is_eq, is_gt).count(True),
            1,
            msg=f"Trichotomy invariant violated for case: {self._description}",
        )
        self.assertEqual(
            le32(self._a, self._b),
            is_lt or is_eq,
            msg=f"'le32' disagrees with 'lt32 or ==' for case: {self._description}",
        )
        self.assertEqual(
            ge32(self._a, self._b),
            is_gt or is_eq,
            msg=f"'ge32' disagrees with 'gt32 or ==' for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Zero plus zero stays at zero.",
            "_a": 0x0000_0000,
            "_n": 0,
            "_results": {"add": 0x0000_0000, "sub": 0x0000_0000},
        },
        {
            "_description": "Typical small forward step, no wrap.",
            "_a": 0x0000_0064,
            "_n": 50,
            "_results": {"add": 0x0000_0096, "sub": 0x0000_0032},
        },
        {
            "_description": "Add lands exactly on 2**32-1 (no wrap).",
            "_a": 0xFFFF_FFFE,
            "_n": 1,
            "_results": {"add": 0xFFFF_FFFF, "sub": 0xFFFF_FFFD},
        },
        {
            "_description": "Add wraps past 2**32-1 by a few bytes.",
            "_a": 0xFFFF_FFFE,
            "_n": 5,
            "_results": {"add": 0x0000_0003, "sub": 0xFFFF_FFF9},
        },
        {
            "_description": "Add zero is identity.",
            "_a": 0xABCD_EF01,
            "_n": 0,
            "_results": {"add": 0xABCD_EF01, "sub": 0xABCD_EF01},
        },
        {
            "_description": "Sub wraps under zero (negative result wraps to upper half).",
            "_a": 0x0000_0005,
            "_n": 0x10,
            "_results": {"add": 0x0000_0015, "sub": 0xFFFF_FFF5},
        },
        {
            "_description": "Negative 'n' makes 'add32' behave like 'sub32'.",
            "_a": 0x0000_0064,
            "_n": -50,
            "_results": {"add": 0x0000_0032, "sub": 0x0000_0096},
        },
        {
            "_description": "Huge 'n' beyond 2**32 reduces correctly modulo 2**32.",
            "_a": 0x0000_0000,
            "_n": 0x1_0000_0005,
            "_results": {"add": 0x0000_0005, "sub": 0xFFFF_FFFB},
        },
        {
            "_description": "2**32-1 plus one wraps to zero.",
            "_a": UINT_32__MAX,
            "_n": 1,
            "_results": {"add": 0x0000_0000, "sub": 0xFFFF_FFFE},
        },
    ]
)
class TestTcpSeq__AddSub(TestCase):
    """
    The 'add32' / 'sub32' modular-arithmetic matrix.
    """

    _description: str
    _a: int
    _n: int
    _results: dict[str, Any]

    def test__lib__tcp_seq__add32(self) -> None:
        """
        Ensure 'add32(a, n)' returns '(a + n) mod 2**32' as a 32-bit
        unsigned integer for any 'n', positive, zero, or negative.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        result = add32(self._a, self._n)

        self.assertEqual(
            result,
            self._results["add"],
            msg=f"Unexpected 'add32' result for case: {self._description}",
        )
        self.assertTrue(
            0 <= result <= UINT_32__MAX,
            msg=f"'add32' result out of 32-bit unsigned range for case: {self._description}",
        )

    def test__lib__tcp_seq__sub32(self) -> None:
        """
        Ensure 'sub32(a, n)' returns '(a - n) mod 2**32' as a 32-bit
        unsigned integer for any 'n', positive, zero, or negative.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        result = sub32(self._a, self._n)

        self.assertEqual(
            result,
            self._results["sub"],
            msg=f"Unexpected 'sub32' result for case: {self._description}",
        )
        self.assertTrue(
            0 <= result <= UINT_32__MAX,
            msg=f"'sub32' result out of 32-bit unsigned range for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Linear range, value strictly inside.",
            "_x": 0x0000_0005,
            "_lo": 0x0000_0000,
            "_hi": 0x0000_000A,
            "_result": True,
        },
        {
            "_description": "Linear range, value above 'hi'.",
            "_x": 0x0000_000B,
            "_lo": 0x0000_0000,
            "_hi": 0x0000_000A,
            "_result": False,
        },
        {
            "_description": "Linear range, value below 'lo'.",
            "_x": 0x0000_0004,
            "_lo": 0x0000_0005,
            "_hi": 0x0000_000A,
            "_result": False,
        },
        {
            "_description": "Linear range, 'x' equals 'lo' (left boundary inclusive).",
            "_x": 0x0000_0000,
            "_lo": 0x0000_0000,
            "_hi": 0x0000_000A,
            "_result": True,
        },
        {
            "_description": "Linear range, 'x' equals 'hi' (right boundary inclusive).",
            "_x": 0x0000_000A,
            "_lo": 0x0000_0000,
            "_hi": 0x0000_000A,
            "_result": True,
        },
        {
            "_description": "Empty range (lo == hi), 'x' equals both - the only accepted point.",
            "_x": 0x0000_0005,
            "_lo": 0x0000_0005,
            "_hi": 0x0000_0005,
            "_result": True,
        },
        {
            "_description": "Empty range (lo == hi), 'x' differs - rejected.",
            "_x": 0x0000_0004,
            "_lo": 0x0000_0005,
            "_hi": 0x0000_0005,
            "_result": False,
        },
        {
            "_description": "Wrapping range, 'x' in lower (post-wrap) part.",
            "_x": 0x0000_0005,
            "_lo": 0xFFFF_FFFE,
            "_hi": 0x0000_0010,
            "_result": True,
        },
        {
            "_description": "Wrapping range, 'x' in upper (pre-wrap) part.",
            "_x": 0xFFFF_FFFF,
            "_lo": 0xFFFF_FFFE,
            "_hi": 0x0000_0010,
            "_result": True,
        },
        {
            "_description": "Wrapping range, 'x' equals 'lo'.",
            "_x": 0xFFFF_FFFE,
            "_lo": 0xFFFF_FFFE,
            "_hi": 0x0000_0010,
            "_result": True,
        },
        {
            "_description": "Wrapping range, 'x' equals 'hi'.",
            "_x": 0x0000_0010,
            "_lo": 0xFFFF_FFFE,
            "_hi": 0x0000_0010,
            "_result": True,
        },
        {
            "_description": "Wrapping range, 'x' falls past 'hi' in the post-wrap segment.",
            "_x": 0x0000_0020,
            "_lo": 0xFFFF_FFFE,
            "_hi": 0x0000_0010,
            "_result": False,
        },
        {
            "_description": "Full range covers every 32-bit value.",
            "_x": 0x1234_5678,
            "_lo": 0x0000_0000,
            "_hi": UINT_32__MAX,
            "_result": True,
        },
        {
            "_description": "Full range, 'x' at 0 (left edge).",
            "_x": 0x0000_0000,
            "_lo": 0x0000_0000,
            "_hi": UINT_32__MAX,
            "_result": True,
        },
        {
            "_description": "Full range, 'x' at 2**32-1 (right edge).",
            "_x": UINT_32__MAX,
            "_lo": 0x0000_0000,
            "_hi": UINT_32__MAX,
            "_result": True,
        },
        {
            # Far-wrap boundary: 'x' sits at the maximum forward distance
            # (2**32-1 ahead of 'lo', i.e. one step *before* it), so it is
            # outside a small forward window. This pins the 32-bit mask
            # '(x - lo) & UINT_32__MAX' against an off-by-wrap error in the
            # distance computation, where the masked distance (2**32-1)
            # would otherwise collapse to 0 and wrongly report 'x' in range.
            "_description": "'x' at maximum forward distance (2**32-1 ahead of 'lo') is outside a small range.",
            "_x": UINT_32__MAX,
            "_lo": 0x0000_0000,
            "_hi": 0x0000_0010,
            "_result": False,
        },
    ]
)
class TestTcpSeq__InRange(TestCase):
    """
    The 'in_range32' modular closed-interval matrix.
    """

    _description: str
    _x: int
    _lo: int
    _hi: int
    _result: bool

    def test__lib__tcp_seq__in_range32(self) -> None:
        """
        Ensure 'in_range32(x, lo, hi)' is True iff 'x' lies on the
        forward modular path from 'lo' to 'hi' (inclusive at both ends).

        Reference: RFC 9293 §3.4 (modular sequence-number comparison).
        """

        self.assertEqual(
            in_range32(self._x, self._lo, self._hi),
            self._result,
            msg=f"Unexpected 'in_range32' result for case: {self._description}",
        )


class TestTcpSeq__ComparatorAsserts(TestCase):
    """
    The comparator input-bounds assertions.
    """

    def test__lib__tcp_seq__lt32__rejects_negative_a(self) -> None:
        """
        Ensure 'lt32' rejects a negative 'a' argument.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as error:
            lt32(-1, 0)

        self.assertIn(
            "'a' argument must be a 32-bit unsigned integer",
            str(error.exception),
            msg="'lt32' must surface the 'a'-out-of-range assertion message.",
        )

    def test__lib__tcp_seq__lt32__rejects_negative_b(self) -> None:
        """
        Ensure 'lt32' rejects a negative 'b' argument.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as error:
            lt32(0, -1)

        self.assertIn(
            "'b' argument must be a 32-bit unsigned integer",
            str(error.exception),
            msg="'lt32' must surface the 'b'-out-of-range assertion message.",
        )

    def test__lib__tcp_seq__lt32__rejects_overflow_a(self) -> None:
        """
        Ensure 'lt32' rejects an 'a' argument greater than 2**32-1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            lt32(UINT_32__MAX + 1, 0)

    def test__lib__tcp_seq__lt32__rejects_overflow_b(self) -> None:
        """
        Ensure 'lt32' rejects a 'b' argument greater than 2**32-1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            lt32(0, UINT_32__MAX + 1)

    def test__lib__tcp_seq__le32__rejects_negative_a(self) -> None:
        """
        Ensure 'le32' rejects a negative 'a' argument.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            le32(-1, 0)

    def test__lib__tcp_seq__le32__rejects_overflow_b(self) -> None:
        """
        Ensure 'le32' rejects a 'b' argument greater than 2**32-1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            le32(0, UINT_32__MAX + 1)

    def test__lib__tcp_seq__gt32__delegates_assertion_to_lt32(self) -> None:
        """
        Ensure 'gt32' inherits 'lt32' bounds checks via delegation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            gt32(-1, 0)

    def test__lib__tcp_seq__ge32__delegates_assertion_to_le32(self) -> None:
        """
        Ensure 'ge32' inherits 'le32' bounds checks via delegation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            ge32(UINT_32__MAX + 1, 0)


class TestTcpSeq__InRangeAsserts(TestCase):
    """
    The 'in_range32' input-bounds assertions.
    """

    def test__lib__tcp_seq__in_range32__rejects_negative_x(self) -> None:
        """
        Ensure 'in_range32' rejects a negative 'x' argument.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as error:
            in_range32(-1, 0, 0)

        self.assertIn(
            "'x' argument must be a 32-bit unsigned integer",
            str(error.exception),
            msg="'in_range32' must surface the 'x'-out-of-range assertion message.",
        )

    def test__lib__tcp_seq__in_range32__rejects_negative_lo(self) -> None:
        """
        Ensure 'in_range32' rejects a negative 'lo' argument.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as error:
            in_range32(0, -1, 0)

        self.assertIn(
            "'lo' argument must be a 32-bit unsigned integer",
            str(error.exception),
            msg="'in_range32' must surface the 'lo'-out-of-range assertion message.",
        )

    def test__lib__tcp_seq__in_range32__rejects_negative_hi(self) -> None:
        """
        Ensure 'in_range32' rejects a negative 'hi' argument.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as error:
            in_range32(0, 0, -1)

        self.assertIn(
            "'hi' argument must be a 32-bit unsigned integer",
            str(error.exception),
            msg="'in_range32' must surface the 'hi'-out-of-range assertion message.",
        )

    def test__lib__tcp_seq__in_range32__rejects_overflow_x(self) -> None:
        """
        Ensure 'in_range32' rejects an 'x' argument greater than 2**32-1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            in_range32(UINT_32__MAX + 1, 0, 0)

    def test__lib__tcp_seq__in_range32__rejects_overflow_lo(self) -> None:
        """
        Ensure 'in_range32' rejects a 'lo' argument greater than 2**32-1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            in_range32(0, UINT_32__MAX + 1, 0)

    def test__lib__tcp_seq__in_range32__rejects_overflow_hi(self) -> None:
        """
        Ensure 'in_range32' rejects a 'hi' argument greater than 2**32-1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            in_range32(0, 0, UINT_32__MAX + 1)


class TestTcpSeqAdd32__Variadic(TestCase):
    """
    The 'add32' variadic-form tests: confirm the single-arg, two-
    arg, and N-arg cases all reduce modulo 2**32 correctly. Modular
    addition is associative, so the variadic form's semantics
    match repeated binary application.
    """

    def test__lib__tcp_seq__add32__single_arg_returns_self(self) -> None:
        """
        Ensure 'add32(a)' (no trailing operands) returns 'a'
        unchanged - the empty-rest sum is 0.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        self.assertEqual(
            add32(123456),
            123456,
            msg=("add32 with a single operand and no trailing args " "must return that operand unchanged."),
        )

    def test__lib__tcp_seq__add32__three_arg_form_matches_chained_binary(self) -> None:
        """
        Ensure 'add32(a, b, c)' matches the chained binary form
        'add32(add32(a, b), c)'.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        a, b, c = 0xFFFF_FF00, 0x100, 0x50
        self.assertEqual(
            add32(a, b, c),
            add32(add32(a, b), c),
            msg=("add32(a, b, c) must equal add32(add32(a, b), c) - " "modular addition is associative."),
        )

    def test__lib__tcp_seq__add32__four_arg_form_wraps_correctly(self) -> None:
        """
        Ensure 'add32(seq, len, flag_syn, flag_fin)' - the canonical
        TCP session usage pattern - wraps modulo 2**32 when the
        cumulative sum exceeds the 32-bit ceiling.

        Reference: RFC 9293 §3.4 (SYN/FIN consume one seq each; modular wrap).
        """

        # seq just below the wrap, plus a 4-byte payload, plus
        # flag_syn=1, plus flag_fin=0.
        result = add32(0xFFFF_FFFE, 4, 1, 0)
        # Expected: (0xFFFF_FFFE + 4 + 1 + 0) mod 2**32 = 3.
        self.assertEqual(
            result,
            3,
            msg=(
                "add32 over a 4-operand sum that crosses the 32-bit "
                "wrap must return the modular reduction (= 3 here)."
            ),
        )

    def test__lib__tcp_seq__add32__five_arg_form_associative(self) -> None:
        """
        Ensure five-operand variadic add equals iterative binary
        accumulation - sanity check on the implementation's
        'sum(rest)' fold.

        Reference: RFC 9293 §3.4 (modular sequence-number arithmetic).
        """

        operands = [0xDEAD_BEEF, 0x1, 0x2, 0x3, 0x4]
        result = add32(*operands)
        expected = operands[0]
        for operand in operands[1:]:
            expected = (expected + operand) & UINT_32__MAX
        self.assertEqual(
            result,
            expected,
            msg=("Variadic add32 must equal iterative binary fold " "for any operand count."),
        )
