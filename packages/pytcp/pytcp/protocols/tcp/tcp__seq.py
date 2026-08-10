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
This module contains modular 32-bit arithmetic helpers for TCP sequence
and acknowledgement numbers, per RFC 9293 §3.4.

pytcp/protocols/tcp/tcp__seq.py

ver 3.0.10
"""

from net_proto.lib.int_checks import UINT_32__MAX, is_uint32

# Documentation type alias for 32-bit modular sequence numbers (RFC 9293
# §3.4). PEP 695 transparent alias: mypy treats 'Seq32' as 'int' so plain
# integers pass through every API without runtime wrapping or boundary
# friction; the alias only signals to the reader "this value is a TCP seq
# / ack number and MUST be compared via the helpers in this module, not
# Python's built-in comparison operators". Use for parameters, return
# values, and dataclass fields that hold a seq number; do not use for
# byte counts, lengths, or window sizes.
type Seq32 = int


# RFC 9293 §3.4 defines TCP sequence and acknowledgement numbers as 32-bit
# unsigned integers compared modulo 2**32. A value 'a' is "less than" 'b' iff
# the unsigned forward distance (b - a) & 0xFFFFFFFF lies in (0, 2**31).
# At the diametric midpoint distance == 2**31 the forward and backward arcs
# are equal length, so the sign of the relation is genuinely ambiguous; we
# break the tie by raw numerical order so that 'lt32' / 'gt32' / equality
# remain mutually exclusive (trichotomy). Plain Python '<' on raw seq numbers
# breaks the moment either side crosses 2**32-1, hence this module.

SEQ32__HALF = 0x8000_0000


def lt32(a: Seq32, b: Seq32, /) -> bool:
    """
    Return True if 'a' is strictly before 'b' in modular 32-bit
    sequence-number space, per RFC 9293 §3.4.
    """

    assert is_uint32(a), f"The 'a' argument must be a 32-bit unsigned integer. Got: {a!r}"
    assert is_uint32(b), f"The 'b' argument must be a 32-bit unsigned integer. Got: {b!r}"

    diff = (b - a) & UINT_32__MAX
    if diff == SEQ32__HALF:
        return a < b
    return 0 < diff < SEQ32__HALF


def le32(a: Seq32, b: Seq32, /) -> bool:
    """
    Return True if 'a' is before or equal to 'b' in modular 32-bit
    sequence-number space, per RFC 9293 §3.4.
    """

    assert is_uint32(a), f"The 'a' argument must be a 32-bit unsigned integer. Got: {a!r}"
    assert is_uint32(b), f"The 'b' argument must be a 32-bit unsigned integer. Got: {b!r}"

    diff = (b - a) & UINT_32__MAX
    if diff == SEQ32__HALF:
        return a < b
    return diff < SEQ32__HALF


def gt32(a: Seq32, b: Seq32, /) -> bool:
    """
    Return True if 'a' is strictly after 'b' in modular 32-bit
    sequence-number space, per RFC 9293 §3.4.
    """

    # Deliberate operand swap: 'a > b' holds iff 'b < a'.
    return lt32(b, a)  # pylint: disable=arguments-out-of-order


def ge32(a: Seq32, b: Seq32, /) -> bool:
    """
    Return True if 'a' is after or equal to 'b' in modular 32-bit
    sequence-number space, per RFC 9293 §3.4.
    """

    # Deliberate operand swap: 'a >= b' holds iff 'b <= a'.
    return le32(b, a)  # pylint: disable=arguments-out-of-order


def add32(a: Seq32, /, *rest: int) -> Seq32:
    """
    Return 'a + sum(rest)' reduced to a 32-bit unsigned value.

    Variadic form: any number of trailing operands are summed and
    the total reduced modulo 2**32. Modular addition is
    associative, so the variadic semantics match repeated binary
    application: 'add32(a, b, c) == add32(add32(a, b), c)'. The
    common 'tcp__session.py' pattern of summing a base seq with a
    payload length and one or two flag bits ('seq + len(data) +
    flag_syn + flag_fin') becomes a single readable call:
    'add32(seq, len(data), flag_syn, flag_fin)'.
    """

    return (a + sum(rest)) & UINT_32__MAX


def sub32(a: Seq32, n: int, /) -> Seq32:
    """
    Return 'a - n' reduced to a 32-bit unsigned value.
    """

    return (a - n) & UINT_32__MAX


def in_range32(x: Seq32, lo: Seq32, hi: Seq32, /) -> bool:
    """
    Return True if 'x' lies within the closed inclusive modular range
    [lo, hi] interpreted in forward direction (lo -> hi), wrapping at
    2**32 if necessary. When lo == hi, only x == lo qualifies.
    """

    assert is_uint32(x), f"The 'x' argument must be a 32-bit unsigned integer. Got: {x!r}"
    assert is_uint32(lo), f"The 'lo' argument must be a 32-bit unsigned integer. Got: {lo!r}"
    assert is_uint32(hi), f"The 'hi' argument must be a 32-bit unsigned integer. Got: {hi!r}"

    return ((x - lo) & UINT_32__MAX) <= ((hi - lo) & UINT_32__MAX)
