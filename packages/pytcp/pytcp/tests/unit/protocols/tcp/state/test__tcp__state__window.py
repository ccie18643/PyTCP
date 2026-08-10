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
Unit tests for WindowState.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__window.py

ver 3.0.9
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__window import (
    WindowState,
    derive_rcv_wscale,
)


class TestWindowState(TestCase):
    """
    Default values + bump_max_window behaviour.
    """

    def test__window_state__defaults(self) -> None:
        """
        Ensure snd_mss defaults to 536 (RFC 879 / 9293 §3.7.5),
        rcv_wsc defaults to 7 (canonical Linux WSCALE), rcv_wnd_max
        defaults to 65535 (uint16 ceiling), other fields default
        to 0.

        Reference: RFC 9293 §3.7.1 (MSS default).
        Reference: RFC 7323 §2.3 (WSCALE shift).
        """

        s = WindowState()
        self.assertEqual(s.snd_mss, 536, msg="snd_mss must default to 536.")
        self.assertEqual(s.snd_wnd, 0, msg="snd_wnd must default to 0.")
        self.assertEqual(s.snd_wsc, 0, msg="snd_wsc must default to 0.")
        self.assertEqual(s.max_window, 0, msg="max_window must default to 0.")
        self.assertEqual(s.rcv_mss, 0, msg="rcv_mss must default to 0.")
        self.assertEqual(s.rcv_wsc, 7, msg="rcv_wsc must default to 7.")
        self.assertEqual(s.rcv_wnd_max, 65535, msg="rcv_wnd_max must default to 65535.")

    def test__window_state__bump_max_window_advances(self) -> None:
        """
        Ensure 'bump_max_window' advances MAX.SND.WND when the
        supplied value is strictly greater, and leaves it
        untouched when not.

        Reference: RFC 5961 §5 (MAX.SND.WND running maximum).
        """

        s = WindowState()
        s.max_window = 1000
        s.bump_max_window(snd_wnd=2000)
        self.assertEqual(s.max_window, 2000, msg="bump_max_window must advance to higher value.")
        s.bump_max_window(snd_wnd=1500)
        self.assertEqual(s.max_window, 2000, msg="bump_max_window must NOT decrease.")


class TestWindowState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for WindowState.
    """

    def test__tcp_state__window__is_slotted(self) -> None:
        """
        Ensure WindowState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(WindowState(), "__dict__"),
            msg="WindowState must be declared with slots=True (no per-instance __dict__).",
        )


class TestWindowState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the WindowState mutator signatures.
    """

    def test__tcp_state__window__methods_are_keyword_only(self) -> None:
        """
        Ensure the WindowState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(WindowState.bump_max_window).parameters["snd_wnd"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="WindowState.bump_max_window 'snd_wnd' must be keyword-only.",
        )


class TestWindowState__BumpMaxBoundary(TestCase):
    """
    Inclusive-boundary coverage of 'bump_max_window'.
    """

    def test__window_state__bump_max_window_no_change_at_equal(self) -> None:
        """
        Ensure 'bump_max_window' does NOT advance when the offered window
        equals the current maximum (the update is strictly greater-than),
        pinning the '>' against a '>=' relaxation.

        Reference: RFC 5961 §5 (MAX.SND.WND strict running maximum).
        """

        state = WindowState()
        state.max_window = 1000
        state.bump_max_window(snd_wnd=1000)

        self.assertEqual(
            state.max_window,
            1000,
            msg="An equal window must not change max_window (strict '>').",
        )


class TestDeriveRcvWscale(TestCase):
    """
    The SYN-time receive window-scale derivation (RFC 7323 §2.2).
    """

    def test__derive_rcv_wscale__unscaled_for_uint16_ceiling(self) -> None:
        """
        Ensure a space that fits in the unscaled 16-bit window derives
        shift 0.

        Reference: RFC 7323 §2.2 (window scale option).
        """

        self.assertEqual(derive_rcv_wscale(65535), 0, msg="65535 needs no scaling.")

    def test__derive_rcv_wscale__one_byte_over_needs_shift_1(self) -> None:
        """
        Ensure a space one byte past the unscaled ceiling derives
        shift 1.

        Reference: RFC 7323 §2.2 (window scale option).
        """

        self.assertEqual(derive_rcv_wscale(65536), 1, msg="65536 needs shift 1.")

    def test__derive_rcv_wscale__default_rmem_max_derives_7(self) -> None:
        """
        Ensure the default 6 MiB rmem.max derives shift 7 — the
        canonical Linux value, so the wiring changes no behaviour.

        Reference: RFC 7323 §2.2 (window scale option).
        Reference: Linux tcp_select_initial_window (shift for tcp_rmem[2]).
        """

        # 65535 << 6 = 4194240 < 6291456 <= 8388480 = 65535 << 7.
        self.assertEqual(derive_rcv_wscale(6_291_456), 7, msg="6 MiB derives shift 7.")

    def test__derive_rcv_wscale__ten_mb_derives_8(self) -> None:
        """
        Ensure a 10 MB space derives shift 8 (the smallest shift whose
        scaled window covers it).

        Reference: RFC 7323 §2.2 (window scale option).
        """

        # 65535 << 7 = 8388480 < 10000000 <= 16776960 = 65535 << 8.
        self.assertEqual(derive_rcv_wscale(10_000_000), 8, msg="10 MB derives shift 8.")

    def test__derive_rcv_wscale__caps_at_14(self) -> None:
        """
        Ensure the derived shift saturates at the RFC 7323 maximum of
        14 for spaces beyond what any shift can express.

        Reference: RFC 7323 §2.3 (maximum window scale of 14).
        """

        self.assertEqual(derive_rcv_wscale(10**15), 14, msg="Shift must cap at 14.")
