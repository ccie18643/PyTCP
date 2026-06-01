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

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__window import WindowState


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
