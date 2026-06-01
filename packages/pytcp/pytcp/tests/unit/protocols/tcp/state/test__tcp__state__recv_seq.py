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
This module contains unit tests for the per-session receive-side
seq state container in
'pytcp/protocols/tcp/state/tcp__state__recv_seq.py'.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__recv_seq.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__recv_seq import RecvSeqState


class TestRecvSeqState__Defaults(TestCase):
    """
    Per-field default values for 'RecvSeqState'.
    """

    def test__recv_seq_state__all_pointers_default_zero(self) -> None:
        """
        Ensure ini / una / nxt all default to 0 — the
        uninitialised sentinel before reset_to(irs=...) fires.

        Reference: RFC 9293 §3.4 (IRS-anchored receive window).
        """

        s = RecvSeqState()
        self.assertEqual(s.ini, 0, msg="ini must default to 0.")
        self.assertEqual(s.nxt, 0, msg="nxt must default to 0.")
        self.assertEqual(s.una, 0, msg="una must default to 0.")


class TestRecvSeqState__Methods(TestCase):
    """
    Method behaviour for RecvSeqState.
    """

    def test__recv_seq_state__reset_to_anchors_pointers(self) -> None:
        """
        Ensure 'reset_to(irs=IRS)' sets ini, nxt, and una to IRS
        — the canonical post-handshake configuration.

        Reference: RFC 9293 §3.4 (IRS anchor).
        """

        s = RecvSeqState()
        s.reset_to(irs=0x1234_5678)
        self.assertEqual(s.ini, 0x1234_5678, msg="reset_to must set ini.")
        self.assertEqual(s.nxt, 0x1234_5678, msg="reset_to must set nxt.")
        self.assertEqual(s.una, 0x1234_5678, msg="reset_to must set una.")

    def test__recv_seq_state__advance_nxt_advances_modularly(self) -> None:
        """
        Ensure 'advance_nxt(seg_end=...)' moves RCV.NXT forward
        modularly.

        Reference: RFC 9293 §3.4 (modular RCV.NXT advance).
        """

        s = RecvSeqState()
        s.nxt = 1000
        s.advance_nxt(seg_end=1500)
        self.assertEqual(
            s.nxt,
            1500,
            msg="advance_nxt must move RCV.NXT forward.",
        )

    def test__recv_seq_state__advance_nxt_does_not_rewind(self) -> None:
        """
        Ensure 'advance_nxt' leaves RCV.NXT untouched when the
        supplied 'seg_end' lies strictly BEFORE current RCV.NXT
        in modular order. This is the §3.10.7.4 no-rewind
        protection against stale-duplicate segments.

        Reference: RFC 9293 §3.10.7.4 (no-rewind protection).
        """

        s = RecvSeqState()
        s.nxt = 2000
        s.advance_nxt(seg_end=1500)
        self.assertEqual(
            s.nxt,
            2000,
            msg="advance_nxt must NOT rewind RCV.NXT on stale segments.",
        )
