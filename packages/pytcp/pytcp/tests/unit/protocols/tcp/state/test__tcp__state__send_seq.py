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
This module contains unit tests for the per-session send-side
seq state container in
'pytcp/protocols/tcp/state/tcp__state__send_seq.py'.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__send_seq.py

ver 3.0.10
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__send_seq import SendSeqState


class TestSendSeqState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'SendSeqState'.
    """

    def test__send_seq_state__all_pointers_default_zero(self) -> None:
        """
        Ensure all five seq pointers (ini, una, nxt, max, sml) and
        the fin field default to 0 — the uninitialised sentinel
        before 'reset_to(iss=...)' fires at session construction.

        Reference: RFC 9293 §3.4 (ISS-anchored send window).
        """

        s = SendSeqState()
        self.assertEqual(s.ini, 0, msg="ini must default to 0.")
        self.assertEqual(s.una, 0, msg="una must default to 0.")
        self.assertEqual(s.nxt, 0, msg="nxt must default to 0.")
        self.assertEqual(s.max, 0, msg="max must default to 0.")
        self.assertEqual(s.fin, 0, msg="fin must default to 0.")
        self.assertEqual(s.sml, 0, msg="sml must default to 0.")
        self.assertFalse(s.fin_sent, msg="fin_sent must default to False.")


class TestSendSeqState__Methods(TestCase):
    """
    Method behaviour for SendSeqState.
    """

    def test__send_seq_state__reset_to_anchors_all_pointers(self) -> None:
        """
        Ensure 'reset_to(iss=ISS)' anchors ini / una / nxt / max
        / sml to the supplied ISS — the canonical session-start
        configuration where SND.UNA == SND.NXT == SND.MAX == ISS.

        Reference: RFC 9293 §3.4 (ISS-anchored send window).
        """

        s = SendSeqState()
        s.reset_to(iss=0xDEAD_BEEF)
        self.assertEqual(s.ini, 0xDEAD_BEEF, msg="reset_to must set ini.")
        self.assertEqual(s.una, 0xDEAD_BEEF, msg="reset_to must set una.")
        self.assertEqual(s.nxt, 0xDEAD_BEEF, msg="reset_to must set nxt.")
        self.assertEqual(s.max, 0xDEAD_BEEF, msg="reset_to must set max.")
        self.assertEqual(s.sml, 0xDEAD_BEEF, msg="reset_to must set sml.")

    def test__send_seq_state__advance_nxt_modular(self) -> None:
        """
        Ensure 'advance_nxt(seq, data_len, syn, fin)' sets
        SND.NXT to the modular sum of the inputs. SYN/FIN each
        contribute one seq.

        Reference: RFC 9293 §3.4 (modular SND.NXT advance).
        """

        s = SendSeqState()
        s.advance_nxt(seq=1000, data_len=500, flag_syn=True, flag_fin=True)
        self.assertEqual(
            s.nxt,
            1502,
            msg="advance_nxt must equal seq + data_len + syn + fin.",
        )

    def test__send_seq_state__advance_nxt_wraps(self) -> None:
        """
        Ensure 'advance_nxt' wraps modulo 2^32 when seq + len
        crosses the 32-bit boundary.

        Reference: RFC 9293 §3.4 (modular wrap).
        """

        s = SendSeqState()
        s.advance_nxt(seq=0xFFFF_FFFF, data_len=2, flag_syn=False, flag_fin=False)
        self.assertEqual(
            s.nxt,
            1,
            msg="advance_nxt must wrap modulo 2^32.",
        )

    def test__send_seq_state__bump_max_modular(self) -> None:
        """
        Ensure 'bump_max_to_nxt' advances SND.MAX modularly when
        SND.NXT is strictly ahead, and leaves it untouched when
        SND.NXT has been rewound.

        Reference: RFC 9293 §3.4 (modular SND.MAX bump).
        """

        s = SendSeqState()
        s.max = 1000
        s.nxt = 2000
        s.bump_max_to_nxt()
        self.assertEqual(s.max, 2000, msg="Forward NXT must bump MAX.")

        s.nxt = 1500
        s.bump_max_to_nxt()
        self.assertEqual(s.max, 2000, msg="Rewound NXT must NOT decrease MAX.")

    def test__send_seq_state__record_fin_stamps_seq(self) -> None:
        """
        Ensure 'record_fin' stashes SND.NXT into 'fin' and sets
        'fin_sent' True so the CLOSE syscall is idempotent.

        Reference: RFC 9293 §3.10.7.4 (FIN bookkeeping).
        """

        s = SendSeqState()
        s.nxt = 0xCAFE_BABE
        s.record_fin()
        self.assertEqual(s.fin, 0xCAFE_BABE, msg="record_fin must stamp fin to nxt.")
        self.assertTrue(s.fin_sent, msg="record_fin must flip fin_sent True.")

    def test__send_seq_state__bytes_acked_modular(self) -> None:
        """
        Ensure 'bytes_acked' returns the modular delta from the
        current SND.UNA to the supplied new value, including the
        wrap case where new_una has wrapped past 0.

        Reference: RFC 9293 §3.4 (modular bytes-acked).
        """

        s = SendSeqState()
        s.una = 1000
        self.assertEqual(
            s.bytes_acked(new_una=1500),
            500,
            msg="bytes_acked must compute the unsigned delta.",
        )
        s.una = 0xFFFF_FFFE
        self.assertEqual(
            s.bytes_acked(new_una=2),
            4,
            msg="bytes_acked must wrap modulo 2^32.",
        )
        s.una = 0
        self.assertEqual(
            s.bytes_acked(new_una=0xFFFF_FFFF),
            0xFFFF_FFFF,
            msg="bytes_acked over the full 32-bit span must preserve every masked bit.",
        )


class TestSendSeqState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for SendSeqState.
    """

    def test__tcp_state__send_seq__is_slotted(self) -> None:
        """
        Ensure SendSeqState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(SendSeqState(), "__dict__"),
            msg="SendSeqState must be declared with slots=True (no per-instance __dict__).",
        )


class TestSendSeqState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the SendSeqState mutator signatures.
    """

    def test__tcp_state__send_seq__methods_are_keyword_only(self) -> None:
        """
        Ensure the SendSeqState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(SendSeqState.reset_to).parameters["iss"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="SendSeqState.reset_to 'iss' must be keyword-only.",
        )
        self.assertIs(
            inspect.signature(SendSeqState.advance_nxt).parameters["seq"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="SendSeqState.advance_nxt 'seq' must be keyword-only.",
        )
        self.assertIs(
            inspect.signature(SendSeqState.bytes_acked).parameters["new_una"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="SendSeqState.bytes_acked 'new_una' must be keyword-only.",
        )
