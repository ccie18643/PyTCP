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
Unit tests for TxBufferState.

pytcp/tests/unit/protocols/tcp/state/test__tcp__state__tx_buffer.py

ver 3.0.10
"""

import inspect
from unittest import TestCase

from pytcp.protocols.tcp.state.tcp__state__tx_buffer import TxBufferState


class TestTxBufferState(TestCase):
    """
    Defaults + drain + bump_seq_mod_for_flags behaviour.
    """

    def test__tx_buffer__defaults(self) -> None:
        """
        Ensure buffer defaults to empty bytearray, seq_mod to 0,
        and retransmit_request_counter to empty dict.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = TxBufferState()
        self.assertEqual(s.buffer, bytearray(), msg="buffer must default to empty.")
        self.assertEqual(s.seq_mod, 0, msg="seq_mod must default to 0.")
        self.assertEqual(
            s.retransmit_request_counter,
            {},
            msg="retransmit_request_counter must default to {}.",
        )

    def test__tx_buffer__drain_advances_seq_mod(self) -> None:
        """
        Ensure 'drain' removes the front bytes and advances
        seq_mod modularly by the same count.

        Reference: RFC 9293 §3.4 (modular seq anchor).
        """

        s = TxBufferState()
        s.buffer.extend(b"abcdef")
        s.seq_mod = 1000
        s.drain(bytes_count=3)
        self.assertEqual(s.buffer, bytearray(b"def"), msg="drain must remove the front bytes.")
        self.assertEqual(s.seq_mod, 1003, msg="drain must advance seq_mod.")

    def test__tx_buffer__drain_wraps_modulo(self) -> None:
        """
        Ensure 'drain' wraps seq_mod modulo 2^32 when the byte
        count crosses the 32-bit boundary.

        Reference: RFC 9293 §3.4 (modular wrap).
        """

        s = TxBufferState()
        s.buffer.extend(b"\x00" * 10)
        s.seq_mod = 0xFFFF_FFFE
        s.drain(bytes_count=5)
        self.assertEqual(s.seq_mod, 3, msg="drain must wrap seq_mod modulo 2^32.")

    def test__tx_buffer__bump_seq_mod_for_flags(self) -> None:
        """
        Ensure 'bump_seq_mod_for_flags' advances seq_mod by 1
        for SYN, by 1 for FIN, and by 0 for neither.

        Reference: RFC 9293 §3.4 (SYN/FIN consume one seq).
        """

        s = TxBufferState()
        s.seq_mod = 100
        s.bump_seq_mod_for_flags(flag_syn=True, flag_fin=False)
        self.assertEqual(s.seq_mod, 101, msg="SYN must advance seq_mod by 1.")

        s.bump_seq_mod_for_flags(flag_syn=False, flag_fin=True)
        self.assertEqual(s.seq_mod, 102, msg="FIN must advance seq_mod by 1.")

        s.bump_seq_mod_for_flags(flag_syn=True, flag_fin=True)
        self.assertEqual(s.seq_mod, 104, msg="SYN+FIN must advance seq_mod by 2.")

        s.bump_seq_mod_for_flags(flag_syn=False, flag_fin=False)
        self.assertEqual(s.seq_mod, 104, msg="No flags must leave seq_mod unchanged.")


class TestTxBufferState__Slotted(TestCase):
    """
    The slotted-dataclass invariant for TxBufferState.
    """

    def test__tcp_state__tx_buffer__is_slotted(self) -> None:
        """
        Ensure TxBufferState is a slotted dataclass so it grows no per-instance
        __dict__ on the TcpSession state object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(TxBufferState(), "__dict__"),
            msg="TxBufferState must be declared with slots=True (no per-instance __dict__).",
        )


class TestTxBufferState__KeywordOnlySignatures(TestCase):
    """
    Keyword-only enforcement on the TxBufferState mutator signatures.
    """

    def test__tcp_state__tx_buffer__methods_are_keyword_only(self) -> None:
        """
        Ensure the TxBufferState mutators reject positional arguments — their
        public parameters are keyword-only, pinning the call contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            inspect.signature(TxBufferState.drain).parameters["bytes_count"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="TxBufferState.drain 'bytes_count' must be keyword-only.",
        )
        self.assertIs(
            inspect.signature(TxBufferState.bump_seq_mod_for_flags).parameters["flag_syn"].kind,
            inspect.Parameter.KEYWORD_ONLY,
            msg="TxBufferState.bump_seq_mod_for_flags 'flag_syn' must be keyword-only.",
        )
