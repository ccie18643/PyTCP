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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains the per-session TCP segment-validator
collaborator-seam tests — pinning that the 'TcpSegmentValidator'
extracted from TcpSession (Phase 4 of the god-class
decomposition) is the canonical owner of the inbound-segment
acceptability checks + RFC 6191 reuse re-init helper, and that
the session-level delegators ('is_seq_in_window' public,
'_check_segment_acceptability' / '_check_paws_and_update_ts_recent'
/ '_check_rst_acceptability' / '_reinit_for_rfc6191_reuse'
private) preserve the pre-refactor semantics.

The pure correctness of the moved checks is covered by the
existing TCP integration suite (handshake / PAWS / RST / 4-tuple
reuse / ICMP RX paths); this file pins only the
collaborator-seam invariants the refactor itself introduced.

packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__validator.py

ver 3.0.9
"""

from typing import override

from pytcp.protocols.tcp.session.tcp__session__validate import TcpSegmentValidator
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000
_PEER__ISS: int = 0x0000_2000


class TestTcpSegmentValidatorSeam(TcpTestCase):
    """
    The per-session TCP segment-validator collaborator-seam tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and construct an active TCP session
        driven into ESTABLISHED for the collaborator-seam
        round-trips.
        """

        super().setUp()
        self._session = self._drive_handshake_to_established(
            iss=_LOCAL__ISS,
            peer_iss=_PEER__ISS,
        )

    def test__tcp__validator__session_owns_a_TcpSegmentValidator(self) -> None:
        """
        Ensure every TcpSession constructed by the standard
        '__init__' path owns a 'TcpSegmentValidator' instance
        reachable via 'session._validator', so Phase 4's
        collaborator-ownership contract holds for every
        session-creation path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._session._validator,
            TcpSegmentValidator,
            msg="Every TcpSession must own a TcpSegmentValidator reachable via 'session._validator'.",
        )
        self.assertIs(
            self._session._validator._session,
            self._session,
            msg="The validator's back-reference must point at the owning session (no cross-wiring).",
        )

    def test__tcp__validator__is_seq_in_window_delegator_matches_engine(self) -> None:
        """
        Ensure 'session.is_seq_in_window(seq)' delegates to
        'TcpSegmentValidator.is_seq_in_window(seq)' and both
        observe the same SND.UNA / SND.NXT state on the session.
        ICMP RX handlers call the public 'session.is_seq_in_window'
        — the public surface MUST stay byte-identical to the
        engine's result.

        Reference: RFC 5927 §4 (ICMP attacks against TCP).
        """

        # An in-flight seq (SND.UNA itself) must be in the window;
        # a clearly out-of-flight seq must not.
        snd_una = self._session._snd_seq.una
        impossible_seq = (snd_una - 100_000) & 0xFFFF_FFFF
        self.assertEqual(
            self._session.is_seq_in_window(snd_una),
            self._session._validator.is_seq_in_window(snd_una),
            msg="Delegator and engine must agree on an in-window seq.",
        )
        self.assertEqual(
            self._session.is_seq_in_window(impossible_seq),
            self._session._validator.is_seq_in_window(impossible_seq),
            msg="Delegator and engine must agree on an out-of-window seq.",
        )

    def test__tcp__validator__check_segment_acceptability_delegator_invokes_engine(
        self,
    ) -> None:
        """
        Ensure 'session._check_segment_acceptability(packet_rx_md)'
        invokes 'session._validator.check_segment_acceptability'
        and not some shadow path: monkeypatch the engine method
        to record the call and route a delegator call; the
        recorder must observe exactly one invocation with the
        same packet object.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        observed: list[object] = []

        def _spy(packet_rx_md: object, /) -> bool:
            """Record the delegated call without running the check."""
            observed.append(packet_rx_md)
            return True

        self._session._validator.check_segment_acceptability = _spy  # type: ignore[method-assign,assignment]
        sentinel = object()
        result = self._session._check_segment_acceptability(sentinel)  # type: ignore[arg-type]

        self.assertEqual(
            observed,
            [sentinel],
            msg=(
                "session._check_segment_acceptability MUST delegate to "
                "session._validator.check_segment_acceptability with the "
                "same packet object — no shadow path."
            ),
        )
        self.assertTrue(
            result,
            msg="The delegator MUST return the engine's bool result verbatim.",
        )
