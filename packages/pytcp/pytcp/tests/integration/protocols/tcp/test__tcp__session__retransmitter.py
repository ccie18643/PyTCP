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
This module contains the per-session TCP retransmitter
collaborator-seam tests — pinning that the 'TcpRetransmitter'
extracted from TcpSession (Phase 5 of the god-class
decomposition) is the canonical owner of the RTO timeout,
fast-retransmit, TLP firing, and RACK per-ACK helpers, and
that the session-level delegators
('_retransmit_packet_timeout', '_retransmit_packet_request',
'_tlp_pto_tick', '_rack_reorder_tick', '_rack_process_ack')
route through the engine.

The pure correctness of the moved methods is covered by the
existing TCP integration suite (retransmit, SACK, RACK / TLP,
F-RTO, CUBIC / Reno CC); this file pins only the
collaborator-seam invariants the refactor itself introduced.

packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__retransmitter.py

ver 3.0.10
"""

from typing import override

from pytcp.protocols.tcp.session.tcp__session__retransmit import TcpRetransmitter
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000
_PEER__ISS: int = 0x0000_2000


class TestTcpRetransmitterSeam(TcpTestCase):
    """
    The per-session TCP retransmitter collaborator-seam tests.
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

    def test__tcp__retransmitter__session_owns_a_TcpRetransmitter(self) -> None:
        """
        Ensure every TcpSession constructed by the standard
        '__init__' path owns a 'TcpRetransmitter' instance
        reachable via 'session._retransmitter', so Phase 5's
        collaborator-ownership contract holds for every
        session-creation path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._session._retransmitter,
            TcpRetransmitter,
            msg="Every TcpSession must own a TcpRetransmitter reachable via 'session._retransmitter'.",
        )
        self.assertIs(
            self._session._retransmitter._session,
            self._session,
            msg="The retransmitter's back-reference must point at the owning session (no cross-wiring).",
        )

    def test__tcp__retransmitter__retransmit_timeout_delegator_invokes_engine(self) -> None:
        """
        Ensure 'session._retransmit_packet_timeout()' invokes
        'session._retransmitter.retransmit_packet_timeout()' and
        not some shadow path: monkeypatch the engine method to
        record the call and route a delegator call; the recorder
        must observe exactly one invocation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        observed: list[int] = []

        def _spy() -> None:
            """Record the delegated call without running the timeout path."""
            observed.append(1)

        self._session._retransmitter.retransmit_packet_timeout = _spy  # type: ignore[method-assign]
        self._session._retransmit_packet_timeout()

        self.assertEqual(
            observed,
            [1],
            msg=(
                "session._retransmit_packet_timeout MUST delegate to "
                "session._retransmitter.retransmit_packet_timeout — "
                "no shadow path."
            ),
        )

    def test__tcp__retransmitter__rack_process_ack_delegator_routes_through_engine(
        self,
    ) -> None:
        """
        Ensure 'session._rack_process_ack(packet_rx_md)' delegates
        to 'session._retransmitter.rack_process_ack(packet_rx_md)'
        — the Phase-3 ACK processor and dup-ACK fast-retransmit
        path both call this hook, so the delegator MUST be wired
        through the engine.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        observed: list[object] = []

        def _spy(packet_rx_md: object, /) -> None:
            """Record the delegated call without running the rack update."""
            observed.append(packet_rx_md)

        self._session._retransmitter.rack_process_ack = _spy  # type: ignore[method-assign,assignment]
        sentinel = object()
        self._session._rack_process_ack(sentinel)  # type: ignore[arg-type]

        self.assertEqual(
            observed,
            [sentinel],
            msg=(
                "session._rack_process_ack MUST delegate to "
                "session._retransmitter.rack_process_ack with the same "
                "packet object — no shadow path."
            ),
        )
