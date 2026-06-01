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
This module contains tests for the 'TcpSession' constructor, property
surface, and '__str__' formatting.

pytcp/tests/unit/protocols/tcp/test__tcp__session__lifecycle.py

ver 3.0.8
"""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState


class _TcpSessionFixture(TestCase):
    """
    Shared fixture that patches 'stack.timer' (to avoid registering
    a real timer callback) and 'stack.egress_interface_mtu' (so the
    session's MSS seed resolves deterministically).
    """

    def setUp(self) -> None:
        """
        Install the stack patches required to build a 'TcpSession'
        object without touching the real stack singletons.
        """

        self._timer = SimpleNamespace(
            call_periodic=lambda *_a, **_k: None,
            cancel=lambda *_: None,
            call_later=lambda *_a, **_k: None,
            now_ms=0,
        )
        self._timer_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.timer",
            self._timer,
        )
        self._timer_patch.start()

        self._mtu_patch = patch(
            "pytcp.protocols.tcp.session.tcp__session.stack.egress_interface_mtu",
            return_value=1500,
        )
        self._mtu_patch.start()

    def tearDown(self) -> None:
        """
        Tear down the stack patches.
        """

        self._timer_patch.stop()
        self._mtu_patch.stop()

    def _make_session(self) -> TcpSession:
        """
        Build a canonical IPv4 'TcpSession' against a mocked socket.
        """

        return TcpSession(
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_ip_address=Ip4Address("10.0.0.2"),
            remote_port=44444,
            socket=MagicMock(),
        )


class TestTcpSessionInit(_TcpSessionFixture):
    """
    The 'TcpSession.__init__' tests.
    """

    def test__tcp_session__init_state_is_closed(self) -> None:
        """
        Ensure a fresh 'TcpSession' starts in the 'CLOSED' state. Every
        state transition in the FSM starts from this baseline.

        Reference: RFC 9293 §3.3.2 (CLOSED is the initial state).
        """

        session = self._make_session()
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="A fresh TcpSession must start in FsmState.CLOSED.",
        )

    def test__tcp_session__init_is_event_driven_no_periodic(self) -> None:
        """
        Ensure '__init__' does NOT register a 1 ms periodic
        (the FSM is event-driven post-migration): no
        'call_periodic', a None coalesced service handle, and
        an empty deadline map. The pump / logical timers are
        armed lazily on first activity, not at construction.

        Reference: RFC 9293 §3.8 (TCP timers drive FSM transitions).
        """

        mock_periodic = MagicMock()
        self._timer.call_periodic = mock_periodic

        session = self._make_session()

        mock_periodic.assert_not_called()
        self.assertIsNone(
            session._timers._service_handle,
            msg="A fresh TcpSession must have no coalesced service handle.",
        )
        self.assertEqual(
            session._timers._deadlines,
            {},
            msg="A fresh TcpSession must have an empty deadline map (nothing armed at construction).",
        )

    def test__tcp_session__init_rx_tx_buffers_empty(self) -> None:
        """
        Ensure the RX and TX buffers start empty so the first data
        event has a predictable starting point.

        Reference: RFC 9293 §3.9.1 (SEND / RECEIVE buffers).
        """

        session = self._make_session()
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg="TcpSession._rx_buffer must start empty.",
        )
        self.assertEqual(
            bytes(session._tx.buffer),
            b"",
            msg="TcpSession._tx_buffer must start empty.",
        )

    def test__tcp_session__init_window_parameters(self) -> None:
        """
        Ensure the receive and send window parameters start at their
        canonical defaults — the session advances these as it
        negotiates with the peer.

        Reference: RFC 9293 §3.7.1 (default MSS).
        Reference: RFC 7323 §2 (WSCALE bilateral negotiation).
        """

        session = self._make_session()
        self.assertEqual(
            session._rcv_wnd,
            65535,
            msg="TcpSession._rcv_wnd must default to 65535.",
        )
        self.assertEqual(
            session._win.rcv_wsc,
            7,
            msg=(
                "TcpSession._win.rcv_wsc must default to 7 (the throughput-"
                "friendly WSCALE shift advertised on outbound SYN per "
                "RFC 7323 §2.2; matches the Linux/FreeBSD default and "
                "yields a max advertised window of 65535 << 7 ~= 8 MB)."
            ),
        )
        self.assertEqual(
            session._win.snd_mss,
            536,
            msg="TcpSession._win.snd_mss must default to 536 (RFC 879 minimum).",
        )
        self.assertEqual(
            session._win.rcv_mss,
            1500 - 40,
            msg="TcpSession._win.rcv_mss must default to the egress interface MTU - 40.",
        )

    def test__tcp_session__init_syn_numbers_are_consistent(self) -> None:
        """
        Ensure the send-side sequence numbers start consistent with
        each other: '_snd_nxt', '_snd_max', and '_snd_una' must all
        equal '_snd_ini' at construction time.

        Reference: RFC 9293 §3.4 (SND.NXT / SND.UNA / ISS initialization).
        """

        session = self._make_session()
        self.assertEqual(
            session._snd_seq.nxt,
            session._snd_seq.ini,
            msg="_snd_nxt must start equal to _snd_ini.",
        )
        self.assertEqual(
            session._snd_seq.max,
            session._snd_seq.ini,
            msg="_snd_max must start equal to _snd_ini.",
        )
        self.assertEqual(
            session._snd_seq.una,
            session._snd_seq.ini,
            msg="_snd_una must start equal to _snd_ini.",
        )
        self.assertEqual(
            session._tx.seq_mod,
            session._snd_seq.ini,
            msg="_tx_buffer_seq_mod must start equal to _snd_ini.",
        )

    def test__tcp_session__init_closing_flag_false(self) -> None:
        """
        Ensure the '_closing' flag starts 'False' — it only flips
        when the application issues CLOSE while the peer still has
        data to flush.

        Reference: RFC 9293 §3.10.4 (CLOSE call processing).
        """

        session = self._make_session()
        self.assertFalse(
            session._closing,
            msg="TcpSession._closing must start False.",
        )

    def test__tcp_session__init_connection_error_is_none(self) -> None:
        """
        Ensure '_connection_error' starts at 'ConnError.NONE'; any
        other value would pre-seed a spurious failure.

        Reference: RFC 9293 §3.10.1 (OPEN signalling fields).
        """

        from pytcp.protocols.tcp.tcp__enums import ConnError

        session = self._make_session()
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg="TcpSession._connection_error must default to ConnError.NONE.",
        )

    def test__tcp_session__init_accecn_r_cep_starts_at_5(self) -> None:
        """
        Ensure the receiver-side 'r.cep' counter initialises to 5
        per the AccECN feedback protocol; 5 is the canonical
        initial value chosen so a freshly negotiated session is
        distinguishable from middlebox-zeroed fields.

        Reference: RFC 9768 §3.2.1 (Initialization of Feedback Counters).
        """

        session = self._make_session()
        self.assertEqual(
            session._accecn.r_cep,
            5,
            msg="TcpSession._accecn_r_cep must initialise to 5 (RFC 9768 §3.2.1).",
        )

    def test__tcp_session__init_accecn_r_e0b_starts_at_1(self) -> None:
        """
        Ensure the receiver-side 'r.e0b' (ECT(0) byte) counter
        initialises to 1; the non-zero initial value distinguishes
        a freshly negotiated session from middlebox-zeroed fields
        and supports the §3.2.3.2.4 zeroing-detection logic.

        Reference: RFC 9768 §3.2.1 (Initialization of Feedback Counters).
        """

        session = self._make_session()
        self.assertEqual(
            session._accecn.r_ect0_b,
            1,
            msg="TcpSession._accecn_r_ect0_b must initialise to 1 (RFC 9768 §3.2.1).",
        )

    def test__tcp_session__init_accecn_r_e1b_starts_at_1(self) -> None:
        """
        Ensure the receiver-side 'r.e1b' (ECT(1) byte) counter
        initialises to 1 for the same zeroing-distinguishability
        reason as 'r.e0b'.

        Reference: RFC 9768 §3.2.1 (Initialization of Feedback Counters).
        """

        session = self._make_session()
        self.assertEqual(
            session._accecn.r_ect1_b,
            1,
            msg="TcpSession._accecn_r_ect1_b must initialise to 1 (RFC 9768 §3.2.1).",
        )

    def test__tcp_session__init_accecn_r_ceb_starts_at_0(self) -> None:
        """
        Ensure the receiver-side 'r.ceb' (CE byte) counter
        initialises to 0 per the spec; unlike 'r.e0b' / 'r.e1b'
        the CE counter starts at zero because zero CE marks at
        connection start is the expected steady state.

        Reference: RFC 9768 §3.2.1 (Initialization of Feedback Counters).
        """

        session = self._make_session()
        self.assertEqual(
            session._accecn.r_ce_b,
            0,
            msg="TcpSession._accecn_r_ce_b must initialise to 0 (RFC 9768 §3.2.1).",
        )


class TestTcpSessionProperties(_TcpSessionFixture):
    """
    The 'TcpSession' read-only property surface tests.
    """

    def test__tcp_session__property_getters(self) -> None:
        """
        Ensure every publicly exposed property (local/remote IP and
        port, socket, state) returns the matching private attribute.

        Reference: RFC 9293 §3.3.1 (TCB fields).
        """

        session = self._make_session()
        self.assertEqual(session.local_ip_address, Ip4Address("10.0.0.1"), msg="local_ip_address getter must match.")
        self.assertEqual(session.remote_ip_address, Ip4Address("10.0.0.2"), msg="remote_ip_address getter must match.")
        self.assertEqual(session.local_port, 8080, msg="local_port getter must match.")
        self.assertEqual(session.remote_port, 44444, msg="remote_port getter must match.")
        self.assertIs(session.socket, session._socket, msg="socket getter must return _socket.")
        self.assertIs(session.state, session._state, msg="state getter must return _state.")

    def test__tcp_session__tx_buffer_nxt_starts_zero(self) -> None:
        """
        Ensure the '_tx_buffer_nxt' helper starts at 0 — 'snd_nxt'
        equals 'snd_ini' so their delta is 0, clamped by 'max(..., 0)'.

        Reference: RFC 9293 §3.4 (SND.NXT initialization).
        """

        session = self._make_session()
        self.assertEqual(
            session._tx_buffer_nxt,
            0,
            msg="_tx_buffer_nxt must start at 0 for a fresh session.",
        )

    def test__tcp_session__tx_buffer_una_starts_zero(self) -> None:
        """
        Ensure the '_tx_buffer_una' helper starts at 0 for the same
        reason.

        Reference: RFC 9293 §3.4 (SND.UNA initialization).
        """

        session = self._make_session()
        self.assertEqual(
            session._tx_buffer_una,
            0,
            msg="_tx_buffer_una must start at 0 for a fresh session.",
        )


class TestTcpSessionStr(_TcpSessionFixture):
    """
    The 'TcpSession.__str__' formatting tests.
    """

    def test__tcp_session__str_four_field_format(self) -> None:
        """
        Ensure '__str__' produces the canonical
        'local_ip/local_port/remote_ip/remote_port' slash-separated
        identifier used in log lines and timer names.

        Reference: RFC 9293 §3.3.1 (4-tuple connection identification).
        """

        session = self._make_session()
        self.assertEqual(
            str(session),
            "10.0.0.1/8080/10.0.0.2/44444",
            msg="TcpSession.__str__ must produce the four-field slash-separated identifier.",
        )

    def test__tcp_session__init_accecn_s_ect0_b_starts_at_1(self) -> None:
        """
        Ensure the sender-side 's.e0b' (ECT(0) byte) counter
        initialises to 1 per the spec mandated initial values;
        the non-zero seed lets the sender's tracker match the
        receiver's r.e0b initial value so the first inbound
        AccECN option's per-counter delta is computed against
        the correct baseline.

        Reference: RFC 9768 §3.2.1 (Data Sender s.e0b initial value 1).
        """

        session = self._make_session()
        self.assertEqual(
            session._accecn.s_ect0_b,
            1,
            msg="TcpSession._accecn_s_ect0_b must initialise to 1 (RFC 9768 §3.2.1).",
        )

    def test__tcp_session__init_accecn_s_ect1_b_starts_at_1(self) -> None:
        """
        Ensure the sender-side 's.e1b' (ECT(1) byte) counter
        initialises to 1 for the same baseline-matching reason
        as 's.e0b'.

        Reference: RFC 9768 §3.2.1 (Data Sender s.e1b initial value 1).
        """

        session = self._make_session()
        self.assertEqual(
            session._accecn.s_ect1_b,
            1,
            msg="TcpSession._accecn_s_ect1_b must initialise to 1 (RFC 9768 §3.2.1).",
        )
