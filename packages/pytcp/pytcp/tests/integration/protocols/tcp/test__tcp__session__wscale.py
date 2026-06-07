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
This module contains integration tests for the TCP Window Scale
option (RFC 7323 §2) in the 'TcpSession' state machine. WSCALE is
the bilateral SYN-time option that lets either side advertise
windows larger than 65535 bytes by left-shifting the wire-level
'win' field by an agreed-upon factor on every post-handshake
segment. Without WSCALE the receive window is permanently capped
at 64 KB / RTT regardless of bandwidth - a 100 ms RTT link is
limited to ~5 Mbps even on a 1 Gbps physical pipe.

Reference RFCs:
    RFC 7323 §2.2    Window Scale Option negotiation
    RFC 7323 §2.3    Using the Window Scale Option

pytcp/tests/integration/protocols/tcp/test__tcp__session__wscale.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240
PEER__MSS: int = 1460

# The default WSCALE factor PyTCP advertises on its outbound SYN
# / SYN+ACK once the implementation lands. 7 yields a maximum
# advertised window of 65535 << 7 = 8_388_480 bytes (~8 MB),
# which matches the Linux / FreeBSD default and is sufficient
# for typical long-fat-pipe scenarios.
LOCAL__RCV_WSCALE: int = 7


class TestTcpSession__Wscale(TcpTestCase):
    """
    Integration tests for the WSCALE option bilateral negotiation
    and post-handshake application to inbound and outbound window
    fields.
    """

    def test__wscale__outbound_syn_advertises_wscale_option(self) -> None:
        """
        Ensure that an active-open session emits its initial
        SYN with the WSCALE option carrying a non-zero
        scaling factor.

        Reference: RFC 7323 §2.2 (Window Scale Option negotiation).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])

        # Sanity: this is the SYN.
        self.assertEqual(
            syn_probe.flags & frozenset({"SYN", "ACK", "FIN", "RST"}),
            frozenset({"SYN"}),
            msg="Setup precondition: outbound segment must be a pure SYN.",
        )

        # The spec encoding: WSCALE option present with our
        # default shift count.
        self.assertEqual(
            syn_probe.wscale,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Outbound SYN MUST carry the WSCALE option with "
                f"shift = {LOCAL__RCV_WSCALE} per RFC 7323 §2.2. "
                "Without our advertisement, peer cannot offer "
                "reciprocal scaling, and the connection is "
                "permanently throughput-capped at 64 KB / RTT. "
                "Current code's '_transmit_packet' line 568 "
                "hard-codes 'tcp__wscale=0', producing an "
                "option-absent wire form."
            ),
        )

        # Sanity: SYN's own 'win' field is NOT shifted (RFC 7323
        # §2.2). If the implementation accidentally shifted, the
        # advertised value would be capped at 65535 (the wire
        # limit) and we'd lose the no-scaling-in-SYN invariant.
        self.assertEqual(
            syn_probe.win,
            65535,
            msg=(
                "SYN's 'win' field MUST equal the unshifted "
                "initial '_rcv_wnd' (65535). Per RFC 7323 §2.2 "
                "'WSopt is not used to scale the value in the "
                "window field of the SYN segment itself' - the "
                "shift only applies to post-handshake segments."
            ),
        )

        # Side-state assertion: the session tracks its advertised
        # shift in '_rcv_wsc' so the post-handshake outbound
        # segments can apply the inverse shift to the
        # advertised window.
        self.assertEqual(
            session._win.rcv_wsc,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Session '_rcv_wsc' must equal the advertised "
                f"shift ({LOCAL__RCV_WSCALE}) - it is the canonical "
                "place for post-handshake code to read 'how much "
                "to shift our outbound win field by'."
            ),
        )

    def test__wscale__bilateral_handshake_sets_both_directions(self) -> None:
        """
        Ensure that when both sides advertise WSCALE on the
        SYN / SYN+ACK exchange, the session ends up with both
        directions of scale state set: '_rcv_wsc' equal to
        OUR advertised shift (governs how we shift outbound
        'win' fields) and '_snd_wsc' equal to PEER'S
        advertised shift (governs how we interpret inbound
        'win' fields).

        Reference: RFC 7323 §2.2 (Window Scale Option negotiation).
        Reference: RFC 7323 §2.3 (Using the Window Scale Option).
        """

        peer_wscale = 10
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # Our advertised shift (governs outbound win shifts).
        self.assertEqual(
            session._win.rcv_wsc,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Session '_rcv_wsc' must equal our advertised "
                f"shift ({LOCAL__RCV_WSCALE}). It is unchanged by "
                "peer's offer; the 'rcv' side governs the shift we "
                "apply to OUR receive window when filling the "
                "outbound 'win' field."
            ),
        )

        # Peer's advertised shift (governs inbound win interpretation).
        self.assertEqual(
            session._win.snd_wsc,
            peer_wscale,
            msg=(
                f"Session '_snd_wsc' must equal peer's advertised "
                f"shift ({peer_wscale}) per RFC 7323 §2.3 - the "
                "'snd' side governs how we interpret peer's "
                "inbound 'win' fields. The bilateral negotiation "
                "succeeded because we advertised WSCALE on our "
                "outbound SYN (scenario #1), so peer's offer is "
                "now legal bilateral. With no advertisement on "
                "our side, the asymmetric-offer rule from "
                "'data_transfer__window.py' #2 would force this "
                "to remain 0; that test will need to flip its "
                "expected behaviour once WSCALE lands."
            ),
        )

    def test__wscale__peer_wscale_applied_to_inbound_window(self) -> None:
        """
        Ensure that after a bilateral WSCALE negotiation, the
        peer's post-handshake 'win' field is interpreted as
        '_snd_wnd = peer.win << _snd_wsc'. The SYN+ACK's own
        'win' field is NOT shifted; the shift applies only to
        subsequent segments.

        Reference: RFC 7323 §2.3 (Using the Window Scale Option).
        """

        peer_wscale = 10
        peer_post_handshake_win = 1024

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: bilateral WSCALE handshake must complete.",
        )

        # Peer post-handshake ACK + 1 byte of data with win=1024.
        # The 1-byte payload steers the segment through the
        # data-handling branch (and thus '_process_ack_packet'
        # which updates '_snd_wnd'); a bare ACK at 'ack ==
        # SND.UNA, no data' would be intercepted as a duplicate
        # ACK and would not refresh the send-window state.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH"),
            win=peer_post_handshake_win,
            payload=b"x",
        )
        self._drive_rx(frame=peer_ack)

        # The spec encoding: _snd_wnd is shifted.
        expected_snd_wnd = peer_post_handshake_win << peer_wscale
        self.assertEqual(
            session._win.snd_wnd,
            expected_snd_wnd,
            msg=(
                f"Peer's post-handshake 'win = {peer_post_handshake_win}' "
                f"with negotiated 'snd_wsc = {peer_wscale}' must "
                f"yield '_snd_wnd = {peer_post_handshake_win} << "
                f"{peer_wscale} = {expected_snd_wnd}' per RFC 7323 "
                "§2.3. Catching 1024 here would mean the shift "
                "did NOT get applied (the unscaled value leaked "
                "through), confirming the bilateral negotiation "
                "did not record peer's wscale."
            ),
        )

        # Sanity: state still ESTABLISHED.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED after a normal post-handshake ACK.",
        )

    def test__wscale__outbound_window_advertised_with_local_wscale_shift(self) -> None:
        """
        Ensure that the wire-level 'win' field in our
        post-handshake outbound segments is right-shifted by
        '_rcv_wsc', so the peer reconstructs our actual
        receive window via 'peer_snd_wnd = wire_win <<
        our_wsc'.

        Reference: RFC 7323 §2.3 (Using the Window Scale Option).
        """

        peer_wscale = 10

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(session.state, FsmState.ESTABLISHED)

        # Two 100-byte data segments back-to-back; second one
        # triggers inline ACK via every-other-segment rule.
        seg_len = 100
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH"),
            win=1024,
            payload=b"X" * seg_len,
        )
        seg1_inline = self._drive_rx(frame=seg1)
        self.assertEqual(
            seg1_inline,
            [],
            msg="Setup precondition: first segment must not produce an inline ACK.",
        )

        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + seg_len,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH"),
            win=1024,
            payload=b"Y" * seg_len,
        )
        seg2_inline = self._drive_rx(frame=seg2)
        self.assertEqual(
            len(seg2_inline),
            1,
            msg=(
                "Setup precondition: second segment must produce "
                "exactly one inline cumulative ACK via the "
                "every-other-segment rule."
            ),
        )

        ack_probe = self._parse_tx(seg2_inline[0])

        # The spec encoding: wire_win = (rcv_wnd_max - buffer_fill)
        # >> _rcv_wsc.
        actual_rcv_wnd = 65535 - 2 * seg_len
        expected_wire_win = actual_rcv_wnd >> LOCAL__RCV_WSCALE
        self.assertEqual(
            ack_probe.win,
            expected_wire_win,
            msg=(
                f"Outbound ACK's 'win' field MUST equal "
                f"'rcv_wnd >> _rcv_wsc' = {actual_rcv_wnd} >> "
                f"{LOCAL__RCV_WSCALE} = {expected_wire_win} per "
                "RFC 7323 §2.3. Catching the unshifted value "
                f"({actual_rcv_wnd}) would mean we are advertising "
                "the actual byte count on the wire - peer's WSCALE "
                "shift on the inbound side would then misinterpret "
                "our window as far larger than reality."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED.",
        )

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them. After a SYN arrives,
        '_tcp_fsm_listen' mutates the original session in place into
        the child (in SYN_RCVD) and grafts a fresh listening session
        onto the original 'TcpSocket'. So the returned 'session' here
        is the listening session, and after one SYN it becomes the
        child; the listening socket's '_tcp_session' is then a new
        listening session.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = PEER__PORT  # the listen port
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=PEER__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock, session  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__wscale__passive_open_mirrors_peer_wscale_offer(self) -> None:
        """
        Ensure that when an inbound SYN to a listening socket
        carries the WSCALE option, our SYN+ACK reply mirrors
        the offer (carrying our own WSCALE) and the resulting
        child session records peer's wscale as '_snd_wsc'.

        Reference: RFC 7323 §2.2 (Window Scale Option negotiation).
        """

        peer_wscale = 12
        listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS)

        # Peer sends SYN with WSCALE.
        peer_syn = build_tcp4(
            sport=PEER__PORT + 1000,  # arbitrary distinct peer port
            dport=PEER__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn)

        # The original listen_session is now the child (in SYN_RCVD).
        child_session = listen_session
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: original listen_session is now the child in SYN_RCVD.",
        )

        # Tick to fire SYN+ACK.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])

        # The spec encoding: SYN+ACK carries our WSCALE (we mirror
        # peer's offer) and the child session records both values.
        self.assertEqual(
            syn_ack_probe.flags,
            frozenset({"SYN", "ACK"}),
            msg="Setup precondition: outbound segment must be a SYN+ACK.",
        )
        self.assertEqual(
            syn_ack_probe.wscale,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Outbound SYN+ACK MUST carry WSCALE = "
                f"{LOCAL__RCV_WSCALE} per RFC 7323 §2.2 - peer "
                "offered, we mirror, bilateral negotiation succeeds."
            ),
        )
        self.assertEqual(
            child_session._win.rcv_wsc,
            LOCAL__RCV_WSCALE,
            msg=(f"Child session '_rcv_wsc' must equal our advertised " f"shift ({LOCAL__RCV_WSCALE})."),
        )
        self.assertEqual(
            child_session._win.snd_wsc,
            peer_wscale,
            msg=(
                f"Child session '_snd_wsc' must equal peer's "
                f"advertised shift ({peer_wscale}) - bilateral "
                "negotiation succeeded because our SYN+ACK mirrors "
                "peer's WSCALE."
            ),
        )

        # Sanity: the listening socket still has a fresh listening
        # session ready for further inbound SYNs.
        new_listen_session = listen_sock._tcp_session
        assert new_listen_session is not None
        self.assertIs(
            new_listen_session.state,
            FsmState.LISTEN,
            msg=(
                "After a SYN spawns a child, the listening socket's "
                "'_tcp_session' must be a fresh listening session "
                "ready to accept further connections."
            ),
        )

    def test__wscale__passive_open_omits_wscale_when_peer_did_not_offer(self) -> None:
        """
        Ensure that when an inbound SYN to a listening socket
        does NOT carry the WSCALE option, our SYN+ACK reply
        also omits it and the resulting child session keeps
        both '_rcv_wsc' and '_snd_wsc' at 0 for the
        connection lifetime.

        Reference: RFC 7323 §2.2 (bilateral non-offer rule).
        """

        listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS)

        # Peer sends SYN WITHOUT WSCALE option.
        peer_syn = build_tcp4(
            sport=PEER__PORT + 1000,
            dport=PEER__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            # No wscale= parameter.
        )
        self._drive_rx(frame=peer_syn)

        child_session = listen_session
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: original listen_session is now the child in SYN_RCVD.",
        )

        # Tick to fire SYN+ACK.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])

        # The spec encoding: SYN+ACK omits WSCALE; both wscale
        # state fields stay at 0.
        self.assertEqual(
            syn_ack_probe.flags,
            frozenset({"SYN", "ACK"}),
            msg="Setup precondition: outbound segment must be a SYN+ACK.",
        )
        self.assertIsNone(
            syn_ack_probe.wscale,
            msg=(
                "Outbound SYN+ACK MUST NOT carry WSCALE when peer's "
                "SYN did not offer it - RFC 7323 §2.2 forbids "
                "unilateral offering. Mirroring peer's non-offer "
                "keeps the bilateral non-offer rule intact."
            ),
        )
        self.assertEqual(
            child_session._win.rcv_wsc,
            0,
            msg=(
                "Child session '_rcv_wsc' must equal 0 when peer "
                "did not offer WSCALE - bilateral non-offer means "
                "no scaling on either direction."
            ),
        )
        self.assertEqual(
            child_session._win.snd_wsc,
            0,
            msg=(
                "Child session '_snd_wsc' must equal 0 when peer "
                "did not offer WSCALE - nothing to apply to "
                "inbound 'win' fields."
            ),
        )

    def test__wscale__syn_ack_own_win_field_is_not_wscale_shifted(self) -> None:
        """
        Ensure that peer's SYN+ACK 'win' field is NOT
        left-shifted by the negotiated WSCALE — the SYN
        segment itself uses an unshifted window value, the
        shift only applies to subsequent post-handshake
        segments.

        Reference: RFC 7323 §2.2 (SYN's own win field is unscaled).
        """

        peer_wscale = 10
        peer_win_on_syn_ack = 64240

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_win_on_syn_ack,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: bilateral WSCALE handshake must complete.",
        )

        # The spec encoding: SYN+ACK's win is NOT shifted.
        self.assertEqual(
            session._win.snd_wnd,
            peer_win_on_syn_ack,
            msg=(
                f"Post-handshake '_snd_wnd' MUST equal the literal "
                f"SYN+ACK win value ({peer_win_on_syn_ack}), NOT "
                f"the shifted value ({peer_win_on_syn_ack << peer_wscale}). "
                "Per RFC 7323 §2.2, 'WSopt is not used to scale the "
                "value in the window field of the SYN segment itself'. "
                "The shift applies only to post-handshake segments."
            ),
        )

    def test__wscale__asymmetric_offer_we_disabled_advertising_ignores_peer_wscale(self) -> None:
        """
        Ensure that when our session is explicitly
        configured to NOT advertise WSCALE on its outbound
        SYN (via setting '_advertise_wscale = False'), peer's
        WSCALE option on the SYN+ACK is ignored.

        Reference: RFC 7323 §2.2 (bilateral non-offer rule).
        """

        peer_wscale = 8

        session = self._make_active_session(iss=LOCAL__ISS)
        # Explicitly opt out of advertising WSCALE on this session.
        # Once the WSCALE implementation lands and defaults to
        # advertising, this is the API the user (or test) flips to
        # match a non-WSCALE peer or a constrained-buffer profile.
        session._advertise.wscale = False
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertIsNone(
            syn_probe.wscale,
            msg=(
                "With '_advertise_wscale = False', the outbound SYN "
                "MUST NOT carry the WSCALE option - the bilateral "
                "non-offer rule of RFC 7323 §2.2 applies."
            ),
        )

        # Peer replies with WSCALE.
        peer_post_handshake_win = 32768
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_post_handshake_win,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # The spec encoding: peer's WSCALE is ignored in both
        # directions; window stays unshifted.
        self.assertEqual(
            session._win.rcv_wsc,
            0,
            msg=(
                "Session '_rcv_wsc' must equal 0 when we opted out "
                "of advertising - bilateral non-offer rule means no "
                "scaling on outbound win fields either."
            ),
        )
        self.assertEqual(
            session._win.snd_wsc,
            0,
            msg=(
                "Session '_snd_wsc' must equal 0 when we opted out, "
                "even though peer offered WSCALE - RFC 7323 §2.2: "
                "'if it is offered in only one direction, it MUST "
                "be ignored'."
            ),
        )
        self.assertEqual(
            session._win.snd_wnd,
            peer_post_handshake_win,
            msg=(
                f"'_snd_wnd' must equal peer's raw advertised window "
                f"({peer_post_handshake_win}) with no left shift - "
                "the asymmetric offer was ignored, so neither side "
                "scales."
            ),
        )

    def test__wscale__active_open_us_only_peer_omits_wscale_disables_scaling(self) -> None:
        """
        Ensure that an active open where WE advertise WSCALE
        on the SYN but peer's SYN+ACK OMITS WSCALE results in
        the asymmetric offer being ignored on both sides.

        Reference: RFC 7323 §2.2 (bilateral non-offer rule).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertIsNotNone(
            syn_probe.wscale,
            msg=("Setup invariant: outbound SYN MUST advertise WSCALE " "(default-on per shipped behaviour)."),
        )

        # Peer's SYN+ACK omits WSCALE.
        peer_post_handshake_win = 32768
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_post_handshake_win,
            mss=PEER__MSS,
            # wscale=None (deliberately omitted).
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake must complete on peer SYN+ACK.",
        )
        self.assertEqual(
            session._win.snd_wsc,
            0,
            msg=(
                "RFC 7323 §2.2 us-only asymmetric: peer omitted WSCALE, "
                f"so '_snd_wsc' MUST stay at 0. Got {session._win.snd_wsc}."
            ),
        )
        self.assertEqual(
            session._win.snd_wnd,
            peer_post_handshake_win,
            msg=(
                f"RFC 7323 §2.2 us-only asymmetric: '_snd_wnd' MUST equal "
                f"peer's raw 'win' ({peer_post_handshake_win}) unshifted. "
                f"Got {session._win.snd_wnd}."
            ),
        )

    def test__wscale__active_open_neither_advertises_disables_scaling(self) -> None:
        """
        Ensure that an active open where NEITHER side
        advertises WSCALE results in scaling being not in
        effect; '_snd_wsc' and '_rcv_wsc' both remain 0 and
        '_snd_wnd' equals peer's raw 'win' field.

        Reference: RFC 7323 §2.2 (bilateral non-offer rule).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._advertise.wscale = False
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertIsNone(
            syn_probe.wscale,
            msg="Setup invariant: opt-out -> outbound SYN MUST NOT carry WSCALE.",
        )

        # Peer's SYN+ACK also omits WSCALE.
        peer_post_handshake_win = 32768
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_post_handshake_win,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(session.state, FsmState.ESTABLISHED)
        self.assertEqual(
            session._win.snd_wsc,
            0,
            msg=("Neither side offered WSCALE: '_snd_wsc' MUST be 0. " f"Got {session._win.snd_wsc}."),
        )
        self.assertEqual(
            session._win.rcv_wsc,
            0,
            msg=("Neither side offered WSCALE: '_rcv_wsc' MUST be 0. " f"Got {session._win.rcv_wsc}."),
        )
        self.assertEqual(
            session._win.snd_wnd,
            peer_post_handshake_win,
            msg=(
                f"Neither side offered WSCALE: '_snd_wnd' MUST equal "
                f"peer's raw 'win' ({peer_post_handshake_win}) "
                f"unshifted. Got {session._win.snd_wnd}."
            ),
        )
