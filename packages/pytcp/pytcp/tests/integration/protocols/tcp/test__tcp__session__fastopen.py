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
This module contains integration tests for RFC 7413 TCP Fast Open
(TFO) in 'TcpSession'. RFC 7413 §1 motivates TFO as the mechanism
that lets a TCP connection carry application data on the SYN
itself, eliminating the round-trip cost of the standard 3-way
handshake for short-lived connections (HTTP requests, RPC calls,
DNS over TCP, etc.).

The mechanism splits cleanly into two roles:

  Server side (this file's first scenarios):
    1. Cookie issuance: when peer sends SYN with the TFO option
       carrying an empty cookie (the 'cookie request' form), the
       server generates an opaque, peer-bound cookie (HMAC of the
       peer's IP + a server-side secret) and returns it in the
       SYN+ACK.
    2. Cookie use: when peer's SYN carries a previously-issued
       valid cookie + data payload, the server validates the
       cookie, queues the data for the application, and ACKs the
       data in the SYN+ACK so the application sees the data
       before the third-leg ACK arrives.

  Client side (subsequent scenarios):
    3. Cookie cache: client caches the server's cookie keyed by
       (peer IP, peer port).
    4. Connect-with-data: 'connect()' with data + cached cookie
       emits SYN with cookie + data. The server accepts the data
       in the SYN+ACK, eliminating the data RTT.

The RFC 7413 §2 wire format uses Kind = 34 and a Length field
that distinguishes empty-cookie (Length = 2, request form) from
non-empty-cookie (Length = 6..18, response/use form).

pytcp/tests/integration/protocols/tcp/test__tcp__session__fastopen.py

ver 3.0.8
"""

from net_addr import Ip4Address, Ip6Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4, build_tcp6
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS

# IPv6 addressing for the IPv6 regression-guard scenario.
STACK__IP6: Ip6Address = STACK__IP6_HOST.address
PEER__IP6: Ip6Address = HOST_A__IP6_ADDRESS

# Listen-side ISS pinned for deterministic SYN+ACK seq numbers.
LOCAL__ISS: int = 0x0000_3000

# Peer's advertised receive window on its SYN.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN.
PEER__MSS: int = 1460

# Peer's source ISS on its SYN.
PEER__ISS: int = 0x0000_4000

# Distinct peer source port for the TFO scenarios (avoids
# collision with other TestTcpSession__* classes that bind
# the canonical PEER__PORT = 80 themselves).
PEER__PORT_FOR_FASTOPEN: int = 33500


class TestTcpSession__FastOpen(TcpTestCase):
    """
    Integration tests for RFC 7413 Fast Open (TFO) on
    'TcpSession'. The first scenario pins server-side cookie
    issuance: a SYN with an empty TFO cookie request MUST elicit
    a SYN+ACK that carries a non-empty cookie via the TFO option.
    """

    def _make_listen_session(
        self,
        *,
        iss: int,
        enable_tfo: bool = False,
    ) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them. When 'enable_tfo'
        is True, opts the listening socket in to TFO via
        'setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 16)' before the
        FSM is driven into LISTEN; the LISTEN handler reads the
        opt-in flag to decide whether to issue cookies and
        accept TFO SYN-data.
        """

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0
        if enable_tfo:
            sock._tcp_fastopen_qlen = 16
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock, session

    def test__fastopen__server_issues_cookie_on_tfo_request_syn(self) -> None:
        """
        Ensure that when an inbound SYN carries the Fast Open
        option with an empty cookie (the cookie-request form,
        Length = 2), our SYN+ACK reply carries the Fast Open
        option with a non-empty 4..16 byte cookie that the
        peer can cache and present on a subsequent connection.
        The cookie value itself is opaque from the peer's
        perspective.

        Reference: RFC 7413 §2 (Fast Open option wire format and cookie length 4..16 bytes).
        Reference: RFC 7413 §3.1 (server-side cookie issuance on TFO request).
        """

        _listen_sock, _listen_session = self._make_listen_session(iss=LOCAL__ISS, enable_tfo=True)

        # Peer SYN with TFO option carrying an empty cookie
        # (the 'cookie request' form).
        peer_syn_tfo_request = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",  # empty cookie -> request form
        )
        self._drive_rx(frame=peer_syn_tfo_request)

        # Tick to fire SYN+ACK from the spawned child's timer.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg=("Setup precondition: the SYN+ACK MUST fire on " "the next tick after a SYN arrives."),
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertEqual(
            syn_ack.flags & frozenset({"SYN", "ACK", "RST", "FIN"}),
            frozenset({"SYN", "ACK"}),
            msg=(
                "Setup precondition: outbound segment MUST be a " f"SYN+ACK (no RST/FIN). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertIsNotNone(
            syn_ack.fastopen_cookie,
            msg=(
                "RFC 7413 §3.1: a SYN+ACK in response to a TFO "
                "cookie request MUST carry the TFO option with a "
                "non-empty cookie. Today the option is absent on "
                "the wire (PyTCP ignores TFO entirely)."
            ),
        )
        # Cookie length per RFC 7413 §2 must be 4..16 bytes.
        assert syn_ack.fastopen_cookie is not None  # mypy
        cookie_len = len(syn_ack.fastopen_cookie)
        self.assertGreaterEqual(
            cookie_len,
            4,
            msg=(
                f"RFC 7413 §2: TFO cookie length MUST be at "
                f"least 4 bytes. Got {cookie_len} bytes "
                f"({syn_ack.fastopen_cookie!r})."
            ),
        )
        self.assertLessEqual(
            cookie_len,
            16,
            msg=(
                f"RFC 7413 §2: TFO cookie length MUST be at "
                f"most 16 bytes. Got {cookie_len} bytes "
                f"({syn_ack.fastopen_cookie!r})."
            ),
        )

    def test__fastopen__server_discards_syn_data_when_cookie_invalid(self) -> None:
        """
        Ensure that when a peer SYN carries the Fast Open
        option with an INVALID (or empty / cookie-request)
        cookie alongside a data payload, the server
        discards the data and falls back to a standard
        three-way handshake. The SYN+ACK 'ack' field MUST
        cover only the SYN (peer_iss + 1) - NOT the SYN
        plus data length - and the data MUST NOT be queued
        into the receive buffer where a future 'recv()'
        could deliver it to the application. The cookie
        gate is the canonical amplification-attack defence:
        an off-path attacker spoofing a SYN with data
        cannot commit server memory without first proving
        peer-IP reachability via a valid cookie.

        Reference: RFC 7413 §3.1 (server discards data on invalid TFO cookie).
        Reference: RFC 7413 §4.1.2 (cookie validation gate before data acceptance).
        """

        _listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS, enable_tfo=True)

        # Peer SYN with the empty-cookie request form
        # (invalid for data acceptance per §4.1.2) plus a
        # non-trivial data payload that would otherwise be
        # delivered to the application's recv() buffer.
        syn_data = b"hello-tfo"
        peer_syn_data_no_cookie = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",  # cookie-request form, invalid for data
            payload=syn_data,
        )
        self._drive_rx(frame=peer_syn_data_no_cookie)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertEqual(
            syn_ack.flags & frozenset({"SYN", "ACK", "RST", "FIN"}),
            frozenset({"SYN", "ACK"}),
            msg=(
                "Setup precondition: outbound segment MUST be a " f"SYN+ACK (no RST/FIN). Got flags={syn_ack.flags!r}."
            ),
        )
        # The spec encoding: ack covers only the SYN's
        # one byte of seq space; the data is discarded.
        self.assertEqual(
            syn_ack.ack,
            PEER__ISS + 1,
            msg=(
                "RFC 7413 §3.1: SYN+ACK 'ack' MUST equal "
                f"peer_iss + 1 = {PEER__ISS + 1} when the "
                "TFO cookie is invalid - the server MUST NOT "
                "ack the SYN-data. Got "
                f"{syn_ack.ack} (= peer_iss + 1 + "
                f"{syn_ack.ack - PEER__ISS - 1}); the server "
                "is acking the data despite the missing valid "
                "cookie, which violates the §4.1.2 "
                "amplification-attack defence."
            ),
        )
        # Data MUST NOT be queued into the listening child's
        # receive buffer. Today PyTCP queues SYN-data
        # unconditionally per RFC 9293 §3.10.7.2 step 3;
        # the TFO cookie gate is the security override.
        self.assertEqual(
            bytes(listen_session._rx_buffer),
            b"",
            msg=(
                "RFC 7413 §3.1: invalid TFO cookie + SYN-data "
                "MUST result in the data being discarded - the "
                "child session's '_rx_buffer' MUST be empty. "
                f"Got {bytes(listen_session._rx_buffer)!r}."
            ),
        )

    def test__fastopen__server_accepts_syn_data_with_valid_cookie(self) -> None:
        """
        Ensure that when a peer SYN carries the Fast Open
        option with a previously-issued (and therefore
        valid for this peer IP) cookie alongside a data
        payload, the server accepts the data: the SYN+ACK
        'ack' field covers both the SYN and the data
        ('peer_iss + 1 + len(data)') and the data is
        queued into the child session's receive buffer
        ready for the application's eventual 'recv()'.

        The valid cookie is computed via the same HMAC
        helper the server uses for issuance, so the test
        exercises the round-trip the cookie validation
        path is gated on.

        Reference: RFC 7413 §3.1 (server accepts SYN-data on valid TFO cookie).
        """

        from pytcp import stack
        from pytcp.protocols.tcp.tcp__fastopen import generate_cookie

        # Compute the cookie the server WOULD issue for our
        # test peer IP - this is what a peer would have
        # cached after a previous round-trip and would now
        # replay on a TFO-fast-open SYN.
        valid_cookie = generate_cookie(
            peer_address=PEER__IP,
            secret=stack.TCP__FASTOPEN_SECRET,
        )

        _listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS, enable_tfo=True)

        syn_data = b"valid-tfo-data"
        peer_syn_with_cookie_and_data = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=valid_cookie,
            payload=syn_data,
        )
        self._drive_rx(frame=peer_syn_with_cookie_and_data)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        # The spec encoding: ack covers SYN + data.
        self.assertEqual(
            syn_ack.ack,
            PEER__ISS + 1 + len(syn_data),
            msg=(
                "RFC 7413 §3.1: SYN+ACK 'ack' MUST equal "
                f"peer_iss + 1 + len(data) = "
                f"{PEER__ISS + 1 + len(syn_data)} when the "
                "TFO cookie is valid. The server has "
                f"accepted the {len(syn_data)} bytes of "
                f"SYN-data. Got {syn_ack.ack}."
            ),
        )
        # Data MUST be queued for delivery to the
        # application via 'recv()'.
        self.assertEqual(
            bytes(listen_session._rx_buffer),
            syn_data,
            msg=(
                "RFC 7413 §3.1: SYN-data with valid TFO "
                "cookie MUST be queued into the child "
                f"session's '_rx_buffer'. Expected "
                f"{syn_data!r}, got "
                f"{bytes(listen_session._rx_buffer)!r}."
            ),
        )

    def _make_active_session(  # type: ignore[override]
        self,
        *,
        iss: int,
    ) -> TcpSession:
        """
        TFO addressing override — uses PEER__PORT_FOR_FASTOPEN as the
        local client port and LISTEN__PORT as the remote server port
        instead of the canonical 12345 / 80 defaults.
        """

        return super()._make_active_session(
            iss=iss,
            local_port=PEER__PORT_FOR_FASTOPEN,
            remote_port=LISTEN__PORT,
        )

    def test__fastopen__active_open_syn_advertises_tfo_cookie_request(self) -> None:
        """
        Ensure that on a first connection the active-open
        SYN carries the Fast Open option in the
        cookie-request form (Length = 2, empty cookie).
        The client has no cached cookie for this server
        yet, so it advertises an empty cookie request to
        elicit the server's cookie issuance in the SYN+ACK
        reply. On a subsequent connection the client
        replays the cached cookie + data payload to skip
        the data RTT.

        Reference: RFC 7413 §3.1 (client first connect emits TFO cookie request).
        """

        # Ensure the cache is empty for this test scenario;
        # a previous test (or test order) may have populated
        # it via the cache scenario below.
        stack.tcp_stack.fastopen_cookies.pop(PEER__IP, None)

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN MUST fire on the first tick.",
        )
        syn = self._parse_tx(syn_tx[0])

        self.assertEqual(
            syn.flags & frozenset({"SYN", "ACK", "RST", "FIN"}),
            frozenset({"SYN"}),
            msg=("Setup precondition: outbound segment MUST be " f"a pure SYN (active open). Got flags={syn.flags!r}."),
        )
        # The spec encoding: TFO option present with empty
        # cookie payload (Length = 2, the cookie-request form).
        self.assertEqual(
            syn.fastopen_cookie,
            b"",
            msg=(
                "RFC 7413 §3.1: client's active-open SYN MUST "
                "carry the Fast Open option in the cookie-request "
                "form (empty cookie). Got "
                f"fastopen_cookie={syn.fastopen_cookie!r}."
            ),
        )

    def test__fastopen__client_caches_server_cookie_and_replays_on_next_connect(self) -> None:
        """
        Ensure that after a client active-open handshake
        whose SYN+ACK carried a Fast Open cookie, the
        cookie is cached against the peer's IP and replayed
        on a subsequent active-open SYN to the same peer.
        This is the round-trip that earns the
        Fast-Open-named latency saving: the first connect
        round-trip seeds the cache, and every connect
        thereafter to the same server can preemptively
        carry data on the SYN.

        Reference: RFC 7413 §3.1 (client cookie cache + replay).
        Reference: RFC 7413 §4.1.3 (cookie cache keyed by server IP).
        """

        cached_cookie = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
        stack.tcp_stack.fastopen_cookies.pop(PEER__IP, None)

        # First connection: empty cookie request. Drive the
        # SYN+ACK with the server-supplied cookie.
        first_session = self._make_active_session(iss=LOCAL__ISS)
        first_session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            src_ip=PEER__IP,
            dst_ip=STACK__IP,
            sport=LISTEN__PORT,
            dport=PEER__PORT_FOR_FASTOPEN,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=cached_cookie,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(
            first_session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: first connection MUST reach ESTABLISHED.",
        )

        # The spec encoding: cache is populated.
        self.assertEqual(
            stack.tcp_stack.fastopen_cookies.get(PEER__IP),
            cached_cookie,
            msg=(
                "RFC 7413 §3.1: a peer-supplied TFO cookie "
                "MUST be cached against the peer IP. Cache "
                f"lookup: {stack.tcp_stack.fastopen_cookies.get(PEER__IP)!r}, "
                f"expected {cached_cookie!r}."
            ),
        )

        # Second connection to the same peer: outbound SYN
        # MUST carry the cached cookie, not the empty
        # cookie-request form.
        # Use a different source port so the second session
        # has a distinct 4-tuple from the first.
        second_local_iss = LOCAL__ISS + 0x1000
        self._force_iss(second_local_iss)
        second_sock = TcpSocket(family=AddressFamily.INET4)
        second_sock._local_ip_address = STACK__IP
        second_sock._local_port = PEER__PORT_FOR_FASTOPEN + 1
        second_sock._remote_ip_address = PEER__IP
        second_sock._remote_port = LISTEN__PORT
        second_session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=PEER__PORT_FOR_FASTOPEN + 1,
            remote_ip_address=PEER__IP,
            remote_port=LISTEN__PORT,
            socket=second_sock,
        )
        second_sock._tcp_session = second_session
        stack.sockets[second_sock.socket_id] = second_sock

        second_session.tcp_fsm(syscall=SysCall.CONNECT)
        second_syn_tx = self._advance(ms=1)
        # Capture the second session's outbound SYN. There
        # may be other TX (first session retransmits, etc.);
        # filter to the one whose source port matches the
        # second session.
        second_syn = None
        for frame in second_syn_tx:
            probe = self._parse_tx(frame)
            if probe.sport == PEER__PORT_FOR_FASTOPEN + 1:
                second_syn = probe
                break

        self.assertIsNotNone(
            second_syn,
            msg=("Setup precondition: second active-open SYN MUST fire on the next tick."),
        )
        assert second_syn is not None  # mypy
        self.assertEqual(
            second_syn.fastopen_cookie,
            cached_cookie,
            msg=(
                "RFC 7413 §3.1: a subsequent active-open SYN "
                "to the same peer MUST replay the cached "
                f"cookie. Expected cookie={cached_cookie!r}, "
                f"got {second_syn.fastopen_cookie!r}."
            ),
        )

    def test__fastopen__active_open_syn_carries_data_when_cookie_cached(self) -> None:
        """
        Ensure that on an active-open with a cached TFO
        cookie for the peer AND pre-loaded send-buffer
        data, the outbound SYN carries the data payload
        alongside the cookie. This is the round-trip
        saving that gives TCP Fast Open its name: the
        client sends application data piggybacked on the
        SYN itself, and a cooperating server accepts the
        data immediately on cookie validation rather than
        waiting for the third-leg ACK to start data
        transfer.

        Reference: RFC 7413 §3.1 (client subsequent connect: SYN-with-data).
        """

        cached_cookie = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
        stack.tcp_stack.fastopen_cookies[PEER__IP] = cached_cookie

        session = self._make_active_session(iss=LOCAL__ISS)
        # Pre-load the TX buffer with application data the
        # caller wants to attach to the SYN. Mirrors the
        # BSD-style 'sendto(MSG_FASTOPEN, data, server)'
        # entry path: the data is queued before 'connect()'
        # so the TFO-aware SYN emit can slice it onto the
        # wire.
        early_data = b"GET / HTTP/1.1\r\n"
        session._tx.buffer.extend(early_data)

        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: SYN MUST fire on the next tick.",
        )
        syn = self._parse_tx(syn_tx[0])

        # The spec encoding: SYN carries cached cookie.
        self.assertEqual(
            syn.fastopen_cookie,
            cached_cookie,
            msg=(
                "RFC 7413 §3.1: active-open SYN with a "
                "cached cookie MUST replay it on the wire. "
                f"Expected {cached_cookie!r}, got "
                f"{syn.fastopen_cookie!r}."
            ),
        )
        # The spec encoding: SYN carries the pre-loaded data.
        self.assertEqual(
            syn.payload,
            early_data,
            msg=(
                "RFC 7413 §3.1: active-open SYN with a "
                "cached cookie MUST carry the pre-loaded "
                f"send-buffer data. Expected {early_data!r}, "
                f"got {syn.payload!r}."
            ),
        )

    def test__fastopen__client_tfo_data_acked_in_syn_ack_drains_tx_buffer(self) -> None:
        """
        Ensure that when client's TFO SYN-with-data is
        accepted by the server (the SYN+ACK 'ack' field
        covers SYN + data), the post-handshake state is
        consistent: the session reaches ESTABLISHED,
        SND.UNA advances past the data, and the TX
        buffer is drained of the bytes the server has
        confirmed receipt of. This is the canonical
        successful-fast-open completion path; any
        residue in the TX buffer would cause the
        post-handshake transmit to spuriously re-send
        the already-acked bytes.

        Reference: RFC 7413 §3.1 (successful TFO completion: data ack'd in SYN+ACK).
        """

        cached_cookie = b"\xab\xcd\xef\x01\x23\x45\x67\x89"
        stack.tcp_stack.fastopen_cookies[PEER__IP] = cached_cookie

        session = self._make_active_session(iss=LOCAL__ISS)
        early_data = b"hello-tfo"
        session._tx.buffer.extend(early_data)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        # Tick so the SYN-with-data fires.
        self._advance(ms=1)

        # Server's SYN+ACK accepts the TFO data: 'ack'
        # covers SYN + data ('peer_iss + 0' on peer side,
        # ack on our side = LOCAL__ISS + 1 + len(data)).
        peer_syn_ack = build_tcp4(
            src_ip=PEER__IP,
            dst_ip=STACK__IP,
            sport=LISTEN__PORT,
            dport=PEER__PORT_FOR_FASTOPEN,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1 + len(early_data),
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=("Successful TFO completion MUST land in " f"ESTABLISHED. Got state={session.state!r}."),
        )
        self.assertEqual(
            session._snd_seq.una,
            LOCAL__ISS + 1 + len(early_data),
            msg=(
                "RFC 7413 §3.1: SND.UNA MUST advance past "
                f"SYN + data = {LOCAL__ISS + 1 + len(early_data)} "
                "after the server's SYN+ACK ack covers the "
                f"data. Got {session._snd_seq.una}."
            ),
        )
        self.assertEqual(
            bytes(session._tx.buffer),
            b"",
            msg=(
                "RFC 7413 §3.1: server-acked TFO data MUST "
                "be drained from the client's TX buffer; a "
                "residue would cause the post-handshake "
                "transmit to spuriously re-send the bytes. "
                f"Got {bytes(session._tx.buffer)!r}."
            ),
        )

    def test__fastopen__server_syn_ack_retransmit_still_carries_tfo_cookie(self) -> None:
        """
        Ensure that when the server retransmits a SYN+ACK
        (because the third-leg ACK has not arrived within
        the RTO), the retransmit MUST still carry the Fast
        Open option with the same cookie. SYN+ACK
        retransmits are required to be option-equivalent
        to the original so a peer that lost the original
        SYN+ACK still receives the cookie on the
        retransmit and can cache it for subsequent
        connections.

        Reference: RFC 7413 §3.1 (SYN+ACK retransmits carry the same cookie).
        """

        _listen_sock, _listen_session = self._make_listen_session(iss=LOCAL__ISS, enable_tfo=True)

        # Peer SYN with TFO cookie request.
        peer_syn = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",
        )
        self._drive_rx(frame=peer_syn)

        # First SYN+ACK fires on the next tick; capture the
        # cookie it issued so the retransmit can be compared.
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first SYN+ACK MUST fire on the first tick.",
        )
        first_syn_ack = self._parse_tx(first_tx[0])
        self.assertIsNotNone(
            first_syn_ack.fastopen_cookie,
            msg="Setup precondition: first SYN+ACK MUST carry a TFO cookie.",
        )
        original_cookie = first_syn_ack.fastopen_cookie

        # Drive past the RTO so the retransmit timer fires.
        # PyTCP's INITIAL_RTO_MS = 1000; advance well past
        # so the retransmit handler runs and re-emits the
        # SYN+ACK from SYN_RCVD.
        retransmit_tx = self._advance(ms=1100)

        # Find the re-emitted SYN+ACK in the retransmit
        # window.
        retransmit_syn_ack = None
        for frame in retransmit_tx:
            probe = self._parse_tx(frame)
            if probe.flags == frozenset({"SYN", "ACK"}):
                retransmit_syn_ack = probe
                break

        self.assertIsNotNone(
            retransmit_syn_ack,
            msg=(
                "Setup precondition: a SYN+ACK retransmit MUST "
                "fire after the RTO when the third-leg ACK has "
                f"not arrived. Got {len(retransmit_tx)} frames "
                f"in the post-RTO window."
            ),
        )
        assert retransmit_syn_ack is not None  # mypy
        # The spec encoding: retransmit SYN+ACK carries the
        # SAME cookie as the original.
        self.assertEqual(
            retransmit_syn_ack.fastopen_cookie,
            original_cookie,
            msg=(
                "RFC 7413 §3.1: the retransmitted SYN+ACK "
                "MUST carry the same TFO cookie as the "
                "original. Today PyTCP consumes the cookie on "
                "first emit so the retransmit carries no TFO "
                f"option. Original cookie={original_cookie!r}, "
                f"retransmit cookie={retransmit_syn_ack.fastopen_cookie!r}."
            ),
        )

    def test__fastopen__client_resends_tfo_data_when_server_rejects(self) -> None:
        """
        Ensure that when the server's SYN+ACK acknowledges
        only the SYN (the server discarded the TFO data,
        e.g., because the cookie failed validation or TFO
        is disabled), the client retransmits the data
        promptly post-handshake instead of waiting for the
        RTO timer to fire. The client side rewinds SND.NXT
        to SND.UNA after the partial-ack handshake so the
        data still in the TX buffer is re-emitted on the
        next tick alongside the third-leg ACK.

        Reference: RFC 7413 §4.2 (client resends data when server only acks SYN).
        """

        cached_cookie = b"\x10\x20\x30\x40\x50\x60\x70\x80"
        stack.tcp_stack.fastopen_cookies[PEER__IP] = cached_cookie

        session = self._make_active_session(iss=LOCAL__ISS)
        early_data = b"reject-me"
        session._tx.buffer.extend(early_data)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        # Tick so the SYN-with-data fires.
        self._advance(ms=1)

        # Server's SYN+ACK acks ONLY the SYN (rejected the
        # TFO data); 'ack = peer_iss + 1', not
        # 'peer_iss + 1 + len(data)'.
        peer_syn_ack = build_tcp4(
            src_ip=PEER__IP,
            dst_ip=STACK__IP,
            sport=LISTEN__PORT,
            dport=PEER__PORT_FOR_FASTOPEN,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        post_syn_ack_tx = self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: handshake MUST reach " "ESTABLISHED even when the server rejects the " "TFO data."
            ),
        )

        # Find a post-handshake segment carrying the
        # rejected data. The third-leg ACK fires inline on
        # SYN+ACK reception; PyTCP's
        # 'tcp_fsm__syn_sent.fsm__syn_sent' calls
        # '_transmit_packet(flag_ack=True)' before the
        # ESTABLISHED transition, but a retransmit of the
        # unacked data needs to fire on the next tick.
        post_tick_tx = self._advance(ms=1)
        all_post_handshake_tx = list(post_syn_ack_tx) + list(post_tick_tx)
        data_segment = None
        for frame in all_post_handshake_tx:
            probe = self._parse_tx(frame)
            if probe.payload == early_data:
                data_segment = probe
                break

        self.assertIsNotNone(
            data_segment,
            msg=(
                "RFC 7413 §4.2: a TFO client whose SYN-data was "
                "rejected (SYN+ACK acked only the SYN) MUST "
                "retransmit the data promptly after handshake "
                "completion (not wait for the RTO retransmit "
                f"timer). Got {len(all_post_handshake_tx)} TX "
                "frames in the post-handshake window, none "
                "carrying the rejected data "
                f"({early_data!r})."
            ),
        )

    def test__fastopen__server_does_not_issue_cookie_when_tfo_disabled(self) -> None:
        """
        Ensure that when the listening socket has not opted
        in to TCP Fast Open via 'setsockopt(IPPROTO_TCP,
        TCP_FASTOPEN, qlen)' with a positive queue depth,
        the server MUST NOT issue a TFO cookie even when
        the inbound SYN carries the option in the
        cookie-request form. The cookie issuance is gated
        on the listening socket's '_tcp_fastopen_qlen > 0';
        without explicit opt-in the server falls back to a
        standard TCP handshake. This matches Linux's
        TFO-disabled-by-default semantics and gives the
        application a clear opt-in switch for TFO support.

        Reference: RFC 7413 §3.1 (server opts in to TFO via setsockopt).
        """

        listen_sock, _listen_session = self._make_listen_session(iss=LOCAL__ISS)
        # Sanity: the socket must NOT have opted in to TFO.
        self.assertEqual(
            listen_sock._tcp_fastopen_qlen,
            0,
            msg="Setup precondition: TCP_FASTOPEN MUST default to 0.",
        )

        peer_syn_tfo_request = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",
        )
        self._drive_rx(frame=peer_syn_tfo_request)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])
        self.assertIsNone(
            syn_ack.fastopen_cookie,
            msg=(
                "RFC 7413 §3.1: server MUST NOT issue a TFO "
                "cookie when the listening socket has not opted "
                "in via 'setsockopt(IPPROTO_TCP, TCP_FASTOPEN, "
                "qlen)' with qlen > 0. Today PyTCP issues "
                "cookies unconditionally on any TFO-bearing "
                "SYN, leaking TFO support to clients even when "
                "the application has not enabled it. Got "
                f"fastopen_cookie={syn_ack.fastopen_cookie!r}."
            ),
        )

    def test__fastopen__cookie_cache_evicts_oldest_at_cap(self) -> None:
        """
        Ensure that when an insert into the client-side
        TFO cookie cache would exceed the configured size
        cap, the oldest entry is evicted in FIFO order.
        Bounds per-process memory for long-running clients
        that connect to many distinct servers.

        Reference: RFC 7413 §3.1 (cookie cache size limit).
        Reference: RFC 7413 §4.1.3 (cache management).
        """

        from pytcp.protocols.tcp.tcp__fastopen import cache_cookie

        # Patch the cap to a small value so the test can
        # observe the eviction without inserting 1024
        # entries.
        self._start_patch("pytcp.stack.TCP__FASTOPEN_CACHE_MAX_SIZE", 3)
        stack.tcp_stack.fastopen_cookies.clear()

        peers = [
            Ip4Address("10.1.1.1"),
            Ip4Address("10.1.1.2"),
            Ip4Address("10.1.1.3"),
            Ip4Address("10.1.1.4"),
        ]
        cookies = [bytes([i]) * 8 for i in range(len(peers))]
        for peer, cookie in zip(peers, cookies):
            cache_cookie(peer_address=peer, cookie=cookie)

        # The spec encoding: cap honoured.
        self.assertEqual(
            len(stack.tcp_stack.fastopen_cookies),
            3,
            msg=(
                "RFC 7413 §3.1: cache MUST NOT exceed "
                "'TCP__FASTOPEN_CACHE_MAX_SIZE = 3' "
                "entries. Got "
                f"{len(stack.tcp_stack.fastopen_cookies)} entries; "
                "the eviction logic in 'cache_cookie' did not "
                "fire."
            ),
        )
        # Oldest entry MUST be evicted.
        self.assertNotIn(
            peers[0],
            stack.tcp_stack.fastopen_cookies,
            msg=(
                "FIFO eviction: the oldest peer "
                f"({peers[0]}) MUST be the first evicted "
                "entry when an insert exceeds the cap."
            ),
        )
        # Newest entry MUST be present.
        self.assertEqual(
            stack.tcp_stack.fastopen_cookies.get(peers[-1]),
            cookies[-1],
            msg=(
                f"Newest cookie (peer={peers[-1]}) MUST be "
                f"present and equal to {cookies[-1]!r}. Got "
                f"{stack.tcp_stack.fastopen_cookies.get(peers[-1])!r}."
            ),
        )

    def test__fastopen__server_issues_cookie_on_tfo_request_syn_over_ipv6(self) -> None:
        """
        Ensure that the server-side TFO cookie issuance
        path works for IPv6 peers identically to IPv4.
        Regression guard for the IP-version-agnostic
        contract: 'TcpOptionFastOpen' is wire-format only,
        'generate_cookie' accepts 'Ip4Address | Ip6Address'
        and uses 'bytes(peer_address)' as HMAC input
        (4 bytes for IPv4, 16 bytes for IPv6 - both stable
        keys), and the LISTEN handler reads
        'packet_rx_md.ip__remote_address' polymorphically.
        Without this guard, a future change that
        accidentally hard-coded IPv4-only behaviour (e.g.
        truncating the address bytes to 4) would not be
        caught by the existing IPv4-only TFO test surface.

        Reference: RFC 7413 §3.1 (server-side cookie issuance, IP-version-agnostic).
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET6)
        sock._local_ip_address = STACK__IP6
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip6Address()
        sock._remote_port = 0
        sock._tcp_fastopen_qlen = 16  # opt in to TFO
        session = TcpSession(
            local_ip_address=STACK__IP6,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip6Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)

        peer_syn_tfo_request = build_tcp6(
            src_ip=PEER__IP6,
            dst_ip=STACK__IP6,
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",
        )
        self._drive_rx(frame=peer_syn_tfo_request)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertIsInstance(
            syn_ack.ip_src,
            Ip6Address,
            msg="Setup precondition: outbound SYN+ACK MUST be carried over IPv6.",
        )
        self.assertIsNotNone(
            syn_ack.fastopen_cookie,
            msg=(
                "RFC 7413 §3.1: SYN+ACK to an IPv6 TFO-request "
                "SYN MUST carry a non-empty cookie identical "
                "to the IPv4 path. Got "
                f"fastopen_cookie={syn_ack.fastopen_cookie!r}."
            ),
        )
        assert syn_ack.fastopen_cookie is not None  # mypy
        cookie_len = len(syn_ack.fastopen_cookie)
        self.assertGreaterEqual(
            cookie_len,
            4,
            msg=(
                "RFC 7413 §2: TFO cookie length MUST be at "
                f"least 4 bytes for IPv6 peers as well. Got "
                f"{cookie_len} bytes."
            ),
        )
        self.assertLessEqual(
            cookie_len,
            16,
            msg=(
                "RFC 7413 §2: TFO cookie length MUST be at "
                f"most 16 bytes for IPv6 peers as well. Got "
                f"{cookie_len} bytes."
            ),
        )
