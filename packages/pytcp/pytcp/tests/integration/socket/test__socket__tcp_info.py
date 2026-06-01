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
Integration tests for the 'getsockopt(IPPROTO_TCP, TCP_INFO)'
surface — M5 of the socket-layer Linux parity audit
('docs/refactor/socket_linux_parity_audit.md' §M5). Linux exposes
~50 fields of per-connection statistics through TCP_INFO so
diagnostic tooling (`ss -i`, telemetry agents) can introspect the
in-kernel state without parsing logs; this set pins the wire-format
shape of the bytes PyTCP returns and the major populated fields.

PyTCP's pre-existing 'TcpSocket.status()' returning a 'TcpStatus'
dataclass remains the high-level API; TCP_INFO is the Linux-shaped
wire surface bolted on top so applications written against the
stdlib socket pattern see the bytes they expect.

pytcp/tests/integration/socket/test__socket__tcp_info.py

ver 3.0.8
"""

import struct
from typing import override

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.socket import IPPROTO_TCP, TCP_INFO, AddressFamily
from pytcp.socket.tcp__info import (
    TCP_INFO__STRUCT,
    TcpInfoOption,
    TcpInfoState,
)
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000


class TestTcpSocketGetsockoptTcpInfo(TcpTestCase):
    """
    The 'getsockopt(IPPROTO_TCP, TCP_INFO)' wire-format + state-mapping
    tests.
    """

    def test__tcp_info__struct_size_matches_linux_5_5_layout(self) -> None:
        """
        Ensure the registered TCP_INFO struct layout packs to the
        Linux 5.5 size of 240 bytes — the layout most consumers in
        the wild (telemetry agents, `ss -i`) target. Smaller or
        larger layouts would break 'struct.unpack' on the consumer
        side.

        Reference: Linux include/uapi/linux/tcp.h struct tcp_info (~5.5).
        """

        self.assertEqual(
            struct.calcsize(TCP_INFO__STRUCT),
            240,
            msg="TCP_INFO struct must pack to 240 bytes (Linux 5.5 layout).",
        )

    def test__tcp_info__no_session_returns_close_state_zero_filled(self) -> None:
        """
        Ensure a fresh socket with no associated 'TcpSession'
        returns the canonical "all zeros + state=TCP_CLOSE" struct
        — matches Linux's behaviour on a never-connected socket.

        Reference: Linux net/ipv4/tcp.c tcp_get_info (CLOSED default).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        info = sock.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        self.assertIsInstance(
            info,
            bytes,
            msg="TCP_INFO must return 'bytes' (the packed struct).",
        )
        self.assertEqual(
            len(info),
            240,
            msg="The returned struct must be the full 240-byte layout.",
        )
        # State byte (offset 0) must be TCP_CLOSE = 7.
        self.assertEqual(
            info[0],
            TcpInfoState.CLOSE,
            msg="State byte for a session-less socket must be TCP_CLOSE.",
        )
        # Every byte past the state byte must be zero.
        self.assertEqual(
            info[1:],
            b"\x00" * 239,
            msg="Every byte past the state byte must be zero on a session-less socket.",
        )

    def test__tcp_info__established_session_packs_state_byte(self) -> None:
        """
        Ensure an ESTABLISHED session reports
        'tcpi_state == TCP_ESTABLISHED (1)' — the canonical
        Linux value diagnostic tools key off.

        Reference: Linux include/uapi/linux/tcp.h TCP_ESTABLISHED=1.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
        )
        info = session._socket.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        self.assertEqual(
            info[0],
            TcpInfoState.ESTABLISHED,
            msg=f"ESTABLISHED session must map to tcpi_state={TcpInfoState.ESTABLISHED}.",
        )

    def test__tcp_info__snd_mss_matches_session_state(self) -> None:
        """
        Ensure the packed 'tcpi_snd_mss' field matches
        'session._win.snd_mss' — the canonical Linux source for
        the field. The peer in this test advertises MSS=1460
        (Ethernet floor); the handshake clamp settles snd_mss at
        the egress-interface MTU minus IP+TCP overhead.

        Reference: Linux include/uapi/linux/tcp.h tcpi_snd_mss.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_mss=1460,
        )
        info = session._socket.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        fields = struct.unpack(TCP_INFO__STRUCT, info)
        # 'tcpi_snd_mss' field index: 8 u8 + rto + ato = field index 10.
        snd_mss = fields[10]
        self.assertEqual(
            snd_mss,
            session._win.snd_mss,
            msg="tcpi_snd_mss must equal session._win.snd_mss.",
        )

    def test__tcp_info__rcv_mss_matches_session_state(self) -> None:
        """
        Ensure the packed 'tcpi_rcv_mss' field matches
        'session._win.rcv_mss'.

        Reference: Linux include/uapi/linux/tcp.h tcpi_rcv_mss.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
        )
        info = session._socket.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        fields = struct.unpack(TCP_INFO__STRUCT, info)
        # 'tcpi_rcv_mss' field index: 8 u8 + rto + ato + snd_mss = 11.
        rcv_mss = fields[11]
        self.assertEqual(
            rcv_mss,
            session._win.rcv_mss,
            msg="tcpi_rcv_mss must equal session._win.rcv_mss.",
        )

    def test__tcp_info__cwnd_and_ssthresh_match_session_cc(self) -> None:
        """
        Ensure 'tcpi_snd_cwnd' and 'tcpi_snd_ssthresh' fields
        match the session's congestion-control state — the
        canonical inputs to RFC 5681 / RFC 6582 / RFC 9438 cwnd
        evolution.

        Reference: Linux include/uapi/linux/tcp.h tcpi_snd_cwnd / tcpi_snd_ssthresh.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
        )
        info = session._socket.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        fields = struct.unpack(TCP_INFO__STRUCT, info)
        # Field layout: 8 u8 (indices 0-7) + rto + ato + snd_mss +
        # rcv_mss + unacked + sacked + lost + retrans + fackets +
        # last_data_sent + last_ack_sent + last_data_recv +
        # last_ack_recv + pmtu + rcv_ssthresh + rtt + rttvar +
        # snd_ssthresh (25) + snd_cwnd (26).
        snd_ssthresh = fields[25]
        snd_cwnd = fields[26]
        # Linux's tcpi_snd_cwnd / tcpi_snd_ssthresh are in SEGMENTS
        # (MSS-units), not bytes. PyTCP's session._cc.cwnd /
        # .ssthresh carry BYTES; the packer divides by snd_mss for
        # ABI parity. Compare against the divided value here.
        snd_mss = session._win.snd_mss
        self.assertEqual(
            snd_cwnd,
            session._cc.cwnd // snd_mss,
            msg="tcpi_snd_cwnd must equal (session._cc.cwnd // snd_mss) in segments.",
        )
        self.assertEqual(
            snd_ssthresh,
            session._cc.ssthresh // snd_mss,
            msg="tcpi_snd_ssthresh must equal (session._cc.ssthresh // snd_mss) in segments.",
        )

    def test__tcp_info__options_flags_reflect_negotiation(self) -> None:
        """
        Ensure the 'tcpi_options' bitfield reports the
        bilaterally-negotiated options — TIMESTAMPS / SACK /
        WSCALE. A handshake with a peer advertising all three
        sets all three bits.

        Reference: Linux include/uapi/linux/tcp.h TCPI_OPT_TIMESTAMPS/SACK/WSCALE.
        Reference: RFC 7323 §2 (TCP Timestamps).
        Reference: RFC 2018 §2 (TCP SACK).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
            peer_wscale=7,
            peer_tsval=12345,
            peer_tsecr=0,
        )
        info = session._socket.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        # 'tcpi_options' is the 6th u8 (offset 5).
        options = info[5]
        self.assertEqual(
            options & TcpInfoOption.TIMESTAMPS,
            TcpInfoOption.TIMESTAMPS,
            msg="TCPI_OPT_TIMESTAMPS must be set when timestamps bilaterally negotiated.",
        )
        self.assertEqual(
            options & TcpInfoOption.SACK,
            TcpInfoOption.SACK,
            msg="TCPI_OPT_SACK must be set when SACK bilaterally negotiated.",
        )
        self.assertEqual(
            options & TcpInfoOption.WSCALE,
            TcpInfoOption.WSCALE,
            msg="TCPI_OPT_WSCALE must be set when WSCALE bilaterally negotiated.",
        )

    def test__tcp_info__wscale_byte_packs_both_nibbles(self) -> None:
        """
        Ensure the 7th u8 packs 'tcpi_snd_wscale : 4' in the low
        nibble and 'tcpi_rcv_wscale : 4' in the high nibble —
        matching the Linux bit layout.

        Reference: Linux include/uapi/linux/tcp.h struct tcp_info bit layout.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_wscale=7,
        )
        info = session._socket.getsockopt(IPPROTO_TCP, TCP_INFO)
        assert isinstance(info, bytes)
        # 7th u8 (offset 6) packs snd_wscale:4 (low) + rcv_wscale:4 (high).
        wscale_byte = info[6]
        snd_wscale = wscale_byte & 0x0F
        rcv_wscale = (wscale_byte >> 4) & 0x0F
        self.assertEqual(
            snd_wscale,
            session._win.snd_wsc,
            msg="snd_wscale nibble (low 4 bits) must equal session._win.snd_wsc.",
        )
        self.assertEqual(
            rcv_wscale,
            session._win.rcv_wsc,
            msg="rcv_wscale nibble (high 4 bits) must equal session._win.rcv_wsc.",
        )

    def test__tcp_info__fsm_state_map_covers_every_fsm_state(self) -> None:
        """
        Ensure the FsmState → Linux tcpi_state map is total
        (every PyTCP FsmState member has a Linux counterpart)
        and that the canonical mappings match the kernel ABI —
        the diagnostic tools key off the exact integer values.

        Reference: Linux include/uapi/linux/tcp.h enum tcp_states (1..11).
        """

        from pytcp.socket.tcp__info import _FSM_TO_TCP_INFO_STATE

        # Coverage — every FsmState member must have a mapping.
        for fsm_state in FsmState:
            self.assertIn(
                fsm_state,
                _FSM_TO_TCP_INFO_STATE,
                msg=f"FsmState.{fsm_state.name} must map to a Linux tcpi_state.",
            )

        # Canonical individual mappings — the values diagnostic
        # tools test for directly.
        self.assertEqual(
            _FSM_TO_TCP_INFO_STATE[FsmState.CLOSED],
            TcpInfoState.CLOSE,
            msg="FsmState.CLOSED must map to TCP_CLOSE (7).",
        )
        self.assertEqual(
            _FSM_TO_TCP_INFO_STATE[FsmState.LISTEN],
            TcpInfoState.LISTEN,
            msg="FsmState.LISTEN must map to TCP_LISTEN (10).",
        )
        self.assertEqual(
            _FSM_TO_TCP_INFO_STATE[FsmState.SYN_SENT],
            TcpInfoState.SYN_SENT,
            msg="FsmState.SYN_SENT must map to TCP_SYN_SENT (2).",
        )
        self.assertEqual(
            _FSM_TO_TCP_INFO_STATE[FsmState.ESTABLISHED],
            TcpInfoState.ESTABLISHED,
            msg="FsmState.ESTABLISHED must map to TCP_ESTABLISHED (1).",
        )
        self.assertEqual(
            _FSM_TO_TCP_INFO_STATE[FsmState.TIME_WAIT],
            TcpInfoState.TIME_WAIT,
            msg="FsmState.TIME_WAIT must map to TCP_TIME_WAIT (6).",
        )

    def test__tcp_info__state_and_option_constants_are_typed_enums(self) -> None:
        """
        Ensure the tcpi_state values and tcpi_options bit flags are
        modelled as typed enum members carrying the Linux ABI integer
        values — 'TcpInfoState' an 'IntEnum' (one mutually-exclusive
        state per value) and 'TcpInfoOption' an 'IntFlag' (OR-combinable
        bits) — and that the FsmState map yields 'TcpInfoState' members.

        Reference: Linux include/uapi/linux/tcp.h enum tcp_states (1..11).
        Reference: Linux include/uapi/linux/tcp.h tcpi_options bit flags.
        """

        from enum import IntEnum, IntFlag

        from pytcp.socket.tcp__info import _FSM_TO_TCP_INFO_STATE

        self.assertTrue(
            issubclass(TcpInfoState, IntEnum),
            msg="TcpInfoState must be an IntEnum (mutually-exclusive states).",
        )
        self.assertTrue(
            issubclass(TcpInfoOption, IntFlag),
            msg="TcpInfoOption must be an IntFlag (OR-combinable bits).",
        )
        # Canonical state values from the kernel enum.
        self.assertEqual(
            TcpInfoState.ESTABLISHED,
            1,
            msg="TcpInfoState.ESTABLISHED must carry the Linux value 1.",
        )
        self.assertEqual(
            TcpInfoState.CLOSING,
            11,
            msg="TcpInfoState.CLOSING must carry the Linux value 11.",
        )
        # Canonical option bits.
        self.assertEqual(
            TcpInfoOption.SACK,
            2,
            msg="TcpInfoOption.SACK must carry the Linux bit value 2.",
        )
        self.assertEqual(
            TcpInfoOption.SYN_DATA,
            32,
            msg="TcpInfoOption.SYN_DATA must carry the Linux bit value 32.",
        )
        # Every FsmState map value must be a TcpInfoState member.
        for fsm_state, info_state in _FSM_TO_TCP_INFO_STATE.items():
            self.assertIsInstance(
                info_state,
                TcpInfoState,
                msg=f"_FSM_TO_TCP_INFO_STATE[{fsm_state.name}] must be a TcpInfoState member.",
            )

    @override
    def setUp(self) -> None:
        """
        Stand up the TcpTestCase fixture; nothing extra needed for
        the TCP_INFO surface (no harness-owned mocks beyond the
        TcpTestCase defaults).
        """

        super().setUp()
