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
Integration tests for the TCP PLPMTUD probe-segment emit
path (Sub-Phase 3c-minimum of the PLPMTUD plan). Exercises:

  * Probe-emit hook fires when 'candidate_mtu - overhead'
    exceeds 'snd_mss' AND enough application data is
    buffered to fill the probe.
  * Emitted probe segment carries 'candidate_mtu - overhead'
    payload bytes (sized at the probe, not at the regular
    snd_mss).
  * Adapter records the probe via 'record_emitted_probe' so
    the snd.una hook can later detect the ACK.

These tests use an artificially-shrunken 'snd_mss' to
trigger the probe-emit gate under the current PyTCP
classical-PMTUD coupling. In normal operation, 'snd_mss' is
at 'interface_mtu - overhead' (link-MTU capacity) and the
engine's candidate is at most 'search_high - overhead =
interface_mtu - overhead', so 'probe_payload > snd_mss' is
never true. Future work (Phase 3c-major) will decouple
'snd_mss' from ICMP signals and let PLPMTUD drive the MSS
based on the engine's confirmed ack_size — at which point
probes naturally fire upward toward interface_mtu without
the artificial-shrink setup.

pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_probe_emit.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.lib.plpmtud import PmtuState
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
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


class TestTcpPlpmtudProbeEmit(TcpTestCase):
    """
    The TCP PLPMTUD probe-segment emit tests.
    """

    def _make_established_session(self) -> TcpSession:
        """
        Build an ESTABLISHED-state session against PEER. Forces
        the handshake to completion so the session is ready to
        emit data segments.
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        # Drive SYN → SYN-ACK → ACK to ESTABLISHED via the
        # harness helper if available; otherwise force the
        # state directly. The session-internal forcing is
        # acceptable here because this is a focused probe-emit
        # test, not an FSM-handshake test.
        session._change_state(FsmState.ESTABLISHED)
        self._advance(ms=1)
        return session

    def test__tcp__plpmtud__probe_emit__fires_when_candidate_exceeds_snd_mss(self) -> None:
        """
        Ensure that when the engine's candidate probe size
        (minus overhead) exceeds 'snd_mss' AND enough data
        is buffered to fill the probe, the next emitted
        data segment carries the probe-sized payload
        instead of the usual MSS-capped size.

        Reference: RFC 4821 §5 (probe segment generation).
        """

        session = self._make_established_session()
        # Enable PLPMTUD probing (Linux 'tcp_mtu_probing=1'
        # equivalent; default is OFF matching Linux).
        session._plpmtud_probing_enabled = True
        # Artificially shrink snd_mss so the engine's BASE
        # candidate (1200 bytes IPv4) exceeds it.
        session._win.snd_mss = 500
        # Open the receive window so 'usable_window' doesn't
        # cap the probe (snd_ewn is the limit; the test
        # session has cwnd = snd_mss = 500 initially).
        session._cc.snd_ewn = 5000
        # Buffer enough data for a 1200-byte probe payload.
        session._tx.buffer.extend(b"A" * 5000)

        frames_before = len(self._frames_tx)
        session._transmit_data()
        emitted_frames = self._frames_tx[frames_before:]

        self.assertGreaterEqual(
            len(emitted_frames),
            1,
            msg="_transmit_data must emit at least one segment when data is buffered.",
        )
        # The first emitted frame should carry the probe-sized
        # TCP payload. IPv4 frame: Ethernet(14) + IPv4(20) +
        # TCP(20 + opts) + payload. For BASE_PLPMTU__IP4=1200,
        # probe payload = 1200 - 40 (IP+TCP fixed) - opts.
        first_frame = emitted_frames[0]
        # IPv4 packet total = candidate_mtu = 1200. Frame =
        # Ethernet header + IPv4 packet.
        self.assertEqual(
            len(first_frame),
            14 + 1200,
            msg="First emitted frame must be Ethernet(14) + IPv4 packet at BASE_PLPMTU__IP4 (1200).",
        )

    def test__tcp__plpmtud__probe_emit__sets_df_bit(self) -> None:
        """
        Ensure the emitted IPv4 probe segment carries the
        Don't-Fragment (DF) bit set, so a path that cannot
        carry the probe-sized packet drops it (black-hole) or
        returns ICMP Frag-Needed rather than fragmenting it —
        which would falsely confirm the larger MTU.

        Reference: RFC 8899 §3 (probe MUST set IPv4 DF).
        Reference: RFC 4821 §7.5 (probe must not be fragmented).
        """

        session = self._make_established_session()
        session._plpmtud_probing_enabled = True
        session._win.snd_mss = 500
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        frames_before = len(self._frames_tx)
        session._transmit_data()
        first_frame = self._frames_tx[frames_before:][0]

        # IPv4 flags sit in the top 3 bits of byte 6 of the IPv4
        # header; the frame is Ethernet(14) + IPv4, so the flags
        # byte is at frame offset 14 + 6 = 20. DF is bit 6 (0x40).
        ipv4_flags_byte = first_frame[20]
        self.assertTrue(
            ipv4_flags_byte & 0x40,
            msg=f"The emitted IPv4 probe segment must set the DF bit. Got flags byte: {ipv4_flags_byte:#04x}.",
        )
        self.assertFalse(
            ipv4_flags_byte & 0x20,
            msg=f"The emitted IPv4 probe segment must not set the MF bit. Got flags byte: {ipv4_flags_byte:#04x}.",
        )

    def test__tcp__plpmtud__probe_emit__records_in_flight(self) -> None:
        """
        Ensure the probe-emit path records the (seq, size)
        entry in the adapter's in-flight dict so the
        subsequent snd.una hook can detect the ACK.

        Reference: RFC 4821 §7.6 (probe result feedback to engine).
        """

        session = self._make_established_session()
        session._plpmtud_probing_enabled = True
        session._win.snd_mss = 500
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        session._transmit_data()

        self.assertEqual(
            len(session._plpmtud_adapter.in_flight_probe_sizes),
            1,
            msg="Exactly one probe must be recorded as in-flight after emit.",
        )
        self.assertEqual(
            session._plpmtud_adapter.in_flight_probe_sizes[0],
            1200,
            msg="Recorded probe size must equal the engine's candidate (1200 BASE_PLPMTU__IP4).",
        )

    def test__tcp__plpmtud__probe_emit__no_emit_when_insufficient_data(self) -> None:
        """
        Ensure that when there is NOT enough application data
        to fill the probe-sized payload, the probe-emit path
        is skipped — a probe must be a complete data segment
        of the candidate size, never a padded short segment.

        Reference: PyTCP design simplification (only probe with available data).
        """

        session = self._make_established_session()
        session._plpmtud_probing_enabled = True
        session._win.snd_mss = 500
        session._cc.snd_ewn = 5000
        # Only 100 bytes buffered — far below the 1160-byte
        # probe payload requirement.
        session._tx.buffer.extend(b"A" * 100)

        session._transmit_data()

        self.assertEqual(
            len(session._plpmtud_adapter.in_flight_probe_sizes),
            0,
            msg="Probe must NOT be recorded when insufficient data is buffered.",
        )

    def test__tcp__plpmtud__probe_emit__ack_transitions_engine(self) -> None:
        """
        Ensure that when a probe is emitted and the resulting
        snd.una advance is processed (via the adapter's
        on_snd_una_advance hook from Phase 3b), the engine
        transitions from BASE to SEARCHING — closing the
        end-to-end probe → ACK → state-advance loop.

        Reference: RFC 8899 §5.2 (Base → Search on confirmation).
        Reference: RFC 4821 §7.6.1 (probe success).
        """

        session = self._make_established_session()
        session._plpmtud_probing_enabled = True
        session._win.snd_mss = 500
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        session._transmit_data()
        # The adapter records the probe at the post-emit
        # snd.nxt; simulate the peer's ACK by manually calling
        # the adapter's snd_una hook with a value past the
        # probe end seq.
        new_snd_una = session._snd_seq.nxt  # post-probe-emit snd.nxt
        session._plpmtud_adapter.on_snd_una_advance(
            new_snd_una=new_snd_una,
            now=1.0,
        )

        self.assertIs(
            session._plpmtud_adapter.state,
            PmtuState.SEARCHING,
            msg="Probe ack via snd.una advance must transition adapter BASE → SEARCHING.",
        )
