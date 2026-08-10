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
Integration tests for the 'tcp.mtu_probing' / 'tcp.base_mss'
PLPMTUD operator-enable surface — Phase 2 of the close-out
plan at 'docs/refactor/plpmtud_closeout.md'.

The probe-emit hot path is unchanged (already shipped in
sub-Phase 3c-minimum); this file pins the cold-start
plumbing that makes the path REACHABLE in default deployments:
'TcpSession.__init__' reads the per-interface 'tcp.mtu_probing'
tristate sysctl, sets the per-session probing flag, and (when
enabled) seeds 'snd_mss' from 'tcp.base_mss' so the engine's
'candidate_mtu > snd_mss' probe-emit gate trips immediately
instead of saturating against 'interface_mtu - overhead' the
way classical PMTUD does.

The seven tests below mirror the §4 Phase 2 test matrix of the
close-out plan one-for-one.

pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_cold_start.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.runtime.socket import AddressFamily
from pytcp.runtime.socket.tcp__socket import TcpSocket
from pytcp.stack import sysctl as sysctl_module
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


class _PlpmtudColdStartFixture(TcpTestCase):
    """
    Shared fixture — resets every per-iface sysctl slot on
    teardown so a 'tcp.mtu_probing=2' write in one test does
    not leak into the next.
    """

    @override
    def tearDown(self) -> None:
        """
        Clear per-iface sysctl storage so the next test sees
        the registered defaults.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _make_session(self, *, force_iss: int = LOCAL__ISS) -> TcpSession:
        """
        Build an unstarted IPv4 session against PEER. The
        session is constructed but the FSM is still in
        CLOSED — useful for pinning '__init__'-time state
        without a handshake.
        """

        self._force_iss(force_iss)
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
        return session


class TestTcpPlpmtudColdStart(_PlpmtudColdStartFixture):
    """
    The 'tcp.mtu_probing' / 'tcp.base_mss' cold-start
    seeding tests. Pin both the per-session probing-flag
    plumbing and the 'snd_mss' seed that gives the engine
    upward-probing headroom.
    """

    def test__tcp__plpmtud__mtu_probing_default_off_no_seed(self) -> None:
        """
        Ensure with 'tcp.mtu_probing=0' (the registered
        default) a fresh session opens with the per-session
        probing flag OFF — no behavioural change versus the
        pre-Phase-2 baseline.

        Reference: Linux net.ipv4.tcp_mtu_probing default 0 (off).
        """

        session = self._make_session()
        self.assertFalse(
            session._plpmtud_probing_enabled,
            msg="Default 'tcp.mtu_probing=0' must leave the per-session probing flag OFF.",
        )

    def test__tcp__plpmtud__mtu_probing_2_enables_probe_emit_flag(self) -> None:
        """
        Ensure setting 'tcp.mtu_probing=2' flips the
        per-session probing flag to ON during session init
        — the operator-facing knob the PLPMTUD probe-emit
        hook in 'session/tcp__session__tx.py' already gates
        on.

        Reference: Linux net.ipv4.tcp_mtu_probing=2 (always-on).
        """

        sysctl_module.set("tcp.default.mtu_probing", 2)
        session = self._make_session()
        self.assertTrue(
            session._plpmtud_probing_enabled,
            msg="'tcp.mtu_probing=2' must flip per-session probing flag ON at init.",
        )

    def test__tcp__plpmtud__mtu_probing_2_seeds_snd_mss_from_base_mss(self) -> None:
        """
        Ensure with 'tcp.mtu_probing=2' a fresh session
        opens with 'snd_mss == base_mss - overhead' so the
        engine's 'candidate_mtu > snd_mss' probe-emit gate
        trips on the first data send. Without this seed
        'snd_mss' would saturate at 'interface_mtu - overhead'
        and the gate would never fire — the "Probing without
        ICMP" scenario unreachable.

        Reference: Linux net.ipv4.tcp_base_mss (snd_mss seed).
        Reference: RFC 4821 §3 (Probing without ICMP).
        """

        sysctl_module.set("tcp.default.mtu_probing", 2)
        session = self._make_session()
        # IPv4: ip_tcp_overhead = 20 + 20 = 40. base_mss
        # default = 1024. egress_interface_mtu in the
        # harness = the canonical TAP MTU (1500). So seed =
        # min(1024, 1500) - 40 = 984.
        expected_snd_mss = 1024 - session._ip_tcp_overhead
        self.assertEqual(
            session._win.snd_mss,
            expected_snd_mss,
            msg="snd_mss must be seeded from 'tcp.base_mss - overhead' when probing is ON.",
        )

    def test__tcp__plpmtud__cold_start_seed_capped_at_interface_mtu(self) -> None:
        """
        Ensure a pathological operator config that raises
        'tcp.base_mss' ABOVE the egress interface MTU
        sanity-caps the cold-start seed at
        'interface_mtu - overhead' — the seed is the
        starting point for upward probing toward
        'interface_mtu'; setting it above the link ceiling
        would have nowhere to probe to and would also
        produce immediate local fragmentation.

        Reference: RFC 4821 §3 (probe between BASE and search_high).
        """

        sysctl_module.set("tcp.default.mtu_probing", 2)
        # Push base_mss above the harness's canonical TAP MTU
        # (1500). The seed must clamp at 'iface_mtu - overhead'.
        sysctl_module.set("tcp.default.base_mss", 9000)
        session = self._make_session()
        iface_mtu = session._egress_interface_mtu()
        expected_snd_mss = iface_mtu - session._ip_tcp_overhead
        self.assertEqual(
            session._win.snd_mss,
            expected_snd_mss,
            msg="snd_mss seed must clamp at 'iface_mtu - overhead' when base_mss exceeds interface MTU.",
        )

    def test__tcp__plpmtud__mtu_probing_per_iface_scope(self) -> None:
        """
        Ensure 'tcp.<ifname>.mtu_probing = 2' only enables
        probing for sessions whose egress interface name
        matches — other interfaces still see the
        '"default"' template (0 = off).

        Reference: Linux net.ipv4.conf.<iface>.tcp_mtu_probing per-iface scope.
        """

        # Write the override under a name DIFFERENT from the
        # egress interface this session resolves to. Probing
        # must stay OFF because the lookup falls through to
        # the 'default' template (still 0).
        sysctl_module.set("tcp.other_iface.mtu_probing", 2)
        session = self._make_session()
        self.assertFalse(
            session._plpmtud_probing_enabled,
            msg="Per-iface override on a non-matching name must not flip the flag.",
        )

    def test__tcp__plpmtud__mtu_probing_rejects_mode_1(self) -> None:
        """
        Ensure the 'tcp.mtu_probing' validator rejects mode
        1 — Linux's "enable after RTO loss suspected to be
        black-hole" — which needs heuristics PyTCP does not
        have today. The rejection message must name the
        deferred-mode rationale so the operator sees an
        actionable error rather than a bare 'ValueError'.

        Reference: Linux net.ipv4.tcp_mtu_probing mode 1 (RTO black-hole).
        """

        with self.assertRaises(ValueError) as ctx:
            sysctl_module.set("tcp.default.mtu_probing", 1)
        self.assertIn(
            "deferred",
            str(ctx.exception).lower(),
            msg="The rejection message must mention that mode 1 is deferred.",
        )

    def test__tcp__plpmtud__cold_start_probe_emits_upward(self) -> None:
        """
        Ensure end-to-end that with 'tcp.mtu_probing=2'
        enabled, driving a full SYN -> SYN-ACK -> ACK
        handshake against a peer advertising a large MSS
        and then buffering enough data emits a first
        segment carrying the engine's candidate-sized
        payload (BASE_PLPMTU__IP4 = 1200 IPv4 packet bytes),
        NOT the peer-MSS-sized payload — proving the
        handshake clamp sites honour the cold-start seed
        and the probe-emit gate trips.

        Reference: RFC 4821 §3 (Probing without ICMP).
        Reference: RFC 4821 §5 (probe segment generation).
        Reference: RFC 8899 §5 (PLPMTUD state machine).
        """

        sysctl_module.set("tcp.default.mtu_probing", 2)
        # Peer advertises MSS=1460 (would normally drive
        # snd_mss up to interface_mtu - overhead and kill
        # the probe-emit gate). With cold-start seeding the
        # handshake clamp must keep snd_mss at base_mss -
        # overhead = 984.
        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_mss=1460,
        )

        self.assertTrue(
            session._plpmtud_probing_enabled,
            msg="Probing flag must remain ON after handshake.",
        )
        self.assertEqual(
            session._win.snd_mss,
            1024 - session._ip_tcp_overhead,
            msg="Handshake clamp must honour the cold-start base_mss ceiling.",
        )

        # Open the receive window so 'usable_window' doesn't
        # cap the probe and buffer enough data for a
        # 1200-byte probe payload.
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        frames_before = len(self._frames_tx)
        session._transmit_data()
        emitted_frames = self._frames_tx[frames_before:]

        self.assertGreaterEqual(
            len(emitted_frames),
            1,
            msg="_transmit_data must emit at least one segment when data is buffered.",
        )
        # IPv4 frame = Ethernet(14) + IPv4 packet at
        # BASE_PLPMTU__IP4 (1200). If snd_mss had been
        # clobbered to 1460 by the handshake, the segment
        # would be sized at min(snd_ewn=5000, snd_mss=1460,
        # remaining)=1460-payload, packed in a 1500-MTU
        # frame — NOT at the probe size.
        self.assertEqual(
            len(emitted_frames[0]),
            14 + 1200,
            msg="First emitted frame must be Ethernet(14) + IPv4 packet at BASE_PLPMTU__IP4 (1200).",
        )
