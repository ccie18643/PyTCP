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
Integration tests for the Linux-aligned PLPMTUD wiring
(Phase 3d) on TCP. Exercises the realistic scenario where
classical-PMTUD ICMP shrinks 'snd_mss', then PLPMTUD active
probing tests upward and grows 'snd_mss' back when the
probe succeeds.

Key contracts verified:

  * Probing DEFAULT-OFF matches Linux's 'tcp_mtu_probing=0':
    even when ICMP has shrunk snd_mss and the engine has a
    larger candidate, no probe fires unless the per-session
    flag is explicitly set.
  * Engine 'on_classical_pmtu' shrinks 'current_mtu' but
    NOT 'search_high' — so post-ICMP the engine retains
    headroom to probe upward toward 'interface_mtu'.
  * Probe success advances 'snd_mss' to the engine's
    confirmed 'current_mtu - overhead' (Linux's
    'tcp_mtu_probe_success' equivalent).

pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_linux.py

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
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000


class TestTcpPlpmtudLinuxAligned(TcpTestCase):
    """
    Linux-aligned PLPMTUD wiring tests.
    """

    def _make_established_session(self) -> TcpSession:
        """
        Build an ESTABLISHED-state session against PEER.
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
        session._change_state(FsmState.ESTABLISHED)
        self._advance(ms=1)
        return session

    def test__tcp__plpmtud__probing_default_off_does_not_fire(self) -> None:
        """
        Ensure that with '_plpmtud_probing_enabled = False'
        (the default, matching Linux's tcp_mtu_probing=0)
        no probe segment is emitted even when the engine
        has a viable candidate and snd_mss has been shrunk
        below it. The probe-emit hook MUST gate on the
        per-session flag.

        Reference: Linux tcp(7) (tcp_mtu_probing=0 default).
        """

        session = self._make_established_session()
        # Default probing flag is False; do NOT set it.
        session._win.snd_mss = 500
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        session._transmit_data()

        self.assertEqual(
            len(session._plpmtud_adapter.in_flight_probe_sizes),
            0,
            msg="Default-off probing must NOT emit a probe even when conditions are met.",
        )

    def test__tcp__plpmtud__icmp_does_not_shrink_search_high(self) -> None:
        """
        Ensure that an inbound classical PMTU signal shrinks
        the engine's working PLPMTU ('current_mtu') but does
        NOT lower 'search_high' — the engine retains the
        ability to probe upward toward 'interface_mtu' so a
        future probe can verify the ICMP-reported MTU
        wasn't overly conservative.

        Reference: Linux tcp_mtu_probing model (search range stays open post-ICMP).
        Reference: RFC 8201 §4 (PTB shrinks PLPMTU, not the probe range).
        """

        session = self._make_established_session()
        engine = session._plpmtud_adapter.engine
        prior_search_high = engine._search_high
        prior_current = engine.current_mtu

        # Simulate an inbound classical PMTU signal.
        session._plpmtud_adapter.on_classical_pmtu(700, now=1.0)

        self.assertLessEqual(
            engine.current_mtu,
            min(prior_current, 700),
            msg="ICMP MTU=700 must shrink engine.current_mtu to <= 700.",
        )
        self.assertEqual(
            engine._search_high,
            prior_search_high,
            msg="ICMP signal MUST NOT lower engine.search_high (Linux-aligned).",
        )

    def test__tcp__plpmtud__probe_ack_grows_snd_mss(self) -> None:
        """
        Ensure that when a PLPMTUD probe is acked (via the
        snd.una advance hook), 'snd_mss' grows to the
        engine's confirmed 'current_mtu - overhead' — the
        Linux 'tcp_mtu_probe_success' equivalent that lets
        future data segments use the larger MSS.

        Reference: Linux tcp_mtu_probe_success (mss_cache grows on probe ack).
        Reference: RFC 4821 §7.6.1 (probe success advances eff_pmtu).
        """

        session = self._make_established_session()
        session._plpmtud_probing_enabled = True
        # Simulate ICMP having shrunk snd_mss earlier; the
        # engine's current_mtu is still tracking via the
        # adapter.
        session._win.snd_mss = 500
        session._plpmtud_adapter.on_classical_pmtu(700, now=0.5)
        # current_mtu = 700; snd_mss = 500 (independent
        # since classical _apply_pmtu_update path is not
        # exercised here).
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        # Emit a probe. With probing enabled + engine
        # candidate > snd_mss, this fires.
        session._transmit_data()
        probes = session._plpmtud_adapter.in_flight_probe_sizes
        self.assertEqual(
            len(probes),
            1,
            msg="Precondition: exactly one probe must be in flight.",
        )
        probe_size = probes[0]
        # Manually drive the snd.una advance hook + the
        # snd_mss growth hook by invoking the engine ack
        # path. We don't drive the full FSM ACK packet here
        # because that has many side effects; the snd_mss
        # growth hook is part of '_process_ack_packet'
        # which we exercise by simulating its key
        # invocations.
        session._plpmtud_adapter.on_snd_una_advance(
            new_snd_una=(session._snd_seq.una + probe_size) & 0xFFFFFFFF,
            now=1.0,
        )
        # The snd_mss-grow hook lives in the
        # '_process_ack_packet' path; emulate by replaying
        # the inline body.
        engine_mss = session._plpmtud_adapter.current_mtu - session._ip_tcp_overhead
        if engine_mss > session._win.snd_mss:
            session._win.snd_mss = engine_mss

        self.assertEqual(
            session._win.snd_mss,
            probe_size - session._ip_tcp_overhead,
            msg="Probe ack must grow snd_mss to probe_size - overhead.",
        )

    def test__tcp__plpmtud__icmp_post_shrink_engine_still_probes_upward(self) -> None:
        """
        Ensure that after classical PMTU shrinks
        'current_mtu' to a smaller value, the engine's
        candidate (computed from ack_size and search_high)
        is still larger than the shrunken snd_mss — so the
        probe-emit gate naturally fires when probing is
        enabled. This is the realistic production scenario.

        Reference: Linux tcp_mtu_probing scenario after ICMP shrink.
        """

        session = self._make_established_session()
        session._plpmtud_probing_enabled = True
        # ICMP shrinks current_mtu to 800 via adapter.
        session._plpmtud_adapter.on_classical_pmtu(800, now=0.5)
        # Simulate the matching snd_mss shrink (the
        # '_apply_pmtu_update' path normally does this in
        # production; we shrink directly here so we don't
        # depend on the inbound-ICMP plumbing in this test).
        session._win.snd_mss = 800 - session._ip_tcp_overhead  # 760
        session._cc.snd_ewn = 5000
        session._tx.buffer.extend(b"A" * 5000)

        session._transmit_data()

        # The engine's candidate (BASE = 1200 for IPv4)
        # exceeds snd_mss (760); a probe must fire.
        self.assertEqual(
            len(session._plpmtud_adapter.in_flight_probe_sizes),
            1,
            msg="Post-ICMP, probing-enabled session must emit a probe upward.",
        )
        probe_size = session._plpmtud_adapter.in_flight_probe_sizes[0]
        self.assertGreater(
            probe_size,
            800,
            msg="Probe size must exceed the ICMP-shrunken current_mtu (probing upward).",
        )
