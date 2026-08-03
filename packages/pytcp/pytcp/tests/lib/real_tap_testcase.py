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
This module contains the 'RealTapTestCase' base class for the root-gated
real-TAP end-to-end smoke suite. Unlike the wire-level integration
harness ('NetworkTestCase'), it runs the REAL daemon on an actual TAP
interface, so it exercises the OS edges the wire tests mock: '/dev/net/tun'
I/O, the real Tx/Rx rings, and real threads + wall-clock timers.

The suite is skipped unless run as root with 'PYTCP_REAL_TAP=1'; it needs
'CAP_NET_ADMIN' to create the tap and open '/dev/net/tun'. This is the one
PyTCP test surface where real time / 'select' timeouts / subprocesses are
legitimate — see docs/refactor/real_tap_smoke_suite.md.

pytcp/tests/lib/real_tap_testcase.py

ver 3.0.9
"""

import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from typing import override

from net_addr import Buffer, Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
)
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.arp.arp__assembler import ArpAssembler
from net_proto.protocols.arp.arp__enums import ArpOperation
from net_proto.protocols.arp.arp__parser import ArpParser
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from pytcp.client.client_stack import ClientStack, connect

# The AF_PACKET protocol number for "capture every ethertype" and the
# 'sll_pkttype' value flagging a frame the kernel is transmitting (our
# own outgoing copy, which the peer socket must ignore).
_ETH_P_ALL = 0x0003
_PACKET_OUTGOING = 4

# The maximum interface-name length the kernel accepts (IFNAMSIZ - 1).
_IFNAME_MAX = 15


def _real_tap_enabled() -> bool:
    """
    Return whether the real-TAP suite may run — root (for CAP_NET_ADMIN)
    and an explicit 'PYTCP_REAL_TAP=1' opt-in. Any normal 'make test'
    run (non-root, or root without the flag) skips the whole suite.
    """

    return os.geteuid() == 0 and os.environ.get("PYTCP_REAL_TAP") == "1"


@unittest.skipUnless(_real_tap_enabled(), "real-TAP suite: run as root with PYTCP_REAL_TAP=1 (needs CAP_NET_ADMIN)")
class RealTapTestCase(unittest.TestCase):
    """
    Base class for the real-TAP end-to-end smoke tests.

    'setUp' creates a persistent TAP, boots the real daemon on it (static
    dual-stack IPv4 + IPv6 address, no DHCP) in a subprocess, waits for
    readiness, and opens an AF_PACKET peer bound to the tap. The test
    drives the stack either from the wire (peer frames) or from above (the
    drop-in 'ClientStack' over the daemon's AF_UNIX control socket), and
    asserts on the real frames the daemon emits. Every resource is torn
    down via 'addCleanup' so a mid-'setUp' failure cannot leak a tap.

    Dual-stack boot on a router-less tap takes a few seconds of DAD
    serialization (link-local -> solicited-node -> static global) before
    readiness — the '_wait_ready' timeout is sized for it. (The earlier
    "IPv6 never reaches readiness" symptom was a real cross-thread
    membership-lock deadlock, fixed by routing IGMP/MLD state-change
    reports through the fire-and-forget TX path; see
    docs/refactor/real_tap_smoke_suite.md §7b.)
    """

    STACK_IP4: Ip4IfAddr = Ip4IfAddr("10.99.0.7/24")
    STACK_IP6: Ip6IfAddr = Ip6IfAddr("fd00:99::7/64")
    STACK_MAC: MacAddress = MacAddress("02:00:00:00:99:07")
    PEER_IP4: Ip4Address = Ip4Address("10.99.0.99")
    PEER_IP6: Ip6Address = Ip6Address("fd00:99::99")
    PEER_MAC: MacAddress = MacAddress("02:00:00:00:99:99")

    _tap: str
    _sock_path: str
    _ready_path: str
    _daemon: subprocess.Popen[bytes]
    _peer: socket.socket

    @override
    def setUp(self) -> None:
        """
        Create the tap, boot the daemon on it, and open the AF_PACKET peer.
        """

        # The daemon accepts only 'tap' / 'tun' interface-name prefixes
        # (_resolve_interface), so the name must start with 'tap'; the pid
        # keeps it unique across concurrent runs.
        self._tap = f"tap{os.getpid()}"[:_IFNAME_MAX]

        # A stale tap from a crashed prior run would fail the create — drop
        # it first (idempotent), then create the persistent tap + bring up.
        subprocess.run(["ip", "tuntap", "del", "name", self._tap, "mode", "tap"], check=False)
        subprocess.run(["ip", "tuntap", "add", "name", self._tap, "mode", "tap"], check=True)
        self.addCleanup(self._delete_tap)
        subprocess.run(["ip", "link", "set", "dev", self._tap, "up"], check=True)

        tmp_dir = tempfile.mkdtemp(prefix="pytcp-realtap-")
        self.addCleanup(shutil.rmtree, tmp_dir, ignore_errors=True)
        self._sock_path = os.path.join(tmp_dir, "daemon.sock")
        self._ready_path = os.path.join(tmp_dir, "daemon.ready")
        self._daemon = self._start_daemon()
        self.addCleanup(self._stop_daemon)
        # Dual-stack DAD (link-local -> solicited-node -> static global)
        # plus IPv4 ACD serializes over a few seconds on a router-less tap.
        self._wait_ready(timeout=30.0)

        self._peer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        self.addCleanup(self._peer.close)
        self._peer.bind((self._tap, 0))
        self._peer.setblocking(False)

    def _start_daemon(self) -> "subprocess.Popen[bytes]":
        """
        Boot the real daemon on the tap in a subprocess with a static
        dual-stack address (no DHCP), signalling readiness via a file.
        """

        runner = (
            "from pytcp.daemon.daemon import run_daemon\n"
            "from net_addr import Ip4IfAddr, Ip6IfAddr, MacAddress\n"
            "run_daemon(\n"
            f"    socket_path={self._sock_path!r},\n"
            f"    interfaces=[{self._tap!r}],\n"
            f"    mac_address=MacAddress({str(self.STACK_MAC)!r}),\n"
            f"    ip4_host=Ip4IfAddr({str(self.STACK_IP4)!r}),\n"
            f"    ip6_host=Ip6IfAddr({str(self.STACK_IP6)!r}),\n"
            "    ip6_support=True,\n"
            f"    on_ready=lambda _p: open({self._ready_path!r}, 'w').close(),\n"
            ")\n"
        )
        return subprocess.Popen(
            [sys.executable, "-c", runner],
            cwd=".",
            env={**os.environ, "PYTHONPATH": "."},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _wait_ready(self, *, timeout: float) -> None:
        """
        Block until the daemon signals readiness (its control server is
        listening), failing if it exits or does not come up in time.
        """

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(self._ready_path):
                return
            if self._daemon.poll() is not None:
                self.fail(f"daemon exited during boot (rc={self._daemon.returncode})")
            time.sleep(0.05)
        self.fail(f"daemon did not signal readiness within {timeout}s")

    def _stop_daemon(self) -> None:
        """
        Signal the daemon to shut down and reap it (kill on overrun).
        """

        if self._daemon.poll() is None:
            self._daemon.send_signal(signal.SIGTERM)
            try:
                self._daemon.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._daemon.kill()
                self._daemon.wait(timeout=5.0)

    def _delete_tap(self) -> None:
        """
        Remove the persistent tap (idempotent).
        """

        subprocess.run(["ip", "tuntap", "del", "name", self._tap, "mode", "tap"], check=False)

    # --- Wire helpers (the test is the peer) -------------------------

    def _peer_send(self, frame: bytes, /) -> None:
        """
        Inject a raw Ethernet frame onto the wire toward the stack.
        """

        self._peer.send(frame)

    def _peer_expect(
        self,
        predicate: Callable[[PacketRx], bool],
        /,
        *,
        timeout: float = 3.0,
    ) -> PacketRx:
        """
        Return the first inbound frame (skipping our own outgoing copies)
        whose Ethernet-parsed 'PacketRx' satisfies 'predicate', failing on
        timeout. 'predicate' may parse further layers; a parse error on a
        non-matching frame is swallowed so unrelated traffic (the stack's
        own DAD / RA / gratuitous ARP boot chatter) does not derail the
        match.
        """

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self._peer], [], [], min(0.2, max(0.0, deadline - time.monotonic())))
            if not ready:
                continue
            try:
                data, addr = self._peer.recvfrom(2048)
            except BlockingIOError:
                continue
            if addr[2] == _PACKET_OUTGOING:
                continue
            packet_rx = PacketRx(data)
            try:
                EthernetParser(packet_rx)
                if predicate(packet_rx):
                    return packet_rx
            except Exception:  # pylint: disable=broad-exception-caught
                continue
        self.fail(f"no inbound frame matched within {timeout}s")

    def _build_eth(
        self,
        *,
        dst: MacAddress,
        payload: ArpAssembler | Ip4Assembler | Ip6Assembler,
    ) -> bytes:
        """
        Assemble an Ethernet frame from an ARP / IPv4 / IPv6 'payload'
        sourced from the peer MAC.
        """

        eth = EthernetAssembler(ethernet__src=self.PEER_MAC, ethernet__dst=dst, ethernet__payload=payload)
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _prime_peer_neighbor(self) -> None:
        """
        Announce the peer's IPv4 address with a gratuitous ARP so the
        stack can reach the peer without a resolution round trip (for
        tests that drive the stack to send toward the peer).
        """

        arp = ArpAssembler(
            arp__oper=ArpOperation.REPLY,
            arp__sha=self.PEER_MAC,
            arp__spa=self.PEER_IP4,
            arp__tha=self.PEER_MAC,
            arp__tpa=self.PEER_IP4,
        )
        self._peer_send(self._build_eth(dst=MacAddress("ff:ff:ff:ff:ff:ff"), payload=arp))

    def _answer_arp_for_peer(self, *, timeout: float = 3.0) -> None:
        """
        Wait for the stack to ARP-request the peer's IPv4 address and
        answer it, so a stack-originated send toward the peer resolves.
        """

        def _is_arp_request_for_peer(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.ARP:
                return False
            ArpParser(packet_rx)
            return packet_rx.arp.oper is ArpOperation.REQUEST and packet_rx.arp.tpa == self.PEER_IP4

        self._peer_expect(_is_arp_request_for_peer, timeout=timeout)

        reply = ArpAssembler(
            arp__oper=ArpOperation.REPLY,
            arp__sha=self.PEER_MAC,
            arp__spa=self.PEER_IP4,
            arp__tha=self.STACK_MAC,
            arp__tpa=self.STACK_IP4.address,
        )
        self._peer_send(self._build_eth(dst=self.STACK_MAC, payload=reply))

    def _ns_to_stack_frame(self) -> bytes:
        """
        Build a unicast Neighbor Solicitation from the peer for the
        stack's IPv6 address, carrying the peer's Source Link-Layer
        Address option so the stack both replies (it owns the target)
        and learns the peer's IPv6 -> MAC binding (RFC 4861 §7.2.3).
        """

        ns = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageNeighborSolicitation(
                target_address=self.STACK_IP6.address,
                options=Icmp6NdOptions(Icmp6NdOptionSlla(slla=self.PEER_MAC)),
            )
        )
        return self._build_eth(
            dst=self.STACK_MAC,
            payload=Ip6Assembler(
                ip6__src=self.PEER_IP6,
                ip6__dst=self.STACK_IP6.address,
                ip6__hop=255,
                ip6__payload=ns,
            ),
        )

    def _prime_peer_neighbor6(self) -> None:
        """
        Populate the stack's Neighbor Cache with the peer's IPv6 -> MAC
        binding by sending a Neighbor Solicitation carrying the peer's
        SLLA option (RFC 4861 §7.2.3 creates a STALE entry for the NS
        source), so a stack-originated IPv6 send toward the peer resolves
        without a round trip.
        """

        self._peer_send(self._ns_to_stack_frame())

    # --- Control-plane helper (the drop-in over the daemon) ----------

    def _client(self) -> ClientStack:
        """
        Connect a drop-in 'ClientStack' to the daemon's control socket,
        closed on cleanup.
        """

        client = connect(socket_path=self._sock_path)
        self.addCleanup(client.close)
        return client
