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
This module contains the 'RealTapRouterTestCase' base class for the
root-gated two-tap router end-to-end suite — the only end-to-end proof
of the 3.0.9 forwarding plane on a real wire. It boots one real daemon
as a router between two persistent taps (each a distinct directly-
connected subnet, IPv4 forwarding + IPv6 forwarding enabled), and opens
one AF_PACKET peer per tap. The test acts as a host on each side and
asserts on the real transit frames the router emits: a datagram sent by
the peer on tap-A toward the peer on tap-B is forwarded out tap-B with
its TTL / Hop Limit decremented, resolving the egress neighbor via a
real ARP / ND exchange.

The suite is skipped unless run as root with 'PYTCP_REAL_TAP=1'; it needs
'CAP_NET_ADMIN' to create the taps and open '/dev/net/tun'.

pytcp/tests/lib/real_tap_router_testcase.py

ver 3.0.10
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
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionTlla,
    IgmpAssembler,
    IgmpMessageV3Report,
    IgmpV3GroupRecord,
    IgmpV3RecordType,
    Ip4OptionRouterAlert,
    Ip4Options,
    IpProto,
)
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.arp.arp__assembler import ArpAssembler
from net_proto.protocols.arp.arp__enums import ArpOperation
from net_proto.protocols.arp.arp__parser import ArpParser
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.icmp6.icmp6__parser import Icmp6Parser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from pytcp.tests.lib.real_tap_testcase import _real_tap_enabled

# AF_PACKET "capture every ethertype" protocol number, and the
# 'sll_pkttype' flag marking a frame the kernel is transmitting (our own
# outgoing copy, which the peer socket must ignore).
_ETH_P_ALL = 0x0003
_PACKET_OUTGOING = 4

# The maximum interface-name length the kernel accepts (IFNAMSIZ - 1).
_IFNAME_MAX = 15


@unittest.skipUnless(_real_tap_enabled(), "real-TAP suite: run as root with PYTCP_REAL_TAP=1 (needs CAP_NET_ADMIN)")
class RealTapRouterTestCase(unittest.TestCase):
    """
    Base class for the two-tap real-TAP router forwarding tests.

    'setUp' creates two persistent taps (tap-A on subnet A, tap-B on
    subnet B), boots one real daemon as a router between them with static
    dual-stack addresses and IPv4 + IPv6 forwarding enabled, waits for
    readiness, and opens one AF_PACKET peer bound to each tap. Tests drive
    a transit datagram in on tap-A and assert on the forwarded frame out
    tap-B. Every resource is torn down via 'addCleanup' so a mid-'setUp'
    failure cannot leak a tap.
    """

    # Router if-A (subnet A) and if-B (subnet B) — two directly-connected
    # subnets, so transit A->B needs no static routes (both are FIB
    # connected routes).
    ROUTER_A_MAC: MacAddress = MacAddress("02:00:00:00:0a:01")
    ROUTER_A_IP4: Ip4IfAddr = Ip4IfAddr("10.77.1.1/24")
    ROUTER_A_IP6: Ip6IfAddr = Ip6IfAddr("fd77:1::1/64")
    ROUTER_B_MAC: MacAddress = MacAddress("02:00:00:00:0b:01")
    ROUTER_B_IP4: Ip4IfAddr = Ip4IfAddr("10.77.2.1/24")
    ROUTER_B_IP6: Ip6IfAddr = Ip6IfAddr("fd77:2::1/64")

    # Peer A on subnet A (source of transit traffic).
    PEER_A_MAC: MacAddress = MacAddress("02:00:00:00:0a:91")
    PEER_A_IP4: Ip4Address = Ip4Address("10.77.1.91")
    PEER_A_IP6: Ip6Address = Ip6Address("fd77:1::91")

    # Peer B on subnet B (destination of transit traffic).
    PEER_B_MAC: MacAddress = MacAddress("02:00:00:00:0b:20")
    PEER_B_IP4: Ip4Address = Ip4Address("10.77.2.20")
    PEER_B_IP6: Ip6Address = Ip6Address("fd77:2::20")

    _tap_a: str
    _tap_b: str
    _sock_path: str
    _ready_path: str
    _daemon: subprocess.Popen[bytes]
    _peer_a: socket.socket
    _peer_b: socket.socket

    @override
    def setUp(self) -> None:
        """
        Create both taps, boot the router daemon, and open the two peers.
        """

        # The daemon accepts only 'tap' / 'tun' name prefixes
        # (_resolve_interface); a shared pid-derived base keeps the two
        # names unique across concurrent runs while both start with 'tap'.
        base = f"tap{os.getpid()}"[: _IFNAME_MAX - 1]
        self._tap_a = f"{base}a"
        self._tap_b = f"{base}b"
        for tap in (self._tap_a, self._tap_b):
            subprocess.run(["ip", "tuntap", "del", "name", tap, "mode", "tap"], check=False)
            subprocess.run(["ip", "tuntap", "add", "name", tap, "mode", "tap"], check=True)
            self.addCleanup(self._delete_tap, tap)
            subprocess.run(["ip", "link", "set", "dev", tap, "up"], check=True)

        tmp_dir = tempfile.mkdtemp(prefix="pytcp-realtap-router-")
        self.addCleanup(shutil.rmtree, tmp_dir, ignore_errors=True)
        self._sock_path = os.path.join(tmp_dir, "daemon.sock")
        self._ready_path = os.path.join(tmp_dir, "daemon.ready")
        self._daemon = self._start_router_daemon()
        self.addCleanup(self._stop_daemon)
        # Two dual-stack interfaces each serialize DAD (link-local ->
        # solicited-node -> static global) at boot; size the wait for it.
        self._wait_ready(timeout=40.0)

        self._peer_a = self._open_peer(self._tap_a)
        self._peer_b = self._open_peer(self._tap_b)

    def _open_peer(self, tap: str, /) -> socket.socket:
        """
        Open a non-blocking AF_PACKET peer bound to 'tap', closed on
        cleanup.
        """

        peer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        self.addCleanup(peer.close)
        peer.bind((tap, 0))
        peer.setblocking(False)
        return peer

    def _start_router_daemon(self) -> "subprocess.Popen[bytes]":
        """
        Boot one real daemon as a router between the two taps: two static
        dual-stack interfaces, IPv4 + IPv6 forwarding enabled, signalling
        readiness via a file. 'run_daemon' cannot express per-interface
        static addresses for a multi-NIC daemon (it autoconfigures every
        NIC), so this drives 'stack.add_interface' directly.
        """

        runner = (
            "import signal, threading\n"
            "from pytcp import stack\n"
            "from pytcp.stack import sysctl\n"
            "from pytcp.ipc.ipc__server import IpcServer\n"
            "from net_addr import Ip4IfAddr, Ip6IfAddr, MacAddress\n"
            "stop = threading.Event()\n"
            "signal.signal(signal.SIGTERM, lambda *_a: stop.set())\n"
            "signal.signal(signal.SIGINT, lambda *_a: stop.set())\n"
            "stack.init()\n"
            f"a = stack.initialize_interface__tap(interface_name={self._tap_a!r}, "
            f"mac_address=MacAddress({str(self.ROUTER_A_MAC)!r}))\n"
            f"stack.add_interface(**a, ip4_host=Ip4IfAddr({str(self.ROUTER_A_IP4)!r}), "
            f"ip6_host=Ip6IfAddr({str(self.ROUTER_A_IP6)!r}))\n"
            f"b = stack.initialize_interface__tap(interface_name={self._tap_b!r}, "
            f"mac_address=MacAddress({str(self.ROUTER_B_MAC)!r}))\n"
            f"stack.add_interface(**b, ip4_host=Ip4IfAddr({str(self.ROUTER_B_IP4)!r}), "
            f"ip6_host=Ip6IfAddr({str(self.ROUTER_B_IP6)!r}))\n"
            "sysctl.set('ip4.ip_forward', True)\n"
            "sysctl.set('ip6.all.forwarding', True)\n"
            # Multicast-router role (IGMP/MLD querier + multicast
            # forwarding) so a transit multicast datagram replicates to
            # interfaces with a learned downstream listener.
            "sysctl.set('igmp.default.mc_forwarding', True)\n"
            "sysctl.set('mld.default.mc_forwarding', True)\n"
            "stack.start(wait_for_dhcp_bind=False)\n"
            "server = IpcServer(socket_path=%r)\n" % self._sock_path + "server.start()\n"
            f"open({self._ready_path!r}, 'w').close()\n"
            "try:\n"
            "    stop.wait()\n"
            "finally:\n"
            "    server.stop()\n"
            "    stack.stop()\n"
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
        Block until the daemon signals readiness, failing if it exits or
        does not come up in time.
        """

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if os.path.exists(self._ready_path):
                return
            if self._daemon.poll() is not None:
                self.fail(f"router daemon exited during boot (rc={self._daemon.returncode})")
            time.sleep(0.05)
        self.fail(f"router daemon did not signal readiness within {timeout}s")

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

    def _delete_tap(self, tap: str, /) -> None:
        """
        Remove a persistent tap (idempotent).
        """

        subprocess.run(["ip", "tuntap", "del", "name", tap, "mode", "tap"], check=False)

    # --- Wire helpers (the test is a host on each side) --------------

    def _send(self, peer: socket.socket, frame: bytes, /) -> None:
        """
        Inject a raw Ethernet frame onto the wire toward the router.
        """

        peer.send(frame)

    def _expect(
        self,
        peer: socket.socket,
        predicate: Callable[[PacketRx], bool],
        /,
        *,
        timeout: float = 3.0,
    ) -> PacketRx:
        """
        Return the first inbound frame on 'peer' (skipping our own
        outgoing copies) whose Ethernet-parsed 'PacketRx' satisfies
        'predicate', failing on timeout. A parse error on a non-matching
        frame is swallowed so unrelated traffic (boot chatter, the other
        subnet's DAD) does not derail the match.
        """

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([peer], [], [], min(0.2, max(0.0, deadline - time.monotonic())))
            if not ready:
                continue
            try:
                data, addr = peer.recvfrom(2048)
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

    def _eth(self, *, src: MacAddress, dst: MacAddress, payload: ArpAssembler | Ip4Assembler | Ip6Assembler) -> bytes:
        """
        Assemble an Ethernet frame from 'src' to 'dst' carrying an
        ARP / IPv4 / IPv6 'payload'.
        """

        eth = EthernetAssembler(ethernet__src=src, ethernet__dst=dst, ethernet__payload=payload)
        buffers: list[Buffer] = []
        eth.assemble(buffers)
        return b"".join(bytes(buffer) for buffer in buffers)

    def _answer_arp_request(
        self,
        peer: socket.socket,
        /,
        *,
        target_ip4: Ip4Address,
        answer_mac: MacAddress,
        timeout: float = 5.0,
    ) -> None:
        """
        Wait for the router to ARP-request 'target_ip4' on 'peer' and
        answer it with 'answer_mac', so the router's egress next-hop
        resolves and it flushes the queued transit datagram.
        """

        def _is_request(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.ARP:
                return False
            ArpParser(packet_rx)
            return packet_rx.arp.oper is ArpOperation.REQUEST and packet_rx.arp.tpa == target_ip4

        request = self._expect(peer, _is_request, timeout=timeout)
        reply = ArpAssembler(
            arp__oper=ArpOperation.REPLY,
            arp__sha=answer_mac,
            arp__spa=target_ip4,
            arp__tha=request.arp.sha,
            arp__tpa=request.arp.spa,
        )
        self._send(peer, self._eth(src=answer_mac, dst=request.arp.sha, payload=reply))

    def _answer_nd_solicitation(
        self,
        peer: socket.socket,
        /,
        *,
        target_ip6: Ip6Address,
        answer_mac: MacAddress,
        router_mac: MacAddress,
        timeout: float = 5.0,
    ) -> None:
        """
        Wait for the router to Neighbor-Solicit 'target_ip6' on 'peer'
        and answer it with a solicited Neighbor Advertisement carrying the
        Target Link-Layer Address 'answer_mac', so the router's IPv6
        egress next-hop resolves and it flushes the queued transit
        datagram.
        """

        def _is_solicitation(packet_rx: PacketRx) -> bool:
            if packet_rx.ethernet.type is not EtherType.IP6:
                return False
            Ip6Parser(packet_rx)
            if packet_rx.ip6.next is not IpProto.ICMP6:
                return False
            Icmp6Parser(packet_rx)
            message = packet_rx.icmp6.message
            return isinstance(message, Icmp6NdMessageNeighborSolicitation) and message.target_address == target_ip6

        solicitation = self._expect(peer, _is_solicitation, timeout=timeout)
        advertisement = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageNeighborAdvertisement(
                flag_s=True,
                flag_o=True,
                target_address=target_ip6,
                options=Icmp6NdOptions(Icmp6NdOptionTlla(tlla=answer_mac)),
            )
        )
        # Unicast the solicited NA straight back to the NS source (the
        # router's interface address / MAC) so it always reaches the
        # router's Neighbor Cache.
        self._send(
            peer,
            self._eth(
                src=answer_mac,
                dst=router_mac,
                payload=Ip6Assembler(
                    ip6__src=target_ip6,
                    ip6__dst=solicitation.ip6.src,
                    ip6__hop=255,
                    ip6__payload=advertisement,
                ),
            ),
        )

    def _igmp_v3_join_frame(self, *, group: Ip4Address, src_ip4: Ip4Address, src_mac: MacAddress) -> bytes:
        """
        Build an IGMPv3 Membership Report joining 'group' in EXCLUDE{}
        (any-source) mode — carried in Ethernet/IPv4 to the
        all-IGMPv3-routers group 224.0.0.22 with the Router Alert option
        and TTL 1 — so the router's querier learns a downstream listener
        for 'group' on the ingress interface.
        """

        report = IgmpAssembler(
            igmp__message=IgmpMessageV3Report(
                records=[IgmpV3GroupRecord(type=IgmpV3RecordType.MODE_IS_EXCLUDE, multicast_address=group)],
            )
        )
        all_igmpv3_routers = Ip4Address("224.0.0.22")
        return self._eth(
            src=src_mac,
            dst=all_igmpv3_routers.multicast_mac,
            payload=Ip4Assembler(
                ip4__src=src_ip4,
                ip4__dst=all_igmpv3_routers,
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=report,
            ),
        )
