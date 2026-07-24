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
This module contains the RFC 5227 IPv4 Address Conflict Detection
engine ('Ip4Acd') — the userspace ACD actor that runs probe and
announce over an AF_PACKET raw link socket, exactly as Linux's
'sd-ipv4acd' / 'n-acd' do. The Linux kernel performs no IPv4 ACD; the
client owns both the mechanism (sending ARP, reading ARP for
conflicts) and the policy (when to probe / announce / yield).

pytcp/protocols/ip4/acd/ip4_acd.py

ver 3.0.9
"""

import random
import time
from dataclasses import dataclass

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import (
    ArpAssembler,
    ArpOperation,
    ArpParser,
    EthernetAssembler,
    EthernetParser,
    EtherType,
    PacketRx,
    PacketValidationError,
)
from pytcp.lib.logger import log
from pytcp.protocols.arp import arp__constants
from pytcp.runtime.socket import ETH_P_ARP, SOCK_RAW, AddressFamily, socket
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

# Inter-poll tick for the conflict watcher: how often the probe loop
# re-checks the ARP socket while waiting out a timing window. Small
# relative to the RFC 5227 sub-second timers, large enough not to spin.
_CONFLICT_POLL_TICK__SEC: float = 0.05

_BROADCAST_MAC = MacAddress(0xFFFFFFFFFFFF)


@dataclass(frozen=True, kw_only=True, slots=True)
class AcdResult:
    """
    Outcome of an 'Ip4Acd.probe' run. 'success=True' means the
    RFC 5227 §2.1.1 Probe sequence completed with no observed
    conflict; the address is safe to claim. 'success=False' means a
    conflicting ARP was seen during the probe window; 'conflict_mac'
    is the offending peer's hardware address.
    """

    success: bool
    address: Ip4Address
    conflict_mac: MacAddress | None = None


class Ip4Acd:
    """
    RFC 5227 IPv4 Address Conflict Detection engine over an AF_PACKET
    raw link socket — the PyTCP equivalent of 'sd-ipv4acd'.

    A consumer (the DHCPv4 client, the RFC 3927 link-local client)
    builds one bound to its interface's MAC + ifindex, then calls
    'probe()' before claiming an address and 'announce()' after. The
    engine opens an ethertype-ARP packet socket scoped to the ifindex,
    sends Probes / Announcements, and reads ARP off that socket to
    detect conflicts — the stack's own ARP RX path is uninvolved (the
    socket is a parallel tap, exactly as Linux's ACD library reads ARP
    independently of the kernel's ARP processing).

    The same raw-link-socket machinery serves the DHCPv4 client's
    RFC 4436 DNAv4 reachability probe ('probe_reachable') — a unicast
    ARP to the cached gateway on INIT-REBOOT — so the client never has
    to reach into the stack's ARP cache or ARP-TX path for it.

    The RFC 5227 timing constants are the live 'arp.*' sysctls, read
    through 'arp__constants' qualified access so an operator override
    takes effect on the next run.
    """

    def __init__(self, *, mac_address: MacAddress, ifindex: int) -> None:
        """
        Build an ACD engine bound to one interface's MAC and ifindex.
        """

        self._mac = mac_address
        self._ifindex = ifindex
        # Long-lived defense socket + the address it is monitoring,
        # held open between 'claim' and 'release' so RFC 5227 §2.4
        # ongoing conflict detection reads ARP off the same socket the
        # probe / announce used (the Linux one-socket lifecycle). None
        # when no address is currently claimed for defense.
        self._sock: socket | None = None
        self._claimed: Ip4Address | None = None

    def probe(self, *, address: Ip4Address) -> AcdResult:
        """
        Run the RFC 5227 §2.1.1 ARP Probe sequence for 'address':
        an initial 0..PROBE_WAIT random delay, PROBE_NUM Probes spaced
        PROBE_MIN..PROBE_MAX apart, then an ANNOUNCE_WAIT quiet period —
        watching the ARP socket for a conflict throughout. Returns an
        'AcdResult'; blocks for the full window (~5-9 s with the default
        sysctls) unless a conflict is seen first.
        """

        sock = self._open_socket()
        try:
            return self._run_probe(sock, address)
        finally:
            sock.close()

    def announce(self, *, address: Ip4Address) -> None:
        """
        Emit the RFC 5227 §2.3 ANNOUNCE_NUM gratuitous-ARP burst for
        'address' (spaced ANNOUNCE_INTERVAL apart) so peers refresh any
        stale cache entry from a previous holder. Blocks for
        (ANNOUNCE_NUM - 1) * ANNOUNCE_INTERVAL seconds.
        """

        sock = self._open_socket()
        try:
            self._run_announce(sock, address)
        finally:
            sock.close()

    def claim(self, *, address: Ip4Address) -> AcdResult:
        """
        Claim 'address' for ongoing defense: run the RFC 5227 §2.1.1
        Probe and, on a clean probe, the §2.3 Announcement, then KEEP
        the socket open so 'poll_conflict' / 'defend' can guard the
        address over its lifetime (the Linux one-socket ACD flow). On a
        clean claim the engine holds the socket (call 'release' to drop
        it); on conflict the socket is closed and the conflicting peer
        MAC is reported.
        """

        sock = self._open_socket()
        result = self._run_probe(sock, address)
        if not result.success:
            sock.close()
            return result
        self._run_announce(sock, address)
        self._sock = sock
        self._claimed = address
        return result

    def start_defense(self, *, address: Ip4Address) -> None:
        """
        Begin RFC 5227 §2.4 ongoing defense of an address the caller has
        already probed clean elsewhere: open the defense socket, emit the
        §2.3 Announcement, and hold the socket so 'poll_conflict' /
        'defend' can guard the address over its lifetime. This is 'claim'
        without the probe — the entry point for a client whose §2.1.1
        Probe and commit-to-use are separated by a wire exchange (the
        DHCPv4 client probes the offered address on the ACK, then begins
        defense only once the lease is committed). Call 'release' to drop
        the claim.
        """

        sock = self._open_socket()
        self._run_announce(sock, address)
        self._sock = sock
        self._claimed = address

    def probe_reachable(
        self,
        *,
        target: Ip4Address,
        target_mac: MacAddress,
        sender: Ip4Address,
        timeout: float,
    ) -> bool:
        """
        RFC 4436 DNAv4 unicast reachability probe over the same raw link
        socket the ACD probe uses. Sends a unicast ARP Request for
        'target' (the previously-cached default gateway, addressed to
        'target_mac') with 'sender' as the candidate sender protocol
        address (RFC 4436 §4.3), then watches the socket for up to
        'timeout' seconds and returns True the moment 'target' answers
        with an ARP Reply from the same IPv4 + MAC — proving the host is
        back on the same L2 segment behind the same gateway, so the
        cached lease can be adopted without a DHCP exchange. Returns
        False on timeout. The stack's ARP RX path is uninvolved.
        """

        sock = self._open_socket()
        try:
            self._send(sock, oper=ArpOperation.REQUEST, spa=sender, tpa=target, dst_mac=target_mac)
            __debug__ and log("stack", f"<lg>DNAv4</>: unicast ARP probe to {target} @ {target_mac}")
            deadline = time.monotonic() + timeout
            while True:
                try:
                    frame, _ = sock.recvfrom()
                except BlockingIOError, TimeoutError:
                    if time.monotonic() >= deadline:
                        return False
                    time.sleep(_CONFLICT_POLL_TICK__SEC)
                    continue
                arp = self._parse_arp(frame)
                if arp is not None and self._is_gateway_reply(arp, target, target_mac):
                    __debug__ and log("stack", f"<lg>DNAv4</>: gateway {target} answered; on-link")
                    return True
        finally:
            sock.close()

    @staticmethod
    def _is_gateway_reply(arp: ArpParser, target: Ip4Address, target_mac: MacAddress, /) -> bool:
        """
        Decide whether an inbound ARP frame is the cached gateway's
        answer to a DNAv4 probe: an ARP Reply whose sender is the gateway
        on both the IPv4 (sender protocol address) and MAC (sender
        hardware address) — confirming the same physical device.
        """

        return arp.oper is ArpOperation.REPLY and arp.spa == target and arp.sha == target_mac

    def poll_conflict(self) -> MacAddress | None:
        """
        Non-blocking RFC 5227 §2.4 ongoing-conflict check on the claimed
        address: drain any ARP queued on the defense socket and return
        the first peer MAC that is using the address (sender protocol
        address == ours, from another MAC), or 'None' if none is
        pending. Requires an active claim ('claim' succeeded, no
        'release' since).
        """

        assert self._sock is not None and self._claimed is not None, "poll_conflict requires an active claim"
        while True:
            try:
                frame, _ = self._sock.recvfrom()
            except BlockingIOError, TimeoutError:
                return None
            arp = self._parse_arp(frame)
            if arp is not None and self._is_ongoing_conflict(arp, self._claimed):
                __debug__ and log("stack", f"<lg>ACD</>: ongoing conflict for {self._claimed} from {arp.sha}")
                return arp.sha

    def defend(self) -> None:
        """
        Broadcast a single defensive gratuitous ARP for the claimed
        address (RFC 5227 §2.4(b)) — an ARP Reply with sender = target =
        the claimed address — so a conflicting peer refreshes its cache
        to our MAC. Requires an active claim.
        """

        assert self._sock is not None and self._claimed is not None, "defend requires an active claim"
        self._send(self._sock, oper=ArpOperation.REPLY, spa=self._claimed, tpa=self._claimed)
        __debug__ and log("stack", f"<lg>ACD</>: defended {self._claimed}")

    def release(self) -> None:
        """
        Drop the claim: close the defense socket and forget the
        monitored address. Idempotent — safe to call when nothing is
        claimed.
        """

        if self._sock is not None:
            self._sock.close()
            self._sock = None
        self._claimed = None

    def _open_socket(self) -> socket:
        """
        Open a non-blocking AF_PACKET (SOCK_RAW) socket scoped to this
        interface's ifindex and filtered to the ARP ethertype.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW, protocol=ETH_P_ARP)
        sock.bind(SockAddrLl(ifindex=self._ifindex, ethertype=ETH_P_ARP))
        sock.setblocking(False)
        return sock

    def _run_probe(self, sock: socket, address: Ip4Address, /) -> AcdResult:
        """
        Probe loop over an already-open socket (the testable core of
        'probe'). Returns clean as soon as the full window elapses with
        no conflict, or conflict the moment one is observed.
        """

        # RFC 5227 §2.1.1 PROBE_WAIT — initial 0..PROBE_WAIT random delay
        # so a fleet powered on together does not probe in lockstep.
        if (
            mac := self._watch_for_conflict(sock, address, random.uniform(0, arp__constants.ARP__PROBE_WAIT))
        ) is not None:
            return AcdResult(success=False, address=address, conflict_mac=mac)

        # RFC 5227 §2.1.1 — PROBE_NUM Probes spaced PROBE_MIN..PROBE_MAX.
        for _ in range(arp__constants.ARP__PROBE_NUM):
            self._send(sock, oper=ArpOperation.REQUEST, spa=Ip4Address(), tpa=address)
            __debug__ and log("stack", f"<lg>ACD</>: sent ARP Probe for {address}")
            spacing = random.uniform(arp__constants.ARP__PROBE_MIN, arp__constants.ARP__PROBE_MAX)
            if (mac := self._watch_for_conflict(sock, address, spacing)) is not None:
                return AcdResult(success=False, address=address, conflict_mac=mac)

        # RFC 5227 §2.1.1 ANNOUNCE_WAIT — post-probe quiet period; a late
        # conflicting ARP can still flag the candidate here.
        if (mac := self._watch_for_conflict(sock, address, arp__constants.ARP__ANNOUNCE_WAIT)) is not None:
            return AcdResult(success=False, address=address, conflict_mac=mac)

        return AcdResult(success=True, address=address)

    def _run_announce(self, sock: socket, address: Ip4Address, /) -> None:
        """
        Announce burst over an already-open socket (the testable core of
        'announce').
        """

        for announce_idx in range(arp__constants.ARP__ANNOUNCE_NUM):
            if announce_idx > 0:
                time.sleep(arp__constants.ARP__ANNOUNCE_INTERVAL)
            self._send(sock, oper=ArpOperation.REQUEST, spa=address, tpa=address)
            __debug__ and log("stack", f"<lg>ACD</>: sent ARP Announcement for {address}")

    def _send(
        self,
        sock: socket,
        /,
        *,
        oper: ArpOperation,
        spa: Ip4Address,
        tpa: Ip4Address,
        dst_mac: MacAddress | None = None,
    ) -> None:
        """
        Build and transmit one ARP frame out the socket. Probe /
        Announcement / defensive frames broadcast (the default); a DNAv4
        reachability probe passes 'dst_mac' to unicast directly to the
        cached gateway. Probe: oper=REQUEST, spa=0.0.0.0. Announcement:
        oper=REQUEST, spa=tpa=address.
        """

        frame = bytes(
            EthernetAssembler(
                ethernet__src=self._mac,
                ethernet__dst=dst_mac if dst_mac is not None else _BROADCAST_MAC,
                ethernet__payload=ArpAssembler(
                    arp__oper=oper,
                    arp__sha=self._mac,
                    arp__spa=spa,
                    arp__tha=MacAddress(),
                    arp__tpa=tpa,
                ),
            )
        )
        sock.sendto(frame, SockAddrLl(ifindex=self._ifindex, ethertype=ETH_P_ARP))

    def _watch_for_conflict(self, sock: socket, address: Ip4Address, duration: float, /) -> MacAddress | None:
        """
        Read ARP off the socket for up to 'duration' seconds, returning
        the offending peer MAC the moment a conflict for 'address' is
        observed, or 'None' if the window elapses cleanly. Drains any
        already-queued frames before honouring the deadline, so a
        conflict captured during a prior window is still caught when
        'duration' is short.
        """

        deadline = time.monotonic() + duration
        while True:
            try:
                frame, _ = sock.recvfrom()
            except BlockingIOError, TimeoutError:
                if time.monotonic() >= deadline:
                    return None
                time.sleep(_CONFLICT_POLL_TICK__SEC)
                continue
            arp = self._parse_arp(frame)
            if arp is not None and self._is_conflict(arp, address):
                __debug__ and log("stack", f"<lg>ACD</>: conflict for {address} from {arp.sha}")
                return arp.sha

    def _parse_arp(self, frame: Buffer, /) -> ArpParser | None:
        """
        Parse a captured link-layer frame into its ARP header, or return
        'None' if it is not a well-formed Ethernet/ARP frame.
        """

        try:
            packet_rx = PacketRx(frame)
            EthernetParser(packet_rx)
            if packet_rx.ethernet.type is not EtherType.ARP:
                return None
            ArpParser(packet_rx)
        except PacketValidationError:
            return None
        return packet_rx.arp

    def _is_conflict(self, arp: ArpParser, address: Ip4Address, /) -> bool:
        """
        Decide whether an inbound ARP frame conflicts with our claim on
        'address' (RFC 5227 §2.1.1): a peer using the address (sender
        protocol address == ours) or a peer probing it simultaneously
        (sender == 0.0.0.0, target == ours). Frames from our own MAC are
        never conflicts.
        """

        if arp.sha == self._mac:
            return False
        if arp.spa == address:
            return True
        return bool(arp.spa.is_unspecified and arp.tpa == address)

    def _is_ongoing_conflict(self, arp: ArpParser, address: Ip4Address, /) -> bool:
        """
        Decide whether an inbound ARP conflicts with a CLAIMED address
        (RFC 5227 §2.4): a peer actively using the address — its sender
        protocol address equals ours, from a different MAC. Unlike
        '_is_conflict', a bare Probe (sender 0.0.0.0) for the address is
        not an ongoing conflict here: the stack's ARP RX path answers
        such Probes for an owned address, which makes the prober back
        off.
        """

        return arp.sha != self._mac and arp.spa == address
