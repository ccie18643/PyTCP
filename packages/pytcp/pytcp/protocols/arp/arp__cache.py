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
This module contains the IPv4 ARP cache — a thin adapter on
top of the generic 'NeighborCache[A, P]' NUD state machine at
'pytcp/lib/neighbor.py'. Phase 2 of the NUD migration plan
('docs/refactor/nud_state_machine.md').

The adapter supplies the IPv4-specific solicit and flush
callbacks: broadcast or unicast ARP Request for solicits
(driven by 'cached_mac is None / not None'), Ethernet TX
ring dispatch with destination-MAC rewrite for flushes.

pytcp/protocols/arp/arp__cache.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp.lib.neighbor import NeighborCache
from pytcp.runtime.packet_handler_api import ArpCacheOwner


class ArpCache(NeighborCache[Ip4Address, EthernetAssembler]):
    """
    The IPv4 ARP cache. Inherits the full NUD state machine
    from 'NeighborCache[Ip4Address, EthernetAssembler]' and supplies the wire-
    level callbacks ('_solicit_arp', '_flush_packet'). The
    public surface ('find_entry', 'add_entry',
    'enqueue_pending', 'add_permanent_entry',
    'confirm_reachability') is overridden with kw-only
    wrappers that match the established PyTCP convention
    ('ip4_address=', 'mac_address=', 'ethernet_packet_tx=').
    """

    # Owning interface handler — injected after construction by
    # 'stack.init()' (the cache <-> handler link is bidirectional).
    # The solicit / flush callbacks route through this handler
    # rather than the global 'stack.packet_handler' / 'stack.tx_ring'
    # shims, so the cache stays bound to exactly one interface (the
    # Linux per-ifindex ARP model). Class-level 'None' default
    # (rather than an '__init__' assignment) so 'create_autospec'
    # exposes the attribute as settable for the test harness.
    _owner: ArpCacheOwner | None = None

    @override
    def __init__(self) -> None:
        """
        Initialise the ARP cache. The Subsystem name is "ARP
        Cache" (legacy log channel "arp-c"); the parent class
        wires the FSM machinery + sysctl-driven timers.
        """

        super().__init__(
            name="ARP Cache",
            solicit_callback=self._solicit_arp,
            flush_callback=self._flush_packet,
        )

    def attach_owner(self, owner: ArpCacheOwner, /, *, iface_name: str | None) -> None:
        """
        Bind this cache to its owning interface handler (the
        bidirectional cache <-> handler link) and record the interface
        name for the 'neighbor.<ifname>.*' sysctl namespace. Called by
        the stack lifecycle at construction time; the solicit / flush
        callbacks route through 'owner'.
        """

        self._owner = owner
        self._iface_name = iface_name

    # ------------------------------------------------------------
    # Public API — kw-only methods preserve the established ARP
    # call-site convention. They delegate to the protected
    # 'NeighborCache._*' hooks rather than overriding a public
    # parent surface, so there is no Liskov violation to ignore.
    # ------------------------------------------------------------

    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None:
        """
        Look up the MAC for an IPv4 address; on miss, fire a
        broadcast ARP Request and return None. See
        'NeighborCache._find_entry' for full FSM semantics.
        """

        return self._find_entry(ip4_address)

    def add_entry(
        self,
        *,
        ip4_address: Ip4Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Install / refresh the IPv4-MAC mapping in response to
        an inbound ARP Reply. Transitions the entry to
        NUD_REACHABLE; flushes any queued packet.
        """

        self._add_entry(ip4_address, mac_address)

    def add_permanent_entry(
        self,
        *,
        ip4_address: Ip4Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Install a PERMANENT static-neighbour entry. Dynamic
        ARP learning never overrides PERMANENT entries.
        """

        self._add_permanent_entry(ip4_address, mac_address)

    def confirm_reachability(self, *, ip4_address: Ip4Address) -> None:
        """
        Upper-layer fastpath: promote a STALE / DELAY / PROBE
        entry directly to REACHABLE without firing a unicast
        ARP probe. Called by the TCP layer on in-window ACK.
        """

        self._confirm_reachability(ip4_address)

    def enqueue_pending(
        self,
        *,
        ip4_address: Ip4Address,
        ethernet_packet_tx: EthernetAssembler,
    ) -> None:
        """
        Save the most recently dropped outbound Ethernet
        packet for an unresolved IPv4 address so the FSM can
        deliver it post-resolution (RFC 1122 §2.3.2.2).
        """

        self._enqueue_pending(ip4_address, ethernet_packet_tx)

    # ------------------------------------------------------------
    # Protocol-specific callbacks consumed by NeighborCache.
    # ------------------------------------------------------------

    def _solicit_arp(
        self,
        ip4_address: Ip4Address,
        cached_mac: MacAddress | None,
    ) -> None:
        """
        Fire an ARP Request — broadcast for INCOMPLETE state
        (cached_mac is None), unicast to the cached MAC for
        PROBE state (RFC 1122 §2.3.2.1 IMPL (2)). Routes
        through the owning interface handler.
        """

        assert self._owner is not None, "ARP cache must be bound to an interface handler before soliciting."
        if cached_mac is None:
            self._owner.send_arp_request(arp__tpa=ip4_address)
        else:
            self._owner.send_arp_unicast_request(
                arp__tpa=ip4_address,
                ethernet__dst=cached_mac,
            )

    def _flush_packet(self, packet: EthernetAssembler, mac_address: MacAddress) -> None:
        """
        Dispatch a queued Ethernet packet through the owning
        interface's TX ring with the destination MAC rewritten to
        the resolved value. The packet type is bound by the
        'NeighborCache[Ip4Address, EthernetAssembler]'
        subscription on the class header.
        """

        assert self._owner is not None, "ARP cache must be bound to an interface handler before flushing."
        assert self._owner.tx_ring is not None, "Owning interface handler must have a TX ring to flush."
        packet.dst = mac_address
        # AF_PACKET egress tap: the flush bypasses '__send_out_packet'
        # (it enqueues to the TX ring directly), so re-invoke the tap here
        # or a queued-then-flushed frame — e.g. a TCP SYN-ACK to an
        # unresolved peer — would never be observed on egress (Linux
        # 'dev_queue_xmit_nit' taps neighbor-queued frames too).
        self._owner.deliver_tx_to_packet_sockets(packet)
        # Phase 4: this direct enqueue becomes a ring-handoff TX
        # request once the per-interface TX worker owns the
        # send-out pipeline.
        self._owner.tx_ring.enqueue(packet)
