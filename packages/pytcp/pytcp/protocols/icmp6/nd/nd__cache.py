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
This module contains the IPv6 Neighbor Discovery cache — a
thin adapter on top of the generic
'NeighborCache[A, P]' NUD state machine at
'pytcp/lib/neighbor.py'. Phase 3 of the NUD migration plan
('docs/refactor/nud_state_machine.md') and the mirror of the
IPv4 ARP cache adapter shipped in Phase 2.

The adapter supplies the IPv6-specific solicit callback —
ICMPv6 Neighbor Solicitation — and inherits everything else
(state machine, timers, queued-packet semantics, PERMANENT
escape hatch, sysctl-driven knobs) from the parent class.

pytcp/protocols/icmp6/nd/nd__cache.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, override

from net_addr import Ip6Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp.lib.neighbor import NeighborCache

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


class NdCache(NeighborCache[Ip6Address, EthernetAssembler]):
    """
    The IPv6 Neighbor Discovery cache. Inherits the full NUD
    state machine from 'NeighborCache[Ip6Address, EthernetAssembler]' and supplies
    the wire-level solicit callback (ICMPv6 Neighbor Solicitation
    via 'PacketHandler.send_icmp6_neighbor_solicitation'). The
    public surface is overridden with kw-only wrappers
    ('ip6_address=', 'mac_address=') that match the established
    PyTCP convention.

    Queued-packet semantics mirror the IPv4 ArpCache:
    'enqueue_pending' parks the EthernetAssembler that
    couldn't resolve, '_flush_packet' re-emits it through the
    TX ring once an inbound Neighbor Advertisement resolves
    the destination MAC (RFC 1122 §2.3.2.2; the IPv6
    equivalent of the ARP unresolved-queue behaviour).
    """

    # Owning interface handler — injected after construction by
    # 'stack.init()' (the cache <-> handler link is bidirectional).
    # The solicit / flush callbacks route through this handler
    # rather than the global 'stack.packet_handler' / 'stack.tx_ring'
    # shims, so the cache stays bound to exactly one interface (the
    # Linux per-ifindex ND model). ND runs on both L2 and L3.
    # Class-level 'None' default (rather than an '__init__'
    # assignment) so 'create_autospec' exposes the attribute as
    # settable for the test harness.
    _owner: "PacketHandlerL2 | PacketHandlerL3 | None" = None

    @override
    def __init__(self) -> None:
        """
        Initialise the ND cache. The Subsystem name is "ICMPv6
        ND Cache" (legacy log channel "nd-c"); the parent class
        wires the FSM machinery + sysctl-driven timers.
        """

        super().__init__(
            name="ICMPv6 ND Cache",
            solicit_callback=self._solicit_ns,
            flush_callback=self._flush_packet,
        )

    def attach_owner(self, owner: "PacketHandlerL2 | PacketHandlerL3", /, *, iface_name: str | None) -> None:
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
    # Public API — kw-only methods preserve the established ND
    # call-site convention. They delegate to the protected
    # 'NeighborCache._*' hooks rather than overriding a public
    # parent surface, so there is no Liskov violation to ignore.
    # ------------------------------------------------------------

    def find_entry(self, *, ip6_address: Ip6Address) -> MacAddress | None:
        """
        Look up the MAC for an IPv6 address; on miss, fire a
        multicast Neighbor Solicitation and return None.
        """

        return self._find_entry(ip6_address)

    def add_entry(
        self,
        *,
        ip6_address: Ip6Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Install / refresh the IPv6-MAC mapping in response to
        an inbound Neighbor Advertisement. Transitions the
        entry to NUD_REACHABLE.
        """

        self._add_entry(ip6_address, mac_address)

    def add_permanent_entry(
        self,
        *,
        ip6_address: Ip6Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Install a PERMANENT static-neighbour entry. Dynamic ND
        learning never overrides PERMANENT entries.
        """

        self._add_permanent_entry(ip6_address, mac_address)

    def confirm_reachability(self, *, ip6_address: Ip6Address) -> None:
        """
        Upper-layer fastpath: promote a STALE / DELAY / PROBE
        entry directly to REACHABLE without firing a unicast
        NS probe. Called by the TCP layer on in-window ACK.
        """

        self._confirm_reachability(ip6_address)

    def enqueue_pending(
        self,
        *,
        ip6_address: Ip6Address,
        ethernet_packet_tx: EthernetAssembler,
    ) -> None:
        """
        Save the most recently dropped outbound Ethernet
        packet for an unresolved IPv6 address so the FSM can
        deliver it post-resolution (RFC 1122 §2.3.2.2 — the
        IPv6 equivalent of the IPv4 ARP unresolved-queue
        SHOULD).
        """

        self._enqueue_pending(ip6_address, ethernet_packet_tx)

    # ------------------------------------------------------------
    # Protocol-specific callbacks consumed by NeighborCache.
    # ------------------------------------------------------------

    def _solicit_ns(
        self,
        ip6_address: Ip6Address,
        cached_mac: MacAddress | None,
    ) -> None:
        """
        Fire an ICMPv6 Neighbor Solicitation — multicast for
        INCOMPLETE state (cached_mac is None; ip6__dst is the
        solicited-node multicast group) or unicast for PROBE
        state (cached_mac is non-None; ip6__dst is the target
        address itself, with the cached MAC resolving at the
        Ethernet TX layer). The unicast form is the IPv6
        analogue of RFC 1122 §2.3.2.1 IMPL (2)'s unicast ARP
        cache-refresh probe — saves segment-wide multicast
        bandwidth on entries the cache already has.

        Routes through the owning interface handler.
        """

        assert self._owner is not None, "ND cache must be bound to an interface handler before soliciting."
        if cached_mac is None:
            self._owner.send_icmp6_neighbor_solicitation(
                icmp6_ns_target_address=ip6_address,
            )
        else:
            self._owner.send_icmp6_neighbor_solicitation_unicast(
                icmp6_ns_target_address=ip6_address,
            )

    def _flush_packet(self, packet: EthernetAssembler, mac_address: MacAddress) -> None:
        """
        Dispatch a queued Ethernet packet through the owning
        interface's TX ring with the destination MAC rewritten to
        the resolved value. The packet type is bound by the
        'NeighborCache[Ip6Address, EthernetAssembler]'
        subscription on the class header.
        """

        assert self._owner is not None, "ND cache must be bound to an interface handler before flushing."
        assert self._owner.tx_ring is not None, "Owning interface handler must have a TX ring to flush."
        packet.dst = mac_address
        # Phase 4: this direct enqueue becomes a ring-handoff TX
        # request once the per-interface TX worker owns the
        # send-out pipeline.
        self._owner.tx_ring.enqueue(packet)
