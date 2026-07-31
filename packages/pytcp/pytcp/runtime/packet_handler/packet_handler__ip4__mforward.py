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
This module contains the IPv4 multicast forwarding (replication)
sub-handler for one interface — the last-hop multicast-router data
plane (Phase-2 M5f). A transit multicast datagram that passes the RPF
check is replicated out every interface whose IGMP querier table has a
downstream listener for the group.

pytcp/runtime/packet_handler/packet_handler__ip4__mforward.py

ver 3.0.9
"""

import struct
from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import EtherType, PacketRx, RawAssembler, inet_cksum
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import Ip4MulticastFilterMode
from pytcp.lib.logger import log
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler
    from pytcp.runtime.packet_handler.packet_handler__igmp__tx import (
        IgmpQuerierMembership,
    )

# IPv4 header field byte offsets rewritten on forward — TTL at byte 8,
# Header Checksum at bytes 10-11 (RFC 791 §3.1).
IP4__MFORWARD__TTL_OFFSET = 8
IP4__MFORWARD__CKSUM_OFFSET = 10

# The IPv4 link-local multicast control block 224.0.0.0/24 (RFC 5771) —
# link-scoped control traffic (IGMP, routing protocols) a router never
# forwards, matching the TTL-1 scoping of RFC 1112 §6.1.
IP4__LINK_LOCAL_MULTICAST__MASK = 0xFF_FF_FF_00
IP4__LINK_LOCAL_MULTICAST__BASE = 0xE0_00_00_00


class Ip4MulticastForwardHandler:
    """
    The IPv4 multicast forwarding (replication) sub-handler for one
    interface.
    """

    _if: "PacketHandler"

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Initialize the IPv4 multicast forward sub-handler.
        """

        self._if = interface

    def _mforwarding_enabled(self) -> bool:
        """
        Return whether this interface is a multicast router
        ('igmp.mc_forwarding'), the same switch that activates the IGMP
        querier.
        """

        return bool(sysctl_iface.get_for_iface("igmp.mc_forwarding", self._if._interface_name))

    def try_mforward_ip4(self, packet_rx: PacketRx, /) -> None:
        """
        Replicate a transit IPv4 multicast datagram out every interface
        with a downstream listener for the group, or drop it via one of
        the '*__drop' counters. Consumes the datagram in every branch.

        Reference: RFC 1812 §5.2.4 (multicast forwarding — last hop).
        """

        ip4 = packet_rx.ip4
        group = ip4.dst
        src = ip4.src

        # 1. Multicast forwarding must be enabled on the ingress
        #    interface. Host parity: an interface that is not a
        #    multicast router drops a group it has not joined, counted
        #    in 'ip4__dst_unknown__drop' exactly like the unicast
        #    host-mode stub (no separate 'mforward_disabled' counter).
        if not self._mforwarding_enabled():
            self._if._packet_stats_rx.ip4__dst_unknown__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - Multicast {group} not joined; forwarding disabled, dropping",
            )
            return

        # 2. Scope: the 224.0.0.0/24 link-local control block and any
        #    TTL-1 datagram are link-scoped and never forwarded
        #    (RFC 5771 / RFC 1112 §6.1).
        if (int(group) & IP4__LINK_LOCAL_MULTICAST__MASK == IP4__LINK_LOCAL_MULTICAST__BASE) or ip4.ttl <= 1:
            self._if._packet_stats_rx.ip4__mforward_scope__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - Link-scoped multicast {group} (ttl={ip4.ttl}) not forwarded, dropping",
            )
            return

        # 3. RPF check: accept the datagram for forwarding only if it
        #    arrived on the interface the unicast FIB would use to reach
        #    its source (Reverse Path Forwarding — the standard
        #    multicast loop-prevention check).
        resolution = stack.forward_next_hop_ip4(src)
        if resolution is None or resolution[0].ifindex != self._if.ifindex:
            self._if._packet_stats_rx.ip4__mforward_rpf__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>RPF check failed for multicast source {src}, dropping</>",
            )
            return

        # 4. Compute the egress interfaces with a downstream listener for
        #    (src, group) from each interface's IGMP querier membership
        #    table (populated by M5b). No listeners -> nothing to do.
        oifs = self._egress_interfaces(group, src)
        if not oifs:
            self._if._packet_stats_rx.ip4__mforward_no_listeners__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - No downstream listener for multicast {group}, dropping",
            )
            return

        # 5. Replicate: decrement the TTL, recompute the header checksum
        #    over the IHL-bounded header (RFC 791 §3.1), and re-emit the
        #    byte-identical datagram out each egress toward the group's
        #    Ethernet multicast MAC (RFC 1112 §6.4). No ARP is needed for
        #    a multicast destination.
        datagram = bytearray(ip4.packet_bytes)
        datagram[IP4__MFORWARD__TTL_OFFSET] -= 1
        datagram[IP4__MFORWARD__CKSUM_OFFSET] = datagram[IP4__MFORWARD__CKSUM_OFFSET + 1] = 0
        struct.pack_into(
            "!H",
            datagram,
            IP4__MFORWARD__CKSUM_OFFSET,
            inet_cksum(memoryview(datagram)[: ip4.hlen]),
        )
        payload = bytes(datagram)
        group_mac = group.multicast_mac

        for oif in oifs:
            raw = RawAssembler(
                raw__payload=payload,
                ether_type=EtherType.IP4,
                echo_tracker=packet_rx.tracker,
            )
            oif._phtx_ethernet(ethernet__dst=group_mac, ethernet__payload=raw)
            self._if._packet_stats_rx.ip4__mforward += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - Forwarded multicast {group} out {oif.interface_name}",
            )

    def _egress_interfaces(self, group: Ip4Address, src: Ip4Address, /) -> list["PacketHandler"]:
        """
        Return the interfaces (other than the ingress) whose IGMP querier
        table has a live downstream listener for '(src, group)'.
        """

        oifs: list["PacketHandler"] = []
        for iface in stack.interfaces.values():
            if iface.ifindex == self._if.ifindex:
                continue
            for membership in iface.igmp_querier_memberships():
                if membership.group == group and self._wants(membership, src):
                    oifs.append(iface)
                    break
        return oifs

    @staticmethod
    def _wants(membership: "IgmpQuerierMembership", src: Ip4Address, /) -> bool:
        """
        Return whether a listener with 'membership' wants traffic from
        'src' (RFC 3376 §6.3 source-specific forwarding): an EXCLUDE
        listener wants every source except its excluded set; an INCLUDE
        listener wants only its included sources.
        """

        if membership.filter_mode is Ip4MulticastFilterMode.EXCLUDE:
            return src not in membership.sources
        return src in membership.sources
