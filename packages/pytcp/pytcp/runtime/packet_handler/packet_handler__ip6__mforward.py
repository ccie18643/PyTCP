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
This module contains the IPv6 multicast forwarding (replication)
sub-handler for one interface — the last-hop multicast-router data
plane (Phase-2 M5f), the IPv6 mirror of the IPv4 handler. A transit
multicast datagram that passes the RPF check is replicated out every
interface whose MLD querier table has a downstream listener.

pytcp/runtime/packet_handler/packet_handler__ip6__mforward.py

ver 3.0.10
"""

from typing import TYPE_CHECKING

from net_addr import Ip6Address
from net_proto import EtherType, PacketRx, RawAssembler
from pytcp import stack
from pytcp.lib.ip6_multicast_filter import Ip6MulticastFilterMode
from pytcp.lib.logger import log
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler
    from pytcp.runtime.packet_handler.packet_handler__icmp6__tx import (
        MldQuerierMembership,
    )

# The IPv6 Hop Limit byte offset in the fixed header (RFC 8200 §3).
IP6__MFORWARD__HOP_OFFSET = 7

# The IPv6 multicast scope nibble (RFC 4291 §2.7): scopes 0-2
# (reserved / interface-local / link-local) are never forwarded off the
# arrival link; a router replicates only scope >= 3 (admin / site /
# organisation / global) traffic.
IP6__MULTICAST__MAX_NON_FORWARDED_SCOPE = 2


class Ip6MulticastForwardHandler:
    """
    The IPv6 multicast forwarding (replication) sub-handler for one
    interface.
    """

    _if: "PacketHandler"

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Initialize the IPv6 multicast forward sub-handler.
        """

        self._if = interface

    def _mforwarding_enabled(self) -> bool:
        """
        Return whether this interface is a multicast router
        ('mld.mc_forwarding'), the same switch that activates the MLD
        querier.
        """

        return bool(sysctl_iface.get_for_iface("mld.mc_forwarding", self._if._interface_name))

    def try_mforward_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        Replicate a transit IPv6 multicast datagram out every interface
        with a downstream listener for the group, or drop it via one of
        the '*__drop' counters. Consumes the datagram in every branch.

        Reference: RFC 1812 §5.2.4 (multicast forwarding — last hop).
        """

        ip6 = packet_rx.ip6
        group = ip6.dst
        src = ip6.src

        # 1. Multicast forwarding must be enabled on the ingress
        #    interface (host parity: a non-router drops a group it has
        #    not joined, counted in 'ip6__dst_unknown__drop').
        if not self._mforwarding_enabled():
            self._if._packet_stats_rx.ip6__dst_unknown__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - Multicast {group} not joined; forwarding disabled, dropping",
            )
            return

        # 2. Scope: interface-local / link-local multicast (scope <= 2,
        #    RFC 4291 §2.7) and any Hop-Limit-1 datagram are link-scoped
        #    and never forwarded.
        if ((int(group) >> 112) & 0x0F) <= IP6__MULTICAST__MAX_NON_FORWARDED_SCOPE or ip6.hop <= 1:
            self._if._packet_stats_rx.ip6__mforward_scope__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - Link-scoped multicast {group} (hop={ip6.hop}) not forwarded, dropping",
            )
            return

        # 3. RPF check: accept only if the datagram arrived on the
        #    interface the unicast FIB would use to reach its source.
        resolution = stack.forward_next_hop_ip6(src)
        if resolution is None or resolution[0].ifindex != self._if.ifindex:
            self._if._packet_stats_rx.ip6__mforward_rpf__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>RPF check failed for multicast source {src}, dropping</>",
            )
            return

        # 4. Compute the egress interfaces with a downstream listener for
        #    (src, group) from each interface's MLD querier table.
        oifs = self._egress_interfaces(group, src)
        if not oifs:
            self._if._packet_stats_rx.ip6__mforward_no_listeners__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - No downstream listener for multicast {group}, dropping",
            )
            return

        # 5. Replicate: decrement the Hop Limit (IPv6 has no header
        #    checksum) and re-emit the byte-identical datagram out each
        #    egress toward the group's Ethernet multicast MAC (RFC 2464
        #    §7). No neighbor resolution is needed for a multicast
        #    destination.
        datagram = bytearray(ip6.packet_bytes)
        datagram[IP6__MFORWARD__HOP_OFFSET] -= 1
        payload = bytes(datagram)
        group_mac = group.multicast_mac

        for oif in oifs:
            raw = RawAssembler(
                raw__payload=payload,
                ether_type=EtherType.IP6,
                echo_tracker=packet_rx.tracker,
            )
            oif._phtx_ethernet(ethernet__dst=group_mac, ethernet__payload=raw)
            self._if._packet_stats_rx.ip6__mforward += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - Forwarded multicast {group} out {oif.interface_name}",
            )

    def _egress_interfaces(self, group: Ip6Address, src: Ip6Address, /) -> list["PacketHandler"]:
        """
        Return the interfaces (other than the ingress) whose MLD querier
        table has a live downstream listener for '(src, group)'.
        """

        oifs: list["PacketHandler"] = []
        for iface in stack.interfaces.values():
            if iface.ifindex == self._if.ifindex:
                continue
            for membership in iface.mld_querier_memberships():
                if membership.group == group and self._wants(membership, src):
                    oifs.append(iface)
                    break
        return oifs

    @staticmethod
    def _wants(membership: "MldQuerierMembership", src: Ip6Address, /) -> bool:
        """
        Return whether a listener with 'membership' wants traffic from
        'src' (RFC 3810 §7.3 source-specific forwarding): an EXCLUDE
        listener wants every source except its excluded set; an INCLUDE
        listener wants only its included sources.
        """

        if membership.filter_mode is Ip6MulticastFilterMode.EXCLUDE:
            return src not in membership.sources
        return src in membership.sources
