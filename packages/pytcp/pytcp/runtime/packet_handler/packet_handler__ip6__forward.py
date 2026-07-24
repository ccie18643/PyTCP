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
This module contains the Phase-2 router forward path for inbound
IPv6 datagrams whose destination is not one of the stack's own
addresses — the RFC 1812 §5.2 transit-forwarding plane, IPv6
edition. It runs the forwarding-policy gate, the scope filter
(never forward a link-local or otherwise non-routable
source/destination), the FIB next-hop lookup, the Hop-Limit
decrement (with ICMPv6 Time Exceeded on expiry) and the no-route
response (ICMPv6 Destination Unreachable), then re-emits the
datagram out the egress interface toward the next hop. Routers
never fragment IPv6 (RFC 8200 §5), so oversize transit traffic
is dropped in M1 pending the M2 Packet Too Big response.

pytcp/runtime/packet_handler/packet_handler__ip6__forward.py

ver 3.0.9
"""

import time as time_module
from collections.abc import Callable
from typing import TYPE_CHECKING

from net_addr import Buffer, Ip6Address
from net_proto import (
    EthernetAssembler,
    EtherType,
    Icmp6DestinationUnreachableCode,
    Icmp6Message,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageTimeExceeded,
    Icmp6TimeExceededCode,
    PacketRx,
    RawAssembler,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.stack import sysctl, sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# IPv6 header field byte offset rewritten on forward — Hop Limit
# at byte 7 (RFC 8200 §3). There is no header checksum to
# recompute (unlike IPv4).
IP6__FORWARD__HOP_OFFSET = 7


class Ip6ForwardHandler:
    """
    Router forward path for inbound transit IPv6 datagrams.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv6 forward sub-handler.
        """

        self._if = interface

    def _forwarding_enabled(self) -> bool:
        """
        Return whether IPv6 forwarding is enabled for the ingress
        interface — the read-time OR of the global master
        ('ip6.all.forwarding') and the per-interface switch
        ('ip6.forwarding'), matching Linux's
        'net.ipv6.conf.all.forwarding' / 'net.ipv6.conf.<iface>.forwarding'
        model.
        """

        if sysctl.get("ip6.all.forwarding"):
            return True
        return bool(sysctl_iface.get_for_iface("ip6.forwarding", self._if._interface_name))

    def try_forward_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        RFC 1812 §5.2 transit-forward an inbound IPv6 datagram whose
        destination is not one of the stack's own addresses. Either
        re-emits it out the egress interface toward its next hop
        (bumping 'ip6__forward'), or drops it — with the obligatory
        ICMPv6 error — via one of the '*__drop' counters. Consumes
        the datagram in every branch.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: RFC 8200 §3 (Hop-Limit decrement on forward).
        """

        ip6 = packet_rx.ip6
        dst = ip6.dst

        # 1. Forwarding must be enabled on the ingress interface.
        #    When it is not, the stack behaves exactly as a host —
        #    the drop is the byte-for-byte host-mode stub, counted in
        #    'ip6__dst_unknown__drop'.
        if not self._forwarding_enabled():
            self._if._packet_stats_rx.ip6__dst_unknown__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - IP packet not destined for this stack; forwarding disabled, dropping",
            )
            return

        # 2. Never forward a non-routable / out-of-scope datagram
        #    (RFC 4007): a link-local source or destination must never
        #    cross interfaces, and loopback / unspecified / multicast
        #    destinations are not unicast-forwardable (multicast
        #    forwarding is the Phase-2 M5 querier/replication work).
        if ip6.src.is_link_local or dst.is_link_local or dst.is_loopback or dst.is_unspecified or dst.is_multicast:
            self._if._packet_stats_rx.ip6__forward_scope__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Refusing to forward out-of-scope "
                f"datagram {ip6.src} -> {dst}, dropping</>",
            )
            return

        # 3. Resolve the next hop via the FIB. A miss is "no route" —
        #    RFC 4443 §3.1 ICMPv6 Destination Unreachable (Code 0, no
        #    route to destination) back to the source.
        resolution = stack.forward_next_hop_ip6(dst)
        if resolution is None:
            self._if._packet_stats_rx.ip6__forward_no_route__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>No route to forward destination "
                f"{dst}, dropping and sending ICMPv6 Destination Unreachable</>",
            )
            self._emit_dest_unreachable(packet_rx)
            return
        egress, next_hop = resolution

        # 4. Decrement the lifetime. A datagram arriving with Hop-Limit
        #    <= 1 cannot be forwarded — RFC 8200 §3 / RFC 4443 §3.3
        #    ICMPv6 Time Exceeded (hop limit exceeded in transit) back
        #    to the source.
        if ip6.hop <= 1:
            self._if._packet_stats_rx.ip6__forward_hop_exceeded__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Forwarded datagram Hop-Limit expired "
                f"(hop={ip6.hop}), dropping and sending ICMPv6 Time Exceeded</>",
            )
            self._emit_time_exceeded(packet_rx)
            return

        # 7. Oversize transit traffic is dropped in M1 (routers never
        #    fragment IPv6 — RFC 8200 §5; the transit Packet Too Big
        #    response lands in M2). Checked against the ORIGINAL
        #    datagram length.
        datagram = bytearray(ip6.packet_bytes)
        if len(datagram) > egress.interface_mtu:
            self._if._packet_stats_rx.ip6__forward_too_big__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Forwarded datagram ({len(datagram)} B) "
                f"exceeds egress MTU {egress.interface_mtu}, dropping (M2: Packet Too Big)</>",
            )
            return

        # 8. Rewrite the Hop-Limit in place (RFC 8200 §3). There is no
        #    header checksum to recompute; the payload is preserved
        #    byte-for-byte.
        datagram[IP6__FORWARD__HOP_OFFSET] -= 1

        self._forward_out_ip6(
            egress=egress,
            next_hop=next_hop,
            datagram=bytes(datagram),
            packet_rx=packet_rx,
        )

    def _forward_out_ip6(
        self,
        *,
        egress: PacketHandler,
        next_hop: Ip6Address,
        datagram: bytes,
        packet_rx: PacketRx,
    ) -> None:
        """
        Re-emit a forwarded IPv6 datagram out 'egress' toward
        'next_hop'. Wraps the (already Hop-Limit-decremented) datagram
        in a RawAssembler + Ethernet frame — no source selection or
        upper-layer re-assembly, so the datagram is preserved
        byte-for-byte. Resolves the next-hop MAC from the egress
        interface's own ND cache; on a miss the frame is queued for
        post-resolution delivery (RFC 1122 §2.3.2.2 mirror) and counted
        as 'ip6__forward_no_neighbor__drop'.
        """

        nd_cache = egress.nd_cache
        assert nd_cache is not None, "IPv6 forward egress must be an L2 interface with an ND cache."

        raw = RawAssembler(
            raw__payload=datagram,
            ether_type=EtherType.IP6,
            echo_tracker=packet_rx.tracker,
        )

        mac_address = nd_cache.find_entry(ip6_address=next_hop)
        if mac_address is not None:
            egress._phtx_ethernet(ethernet__dst=mac_address, ethernet__payload=raw)
            self._if._packet_stats_rx.ip6__forward += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - Forwarded IPv6 datagram to next hop " f"{next_hop} via {egress.interface_name}",
            )
            return

        src_mac = egress.mac_unicast
        assert src_mac is not None, "IPv6 forward egress must have a unicast MAC."
        ethernet_packet_tx = EthernetAssembler(ethernet__src=src_mac, ethernet__payload=raw)
        nd_cache.enqueue_pending(ip6_address=next_hop, ethernet_packet_tx=ethernet_packet_tx)
        self._if._packet_stats_rx.ip6__forward_no_neighbor__drop += 1
        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - <WARN>Next hop {next_hop} unresolved on "
            f"{egress.interface_name}; queued pending ND resolution</>",
        )

    def _emit_time_exceeded(self, packet_rx: PacketRx, /) -> None:
        """
        Emit ICMPv6 Time Exceeded (Type 3, Code 0 — hop limit exceeded
        in transit) back to the source of a forwarded datagram whose
        Hop-Limit expired, subject to the host-requirements gates and
        the ICMP error rate limit.

        Reference: RFC 4443 §3.3 (Time Exceeded on Hop-Limit expiry).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        self._emit_forward_icmp_error(
            packet_rx,
            message_factory=lambda data: Icmp6MessageTimeExceeded(
                code=Icmp6TimeExceededCode.HOP_LIMIT_EXCEEDED_IN_TRANSIT,
                data=data,
            ),
        )

    def _emit_dest_unreachable(self, packet_rx: PacketRx, /) -> None:
        """
        Emit ICMPv6 Destination Unreachable (Type 1, Code 0 — no route
        to destination) back to the source of a forwarded datagram with
        no route, subject to the host-requirements gates and the ICMP
        error rate limit.

        Reference: RFC 4443 §3.1 (Destination Unreachable, no route).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        self._emit_forward_icmp_error(
            packet_rx,
            message_factory=lambda data: Icmp6MessageDestinationUnreachable(
                code=Icmp6DestinationUnreachableCode.NO_ROUTE,
                data=data,
            ),
        )

    def _emit_forward_icmp_error(
        self,
        packet_rx: PacketRx,
        /,
        *,
        message_factory: Callable[[Buffer], Icmp6Message],
    ) -> None:
        """
        Shared emission helper for a router-originated ICMPv6 error
        about a forwarded datagram: run the host-requirements gates +
        rate limit, source the error from the ingress interface's
        address toward the original sender (RFC 1812 §4.3.2.5), and
        send it back out the ingress interface.
        """

        ip6_src = self._if.select_ip6_source(packet_rx.ip6.src)
        if ip6_src is None:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp6_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv6 forward error "
                f"to {packet_rx.ip6.src}: {verdict}</>",
            )
            return

        self._if._marshal_tx(
            lambda: self._if._phtx_icmp6(
                ip6__src=ip6_src,
                ip6__dst=packet_rx.ip6.src,
                icmp6__message=message_factory(packet_rx.ip.packet_bytes),
            )
        )
