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
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6Message,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessagePacketTooBig,
    Icmp6MessageTimeExceeded,
    Icmp6NdMessageRedirect,
    Icmp6NdOption,
    Icmp6NdOptionRedirectedHeader,
    Icmp6NdOptions,
    Icmp6NdOptionTlla,
    Icmp6TimeExceededCode,
    Ip6Assembler,
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

# RFC 4861 §4.5: the ICMPv6 Redirect (message + IPv6 header + ND
# options) MUST fit the IPv6 minimum MTU. Cap the Redirected Header
# option's embedded datagram so the whole message stays under 1280:
# 1280 - 40 (IPv6 hdr) - 40 (Redirect fixed) - 8 (TLLA) - 8 (RH hdr).
IP6__FORWARD__REDIRECT__EMBED_MAX = 1184


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

        # 5b. ICMPv6 ND Redirect (M3). RFC 4861 §8 / RFC 1812 §5.2.7.2:
        #     when the datagram is being forwarded back out the interface
        #     it arrived on (ingress == egress), advise the source of the
        #     better first hop. The triggering datagram is still
        #     forwarded below.
        if egress is self._if:
            self._maybe_emit_redirect(packet_rx, target=next_hop)

        # 7. Oversize transit traffic (M2). Routers never fragment IPv6
        #    (RFC 8200 §5), so a datagram larger than the egress MTU is
        #    discarded and the source is told to lower its path MTU via
        #    an ICMPv6 Packet Too Big (Type 2) carrying the egress MTU
        #    (RFC 4443 §3.2 / RFC 8201 §3). Checked against the ORIGINAL
        #    datagram length.
        if len(ip6.packet_bytes) > egress.interface_mtu:
            self._if._packet_stats_rx.ip6__forward_too_big__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Forwarded datagram ({len(ip6.packet_bytes)} B) "
                f"exceeds egress MTU {egress.interface_mtu}, dropping and sending "
                "ICMPv6 Packet Too Big</>",
            )
            self._emit_packet_too_big(packet_rx, next_hop_mtu=egress.interface_mtu)
            return

        # 8. In-MTU datagram: rewrite the Hop-Limit in place (RFC 8200
        #    §3). There is no header checksum to recompute; the payload
        #    is preserved byte-for-byte.
        datagram = bytearray(ip6.packet_bytes)
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

    def _maybe_emit_redirect(self, packet_rx: PacketRx, /, *, target: Ip6Address) -> None:
        """
        Emit an ICMPv6 ND Redirect (RFC 4861 §4.5) advising the source of
        'packet_rx' that 'target' is the better first hop for the
        datagram's destination, when the datagram is being forwarded back
        out the interface it arrived on. Gated by the per-interface
        'ip6.send_redirects' sysctl.

        The Redirect is sourced from the interface's link-local address
        (RFC 4861 §4.5) with Hop Limit 255, addressed to the original
        source. It carries a Target Link-Layer Address option when the
        target's MAC is in the ND cache, and a Redirected Header option
        embedding (a bounded prefix of) the triggering datagram. The
        triggering datagram is still forwarded.
        """

        if not sysctl_iface.get_for_iface("ip6.send_redirects", self._if._interface_name):
            return

        ip6_src = self._link_local_source()
        if ip6_src is None:
            return

        nd_cache = self._if.nd_cache
        assert nd_cache is not None, "IPv6 forward egress must be an L2 interface with an ND cache."
        target_mac = nd_cache.find_entry(ip6_address=target)

        options: list[Icmp6NdOption] = []
        if target_mac is not None:
            options.append(Icmp6NdOptionTlla(target_mac))
        # The Redirected Header option is a length-prefixed ND option, so
        # its embedded datagram must be a multiple of 8 bytes (RFC 4861
        # §4.6.3): cap at the min-MTU budget, then floor to an 8-byte
        # boundary (dropping up to 7 diagnostic bytes).
        embed = bytes(packet_rx.ip.packet_bytes)[:IP6__FORWARD__REDIRECT__EMBED_MAX]
        embed = embed[: len(embed) - len(embed) % 8]
        options.append(Icmp6NdOptionRedirectedHeader(data=embed))

        ip6_packet_tx = Ip6Assembler(
            ip6__src=ip6_src,
            ip6__dst=packet_rx.ip6.src,
            ip6__hop=255,
            ip6__payload=Icmp6Assembler(
                icmp6__message=Icmp6NdMessageRedirect(
                    target_address=target,
                    destination_address=packet_rx.ip6.dst,
                    options=Icmp6NdOptions(*options),
                ),
                echo_tracker=packet_rx.tracker,
            ),
        )

        self._if._packet_stats_rx.ip6__forward_redirect += 1
        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - Sending ICMPv6 Redirect to {packet_rx.ip6.src}: "
            f"better first hop for {packet_rx.ip6.dst} is {target}",
        )
        # Emit through the L2 path with the original sender's MAC (from
        # the received frame) as the explicit destination. This bypasses
        # the origination-path RFC 4007 §6 source-scope check — which
        # (correctly for general traffic) would reject the RFC 4861 §4.5
        # mandated link-local source toward the global-addressed on-link
        # sender — while keeping the link-local source the RFC requires.
        self._if._phtx_ethernet(
            ethernet__dst=packet_rx.ethernet.src,
            ethernet__payload=ip6_packet_tx,
        )

    def _link_local_source(self) -> Ip6Address | None:
        """
        Return the ingress interface's link-local unicast address — the
        RFC 4861 §4.5 mandated source for an ICMPv6 Redirect — or None
        when the interface has no link-local address configured.
        """

        for address in self._if._ip6_unicast:
            if address.is_link_local:
                return address
        return None

    def _emit_packet_too_big(self, packet_rx: PacketRx, /, *, next_hop_mtu: int) -> None:
        """
        Emit ICMPv6 Packet Too Big (Type 2) carrying the egress
        interface MTU, back to the source of a forwarded datagram that
        exceeds the egress MTU — the transit Path-MTU-Discovery response
        (routers never fragment IPv6).

        Reference: RFC 4443 §3.2 (Packet Too Big).
        Reference: RFC 8201 §3 (next-hop MTU in the ICMP error).
        Reference: RFC 8200 §5 (routers never fragment IPv6).
        """

        self._emit_forward_icmp_error(
            packet_rx,
            message_factory=lambda data: Icmp6MessagePacketTooBig(
                mtu=next_hop_mtu,
                data=data,
            ),
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
