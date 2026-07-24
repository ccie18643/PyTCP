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
IPv4 datagrams whose destination is not one of the stack's own
addresses — the RFC 1812 §5.2 transit-forwarding plane. It runs
the forwarding-policy gate, the martian-destination filter, the
FIB next-hop lookup, the TTL decrement (with ICMPv4 Time
Exceeded on expiry) and the no-route response (ICMPv4
Destination Unreachable), then re-emits the datagram out the
egress interface toward the next hop.

pytcp/runtime/packet_handler/packet_handler__ip4__forward.py

ver 3.0.9
"""

import struct
import time as time_module
from collections.abc import Callable
from typing import TYPE_CHECKING

from net_addr import Buffer, Ip4Address
from net_proto import (
    EthernetAssembler,
    EtherType,
    Icmp4DestinationUnreachableCode,
    Icmp4Message,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageTimeExceeded,
    Icmp4TimeExceededCode,
    Ip4FragAssembler,
    Ip4OptionNop,
    Ip4Options,
    PacketRx,
    RawAssembler,
    inet_cksum,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.protocols.ip.ip_frag import iter_fragment_chunks
from pytcp.stack import sysctl, sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# IPv4 header field byte offsets rewritten on forward — TTL at
# byte 8, Header Checksum at bytes 10-11 (RFC 791 §3.1).
IP4__FORWARD__TTL_OFFSET = 8
IP4__FORWARD__CKSUM_OFFSET = 10


class Ip4ForwardHandler:
    """
    Router forward path for inbound transit IPv4 datagrams.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv4 forward sub-handler.
        """

        self._if = interface

    def _forwarding_enabled(self) -> bool:
        """
        Return whether IPv4 forwarding is enabled for the ingress
        interface — the read-time OR of the global master
        ('ip4.ip_forward') and the per-interface switch
        ('ip4.forwarding'), matching Linux's 'net.ipv4.ip_forward' /
        'net.ipv4.conf.<iface>.forwarding' model.
        """

        if sysctl.get("ip4.ip_forward"):
            return True
        return bool(sysctl_iface.get_for_iface("ip4.forwarding", self._if._interface_name))

    def try_forward_ip4(self, packet_rx: PacketRx, /) -> None:
        """
        RFC 1812 §5.2 transit-forward an inbound IPv4 datagram whose
        destination is not one of the stack's own addresses. Either
        re-emits it out the egress interface toward its next hop
        (bumping 'ip4__forward'), or drops it — with the obligatory
        ICMPv4 error — via one of the '*__drop' counters. Consumes
        the datagram in every branch.

        Reference: RFC 1812 §5.2.1 (forward-or-deliver decision).
        Reference: RFC 1812 §5.3.1 (TTL decrement on forward).
        """

        ip4 = packet_rx.ip4
        dst = ip4.dst

        # 1. Forwarding must be enabled on the ingress interface.
        #    When it is not, the stack behaves exactly as a host —
        #    the drop is the byte-for-byte host-mode stub, counted in
        #    'ip4__dst_unknown__drop' (there is no separate
        #    'forward_disabled' counter; host parity is the stronger
        #    RFC 1812 §5.2.1 constraint).
        if not self._forwarding_enabled():
            self._if._packet_stats_rx.ip4__dst_unknown__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - IP packet not destined for this stack; forwarding disabled, dropping",
            )
            return

        # 2. Never forward toward a martian / non-routable destination
        #    (RFC 1812 §5.3.7): loopback, the unspecified address, the
        #    limited broadcast, a link-local destination (RFC 3927
        #    §2.7), or a multicast group (multicast forwarding is the
        #    Phase-2 M5 querier/replication work).
        if dst.is_loopback or dst.is_unspecified or dst.is_limited_broadcast or dst.is_link_local or dst.is_multicast:
            self._if._packet_stats_rx.ip4__forward_martian_dst__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Refusing to forward toward martian destination {dst}, dropping</>",
            )
            return

        # 3. Resolve the next hop via the FIB. A miss is "no route to
        #    host" — RFC 1812 §4.3.3.1 ICMPv4 Destination Unreachable
        #    (Code 0, network unreachable) back to the source.
        resolution = stack.forward_next_hop_ip4(dst)
        if resolution is None:
            self._if._packet_stats_rx.ip4__forward_no_route__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>No route to forward destination "
                f"{dst}, dropping and sending ICMPv4 Destination Unreachable</>",
            )
            self._emit_dest_unreachable(packet_rx)
            return
        egress, next_hop = resolution

        # 4. Decrement the lifetime. A datagram arriving with TTL <= 1
        #    cannot be forwarded — RFC 1812 §5.3.1 / §4.3.3.5 ICMPv4
        #    Time Exceeded (TTL exceeded in transit) back to the source.
        if ip4.ttl <= 1:
            self._if._packet_stats_rx.ip4__forward_ttl_exceeded__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Forwarded datagram TTL expired "
                f"(ttl={ip4.ttl}), dropping and sending ICMPv4 Time Exceeded</>",
            )
            self._emit_time_exceeded(packet_rx)
            return

        # 7. Oversize transit traffic (M2). A datagram larger than the
        #    egress MTU cannot be forwarded whole. Checked against the
        #    ORIGINAL datagram length; the TTL decrement does not change
        #    it. RFC 1812 §4.3.3.3 / RFC 791 §3.2:
        #    - DF=1  -> discard + ICMPv4 Destination Unreachable /
        #              Fragmentation Needed (Code 4) carrying the egress
        #              MTU (transit PMTU), so the source can lower its
        #              path MTU (RFC 1191).
        #    - DF=0  -> fragment to the egress MTU and forward each
        #              fragment (routers fragment, unlike the host
        #              origination path which fragments its own TX).
        if len(ip4.packet_bytes) > egress.interface_mtu:
            if ip4.flag_df:
                self._if._packet_stats_rx.ip4__forward_too_big__drop += 1
                __debug__ and log(
                    "ip4",
                    f"{packet_rx.tracker} - <WARN>Forwarded datagram "
                    f"({len(ip4.packet_bytes)} B) exceeds egress MTU "
                    f"{egress.interface_mtu} with DF=1, dropping and sending "
                    "ICMPv4 Fragmentation Needed</>",
                )
                self._emit_frag_needed(packet_rx, next_hop_mtu=egress.interface_mtu)
                return
            self._forward_fragmented_ip4(egress=egress, next_hop=next_hop, packet_rx=packet_rx)
            return

        # 8. In-MTU datagram: rewrite the header in place — TTL -= 1,
        #    recompute the header checksum over the IHL-bounded header
        #    (RFC 791 §3.1). The payload is preserved byte-for-byte.
        datagram = bytearray(ip4.packet_bytes)
        datagram[IP4__FORWARD__TTL_OFFSET] -= 1
        datagram[IP4__FORWARD__CKSUM_OFFSET] = datagram[IP4__FORWARD__CKSUM_OFFSET + 1] = 0
        struct.pack_into(
            "!H",
            datagram,
            IP4__FORWARD__CKSUM_OFFSET,
            inet_cksum(memoryview(datagram)[: ip4.hlen]),
        )

        self._forward_out_ip4(
            egress=egress,
            next_hop=next_hop,
            datagram=bytes(datagram),
            packet_rx=packet_rx,
        )

    def _forward_out_ip4(
        self,
        *,
        egress: PacketHandler,
        next_hop: Ip4Address,
        datagram: bytes,
        packet_rx: PacketRx,
    ) -> None:
        """
        Re-emit a forwarded IPv4 datagram out 'egress' toward
        'next_hop'. Wraps the (already TTL-decremented) datagram in a
        RawAssembler + Ethernet frame — no source selection or
        upper-layer re-assembly, so the datagram is preserved
        byte-for-byte. Resolves the next-hop MAC from the egress
        interface's own ARP cache; on a miss the frame is queued for
        post-resolution delivery (RFC 1122 §2.3.2.2) and counted as
        'ip4__forward_no_neighbor__drop'.
        """

        arp_cache = egress.arp_cache
        assert arp_cache is not None, "IPv4 forward egress must be an L2 interface with an ARP cache."

        raw = RawAssembler(
            raw__payload=datagram,
            ether_type=EtherType.IP4,
            echo_tracker=packet_rx.tracker,
        )

        mac_address = arp_cache.find_entry(ip4_address=next_hop)
        if mac_address is not None:
            egress._phtx_ethernet(ethernet__dst=mac_address, ethernet__payload=raw)
            self._if._packet_stats_rx.ip4__forward += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - Forwarded IPv4 datagram to next hop " f"{next_hop} via {egress.interface_name}",
            )
            return

        src_mac = egress.mac_unicast
        assert src_mac is not None, "IPv4 forward egress must have a unicast MAC."
        ethernet_packet_tx = EthernetAssembler(ethernet__src=src_mac, ethernet__payload=raw)
        arp_cache.enqueue_pending(ip4_address=next_hop, ethernet_packet_tx=ethernet_packet_tx)
        self._if._packet_stats_rx.ip4__forward_no_neighbor__drop += 1
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - <WARN>Next hop {next_hop} unresolved on "
            f"{egress.interface_name}; queued pending ARP resolution</>",
        )

    def _forward_fragmented_ip4(
        self,
        *,
        egress: PacketHandler,
        next_hop: Ip4Address,
        packet_rx: PacketRx,
    ) -> None:
        """
        Fragment a forwarded IPv4 datagram to the egress interface MTU
        and emit each fragment toward 'next_hop' (RFC 791 §3.2; the
        router fragments a DF=0 datagram it cannot forward whole). Each
        fragment inherits the original DSCP / ECN / Identification /
        protocol and carries the TTL decremented by one; the first
        fragment keeps the full options, later fragments only the
        copy-flag=1 subset (RFC 791 §3.1 option-copy rule). Reuses the
        origination-path 'iter_fragment_chunks' + 'Ip4FragAssembler'
        machinery. On a next-hop ARP miss the whole datagram is dropped
        (no per-fragment queueing) and counted as a no-neighbor drop.
        """

        arp_cache = egress.arp_cache
        assert arp_cache is not None, "IPv4 forward egress must be an L2 interface with an ARP cache."

        next_hop_mac = arp_cache.find_entry(ip4_address=next_hop)
        if next_hop_mac is None:
            self._if._packet_stats_rx.ip4__forward_no_neighbor__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Next hop {next_hop} unresolved on "
                f"{egress.interface_name}; dropping oversize forward (no fragment queue)</>",
            )
            return

        ip4 = packet_rx.ip4
        ttl_out = ip4.ttl - 1

        first_fragment_options = ip4.options
        copy_options_filtered = ip4.options.with_copy_flag(True)
        copy_options_padding = (-len(copy_options_filtered)) & 0b11
        non_first_fragment_options = Ip4Options(
            *copy_options_filtered,
            *(Ip4OptionNop() for _ in range(copy_options_padding)),
        )

        for offset, chunk, is_last in iter_fragment_chunks(
            bytes(ip4.payload_bytes),
            max_chunk_bytes=egress.interface_mtu - ip4.hlen,
        ):
            fragment_options = first_fragment_options if offset == 0 else non_first_fragment_options
            ip4_frag_tx = Ip4FragAssembler(
                ip4_frag__src=ip4.src,
                ip4_frag__dst=ip4.dst,
                ip4_frag__ttl=ttl_out,
                ip4_frag__dscp=ip4.dscp,
                ip4_frag__ecn=ip4.ecn,
                ip4_frag__options=fragment_options,
                ip4_frag__payload=chunk,
                ip4_frag__offset=offset,
                ip4_frag__flag_mf=not is_last,
                # Preserve the ORIGINAL datagram's Identification so the
                # far-end reassembles all fragments into one datagram.
                ip4_frag__id=ip4.id,
                ip4_frag__proto=ip4.proto,
            )
            egress._phtx_ethernet(ethernet__dst=next_hop_mac, ethernet__payload=ip4_frag_tx)

        self._if._packet_stats_rx.ip4__forward_fragmented += 1
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - Forwarded fragmented IPv4 datagram to next hop "
            f"{next_hop} via {egress.interface_name}",
        )

    def _emit_frag_needed(self, packet_rx: PacketRx, /, *, next_hop_mtu: int) -> None:
        """
        Emit ICMPv4 Destination Unreachable / Fragmentation Needed (Type
        3, Code 4) carrying the egress interface MTU, back to the source
        of a DF=1 forwarded datagram that exceeds the egress MTU — the
        transit Path-MTU-Discovery response.

        Reference: RFC 1812 §4.3.3.3 (Fragmentation Needed on DF=1 oversize).
        Reference: RFC 1191 §3 (next-hop MTU in the ICMP error).
        """

        self._emit_forward_icmp_error(
            packet_rx,
            message_factory=lambda data: Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                mtu=next_hop_mtu,
                data=data,
            ),
        )

    def _emit_time_exceeded(self, packet_rx: PacketRx, /) -> None:
        """
        Emit ICMPv4 Time Exceeded (Type 11, Code 0 — TTL exceeded in
        transit) back to the source of a forwarded datagram whose TTL
        expired, subject to the host-requirements gates and the ICMP
        error rate limit. The error is sourced from the ingress
        interface's address facing the original sender and embeds the
        offending datagram.

        Reference: RFC 1812 §4.3.3.5 (Time Exceeded on TTL expiry).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        self._emit_forward_icmp_error(
            packet_rx,
            message_factory=lambda data: Icmp4MessageTimeExceeded(
                code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
                data=data,
            ),
        )

    def _emit_dest_unreachable(self, packet_rx: PacketRx, /) -> None:
        """
        Emit ICMPv4 Destination Unreachable (Type 3, Code 0 — network
        unreachable) back to the source of a forwarded datagram with no
        route, subject to the host-requirements gates and the ICMP
        error rate limit.

        Reference: RFC 1812 §4.3.3.1 (Destination Unreachable, no route).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        self._emit_forward_icmp_error(
            packet_rx,
            message_factory=lambda data: Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.NETWORK,
                data=data,
            ),
        )

    def _emit_forward_icmp_error(
        self,
        packet_rx: PacketRx,
        /,
        *,
        message_factory: Callable[[Buffer], Icmp4Message],
    ) -> None:
        """
        Shared emission helper for a router-originated ICMPv4 error
        about a forwarded datagram: run the host-requirements gates +
        rate limit, source the error from the ingress interface's
        address toward the original sender (RFC 1812 §4.3.2.5), and
        send it back out the ingress interface.
        """

        ip4_src = self._if.select_ip4_source(packet_rx.ip4.src)
        if ip4_src is None:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp4_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv4 forward error "
                f"to {packet_rx.ip4.src}: {verdict}</>",
            )
            return

        self._if._marshal_tx(
            lambda: self._if._phtx_icmp4(
                ip4__src=ip4_src,
                ip4__dst=packet_rx.ip4.src,
                icmp4__message=message_factory(packet_rx.ip.packet_bytes),
                echo_tracker=packet_rx.tracker,
            )
        )
