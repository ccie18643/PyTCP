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
This module contains packet handler for the outbound IPv6 packets.

pytcp/runtime/packet_handler/packet_handler__ip6__tx.py

ver 3.0.10
"""

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6,
    Icmp6Mld2MessageReport,
    Icmp6NdMessageNeighborSolicitation,
    Ip6Assembler,
    Ip6Payload,
    IpProto,
    RawAssembler,
    Tracker,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddressState
from pytcp.protocols.ip6.ip6__policy_table import lookup as ip6_policy_lookup
from pytcp.protocols.ip6.ip6__source_selection import (
    common_prefix_len,
    ip6_address_scope,
)
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class Ip6TxHandler:
    """
    Packet handler for the outbound IPv6 packets.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv6 TX sub-handler.
        """

        self._if = interface

    def _phtx_ip6(
        self,
        *,
        ip6__dst: Ip6Address,
        ip6__src: Ip6Address,
        ip6__hop: int | None = None,
        ip6__ecn: int = 0,
        ip6__dscp: int = 0,
        ip6__payload: Ip6Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.

        'ip6__hop=None' (the default) lets the packet handler
        pick the effective Hop Limit per RFC 4861 §6.3.4: the
        most recent RA-advertised Cur-Hop-Limit if observed,
        otherwise IP6__DEFAULT_HOP_LIMIT (64). Callers that
        protocol-mandate a specific value (e.g. ND with 255,
        MLD with 1) pass it explicitly and short-circuit the
        lookup.
        """

        self._if._packet_stats_tx.ip6__pre_assemble += 1

        if ip6__hop is None:
            # Linux 'IPV6_DEFAULT_MCASTHOPS' (net/ipv6/af_inet6.c
            # inet6_create): outbound multicast datagrams default to
            # Hop-Limit=1 so multicast does not escape the local link
            # unless the caller explicitly opts in — mirroring the
            # IPv4 TTL=1 default. Unicast reads the RA-advertised /
            # protocol default via '_effective_ip6_hop_limit'.
            ip6__hop = 1 if ip6__dst.is_multicast else self._if._effective_ip6_hop_limit()

        assert 0 < ip6__hop < 256

        # Check if IPv6 protocol support is enabled, if not then silently
        # drop the packet.
        if not self._if._ip6_support:
            self._if._packet_stats_tx.ip6__no_proto_support__drop += 1
            return TxStatus.DROPPED__IP6__NO_PROTOCOL_SUPPORT

        # Validate source address.
        result = self.__validate_src_ip6_address(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__payload=ip6__payload,
        )
        if isinstance(result, TxStatus):
            return result
        ip6__src = result

        # Validate destination address.
        result = self.__validate_dst_ip6_address(
            ip6__dst=ip6__dst,
            tracker=ip6__payload.tracker,
        )
        if isinstance(result, TxStatus):
            return result
        ip6__dst = result

        # RFC 6437 §3 Flow Label auto-generation. When the
        # 'ip6.flow_label_generation' sysctl is non-zero
        # (default 1), derive a stable 20-bit label from the
        # (src, dst) pair so all packets of a given flow
        # carry the same label. Operators / test harnesses
        # that want flow=0 set the sysctl to 0.
        from pytcp.protocols.ip6 import ip6__constants

        ip6__flow = 0
        if ip6__constants.IP6__FLOW_LABEL_GENERATION:
            from pytcp.protocols.ip6.ip6__flow_label import compute_ip6_flow_label

            ip6__flow = compute_ip6_flow_label(src=ip6__src, dst=ip6__dst)

        # assemble IPv6 apcket
        ip6_packet_tx = Ip6Assembler(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__ecn=ip6__ecn,
            ip6__dscp=ip6__dscp,
            ip6__flow=ip6__flow,
            ip6__payload=ip6__payload,
        )

        # Loopback diversion: a locally-destined packet — one to ::1 or to
        # one of THIS host's own unicast addresses — is delivered
        # internally through the loopback interface, never on the wire
        # (the PyTCP analogue of Linux routing local traffic through 'lo';
        # see the IPv4 counterpart). Enqueue the assembled packet onto the
        # loopback ring; its consumer thread drains it into the RX path,
        # so a whole exchange never nests TX -> RX -> TX in one call stack.
        # Phase 2: a FIB HOST-scope local route supersedes this shortcut.
        if (loopback := stack.loopback_handler()) is not None and (
            ip6__dst.is_loopback or ip6__dst in stack.local_ip6_unicast()
        ):
            self._if._packet_stats_tx.ip6__loopback__send += 1
            __debug__ and log("ip6", f"{ip6_packet_tx.tracker} - Loopback delivery of {ip6_packet_tx}")
            loopback.enqueue_loopback(PacketRx(bytes(ip6_packet_tx)))
            return TxStatus.PASSED__IP6__LOOPBACK

        # Check if IP packet can be sent out without fragmentation,
        # if so send it out.
        if len(ip6_packet_tx) <= self._if._interface_mtu:
            self._if._packet_stats_tx.ip6__mtu_ok__send += 1
            __debug__ and log("ip6", f"{ip6_packet_tx.tracker} - {ip6_packet_tx}")
            match self._if._interface_layer:
                case InterfaceLayer.L2:
                    return self._if._phtx_ethernet(
                        ethernet__src=MacAddress(),
                        ethernet__dst=MacAddress(),
                        ethernet__payload=ip6_packet_tx,
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip6_packet_tx=ip6_packet_tx)
                    return TxStatus.PASSED__IP6__TO_TX_RING

        # Fragment packet and send out.
        self._if._packet_stats_tx.ip6__mtu_exceed__frag += 1
        __debug__ and log(
            "ip6",
            f"{ip6_packet_tx.tracker} - IPv6 packet len " f"{len(ip6_packet_tx)} bytes, fragmentation needed",
        )
        return self._if._phtx_ip6_frag(ip6_packet_tx=ip6_packet_tx)

    def __validate_src_ip6_address(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__payload: Ip6Payload,
    ) -> Ip6Address | TxStatus:
        """
        Make sure source ip address is valid, supplement with valid one
        as appropriate.
        """

        tracker = ip6__payload.tracker

        # Check if the the source IP address belongs to this stack
        # or its unspecified.
        if ip6__src not in {
            *self._if._ip6_unicast,
            *self._if._ip6_multicast,
            Ip6Address(),
        }:
            self._if._packet_stats_tx.ip6__src_not_owned__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, stack "
                f"doesn't own IPv6 address {ip6__src}, dropping</>",
            )
            return TxStatus.DROPPED__IP6__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with link
        # local address of the stack.
        if ip6__src in self._if._ip6_multicast:
            if self._if._ip6_unicast:
                self._if._packet_stats_tx.ip6__src_multicast__replace += 1
                ip6__src = self._if._ip6_unicast[0]
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack link local IPv6 address {ip6__src}",
                )
                return ip6__src
            self._if._packet_stats_tx.ip6__src_multicast__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, no stack "
                "link local unicast IPv6 address available</>",
            )
            return TxStatus.DROPPED__IP6__SRC_MULTICAST

        # If src is unspecified and stack is sending an ICMPv6
        # ND Neighbor Solicitation. Per RFC 4861 §4.3 / §7.2.2 a
        # DAD probe is the canonical NS form with src=:: and
        # targets the solicited-node multicast; it MUST NOT carry
        # an SLLA option (RFC 4861 §7.2.2). RFC 7527 §4.1
        # additionally allows a Nonce option for Enhanced DAD,
        # so the option list is no longer a reliable
        # "is DAD probe" proxy — match on message type instead.
        # This branch precedes RFC 6724 source selection: a DAD
        # probe MUST emit src=:: regardless of the stack's other
        # owned addresses.
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6NdMessageNeighborSolicitation)
            and ip6__payload.message.slla is None
        ):
            self._if._packet_stats_tx.ip6__src_unspecified__send += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 ND DAD " "packet, sending",
            )
            return ip6__src

        # If src is unspecified and stack is sending ICMPv6 MLDv2 report.
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6Mld2MessageReport)
        ):
            self._if._packet_stats_tx.ip6__src_unspecified__send += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 MLDv2 " "report, sending",
            )
            return ip6__src

        # If source is unspecified and destination is unicast,
        # run RFC 6724 default source-address selection across
        # the owned candidate set. The local/external split is
        # preserved at the stat-counter level for backwards
        # compatibility with existing observability dashboards.
        if ip6__src.is_unspecified and ip6__dst.is_unicast:
            selected = self._select_ip6_source(ip6__dst=ip6__dst)
            if selected is not None:
                if any(ip6__dst in host.network for host in self._if._ip6_ifaddr):
                    self._if._packet_stats_tx.ip6__src_network_unspecified__replace_local += 1
                else:
                    self._if._packet_stats_tx.ip6__src_network_unspecified__replace_external += 1
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet source is unspecified, RFC 6724 "
                    f"selector picked source IPv6 address {selected}",
                )
                return selected

        # RFC 6724 source selection ALSO applies to a multicast
        # destination (a DHCPv6 SOLICIT to ff02::1:2, an app sending to
        # a group from an unbound socket): fill in a source of adequate
        # scope from the owned set — the link-local for a link-local-
        # scoped group — matching Linux, which selects a source for a
        # multicast send. The DAD-probe (RFC 4861 §4.3) and MLDv2-report
        # branches above already returned the only two src=:: multicast
        # forms that MUST stay unspecified, so a packet reaching here
        # legitimately wants a real source; '_select_ip6_source' returns
        # None (-> drop below) when no owned address has adequate scope.
        if ip6__src.is_unspecified and ip6__dst.is_multicast:
            selected = self._select_ip6_source(ip6__dst=ip6__dst)
            if selected is not None:
                self._if._packet_stats_tx.ip6__src_unspecified__replace_multicast += 1
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet source is unspecified, RFC 6724 "
                    f"selector picked source IPv6 address {selected} for "
                    f"multicast destination {ip6__dst}",
                )
                return selected

        # If src is unspecified and stack can't replace it.
        if ip6__src.is_unspecified:
            self._if._packet_stats_tx.ip6__src_unspecified__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Packet source is unspecified, unable to " "replace with valid source, dropping</>",
            )
            return TxStatus.DROPPED__IP6__SRC_UNSPECIFIED

        # RFC 4007 §6 / RFC 4291 §2.5.6: a node may not send a
        # packet with a source address of smaller scope than the
        # destination. Catches caller-supplied explicit srcs
        # that would otherwise emit a structurally broken packet
        # (e.g. fe80:: source with 2001:db8:: destination — the
        # peer cannot route a reply back to the link-local).
        # Linux gates equivalent at the route layer with
        # ENETUNREACH; we gate here since PyTCP has no route
        # layer to fall through to.
        if ip6_address_scope(ip6__src) < ip6_address_scope(ip6__dst):
            self._if._packet_stats_tx.ip6__src_scope_mismatch__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Source {ip6__src} has smaller scope than "
                f"destination {ip6__dst}; RFC 4007 §6 violation, dropping</>",
            )
            return TxStatus.DROPPED__IP6__SRC_SCOPE_MISMATCH

        # If nothing above applies return the src address intact.
        return ip6__src

    def _select_ip6_source(self, *, ip6__dst: Ip6Address) -> Ip6Address | None:
        """
        Run RFC 6724 default source-address selection over the
        candidate set in '_ip6_ifaddr' and return the winner.

        The candidate set is the addresses owned by the stack;
        rule 1 short-circuits when the destination is itself
        owned. Otherwise the candidates are sorted by a
        lexicographic key that encodes rules 2 (scope), 3 (avoid
        deprecated), 6 (matching label), 7 (temp-address
        preference), and 8 (longest matching prefix), in that
        priority order. Rule 7 is gated on the
        'icmp6.use_tempaddr' sysctl: only 'use_tempaddr=2'
        triggers a positive preference; values 0 (no temp
        addresses to prefer) and 1 (no preference) leave the
        rule as a no-op. Rule 6 consults the RFC 6724 §10.3
        default policy table for label assignment. Rules 4
        (home address), 5 (outgoing interface), and 5.5
        (next-hop) are out of scope: 4/5/5.5 do not apply to a
        single-interface host stack.

        Returns None when no candidate exists. The TX path
        falls back to the existing
        DROPPED__IP6__SRC_UNSPECIFIED handling.
        """

        candidates = [host.address for host in self._if._ip6_ifaddr]
        if not candidates:
            return None

        # Rule 1 — prefer same address.
        if ip6__dst in candidates:
            return ip6__dst

        now = time.monotonic()
        deprecated_addresses = {
            entry.address
            for entry in self._if._icmp6_slaac_addresses
            if entry.state(now) is Icmp6SlaacAddressState.DEPRECATED
        }
        # RFC 8981 temp addresses share the §5.5.4 PREFERRED /
        # DEPRECATED semantics with their stable siblings —
        # 'preferred_until <= now < valid_until' is DEPRECATED.
        deprecated_addresses |= {
            entry.address
            for entry in self._if._icmp6_temp_addresses
            if entry.preferred_until <= now < entry.valid_until
        }
        # Only collect temp-address membership when the policy
        # actively prefers them ('use_tempaddr=2'); for values 0
        # and 1 the rule-7 score is 0 for every candidate and
        # the membership set never needs to be consulted.
        prefer_temp = sysctl_iface.get_for_iface("icmp6.use_tempaddr", self._if._interface_name) == 2
        temp_addresses = {entry.address for entry in self._if._icmp6_temp_addresses} if prefer_temp else set()
        dst_scope = ip6_address_scope(ip6__dst)
        _, dst_label = ip6_policy_lookup(ip6__dst)

        def sort_key(src: Ip6Address) -> tuple[tuple[int, int], int, int, int, int]:
            """
            Build the rule-2/3/6/7/8 lexicographic sort key.
            Higher tuples win under descending sort.
            """

            src_scope = ip6_address_scope(src)
            # Rule 2 — partition by 'scope >= dst_scope', then
            # prefer the smallest scope still >= dst_scope; for
            # candidates below dst_scope, prefer the largest
            # available.
            if src_scope >= dst_scope:
                rule2 = (1, -src_scope)
            else:
                rule2 = (0, src_scope)
            # Rule 3 — prefer non-deprecated.
            rule3 = 0 if src in deprecated_addresses else 1
            # Rule 6 — prefer source whose policy-table label
            # matches the destination's. The §10.3 default
            # table is consulted via 'ip6_policy_lookup'.
            _, src_label = ip6_policy_lookup(src)
            rule6 = 1 if src_label == dst_label else 0
            # Rule 7 — prefer temporary addresses when the
            # 'use_tempaddr' policy says so. With sysctl=0 or 1
            # 'temp_addresses' is empty so the score is 0 for
            # every candidate and rule 7 collapses to a no-op.
            rule7 = 1 if src in temp_addresses else 0
            # Rule 8 — prefer longest common prefix.
            rule8 = common_prefix_len(src, ip6__dst)
            return (rule2, rule3, rule6, rule7, rule8)

        candidates.sort(key=sort_key, reverse=True)
        winner = candidates[0]

        # RFC 4007 §6 / RFC 4291 §2.5.6: a node may not send a
        # packet with a source address of smaller scope than the
        # destination. The RFC 6724 §5 rule 2 fallback ("widest
        # available below dst scope") would otherwise produce a
        # link-local source for a global destination — a
        # structurally broken packet that no peer can route a
        # response back through. Linux gates this at the route
        # layer with ENETUNREACH; PyTCP gates here since there
        # is no route layer to fall through to. The caller drops
        # the TX with DROPPED__IP6__SRC_UNSPECIFIED.
        if ip6_address_scope(winner) < dst_scope:
            return None

        return winner

    def __validate_dst_ip6_address(
        self,
        *,
        ip6__dst: Ip6Address,
        tracker: Tracker,
    ) -> Ip6Address | TxStatus:
        """
        Make sure destination ip address is valid.
        """

        # Drop packet if the destination address is unspecified.
        if ip6__dst.is_unspecified:
            self._if._packet_stats_tx.ip6__dst_unspecified__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Destination address is unspecified, " "dropping</>",
            )
            return TxStatus.DROPPED__IP6__DST_UNSPECIFIED

        return ip6__dst

    def send_ip6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__next: IpProto,
        ip6__payload: bytes = bytes(),
        ip6__hop: int | None = None,
        ip6__ecn: int = 0,
        ip6__dscp: int = 0,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """
        Interface method for RAW Socket -> Packet Assembler
        communication. Handed to the TX worker fire-and-forget via
        '_marshal_tx_async' (Phase 4b): the calling app thread does
        not block for the 'TxStatus'. 'on_complete' (if given) fires
        once after the datagram leaves the send queue — the SO_SNDBUF
        release hook.
        """

        kwargs: dict[str, Any] = {
            "ip6__src": ip6__local_address,
            "ip6__dst": ip6__remote_address,
            "ip6__payload": RawAssembler(
                raw__payload=ip6__payload,
                ip_proto=ip6__next,
            ),
            "ip6__ecn": ip6__ecn,
            "ip6__dscp": ip6__dscp,
        }
        if ip6__hop is not None:
            kwargs["ip6__hop"] = ip6__hop
        self._if._marshal_tx_async(lambda: self._phtx_ip6(**kwargs), on_complete=on_complete)

    def __send_out_packet(self, ip6_packet_tx: Ip6Assembler) -> None:
        assert self._if._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._if._tx_ring.enqueue(ip6_packet_tx)
