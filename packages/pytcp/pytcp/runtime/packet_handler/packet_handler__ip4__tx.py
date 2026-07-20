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
This module contains packet handler for the outbound IPv4 packets.

pytcp/runtime/packet_handler/packet_handler__ip4__tx.py

ver 3.0.8
"""

from typing import TYPE_CHECKING, Any

from net_addr import Ip4Address, MacAddress
from net_proto import (
    Ip4Assembler,
    Ip4FragAssembler,
    Ip4OptionNop,
    Ip4Options,
    Ip4Payload,
    IpProto,
    RawAssembler,
    TcpAssembler,
    Tracker,
    UdpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.ip4 import ip4__constants as ip4_const
from pytcp.protocols.ip4.ip4__source_selection import (
    common_prefix_len,
    ip4_address_scope,
)
from pytcp.protocols.ip.ip_frag import iter_fragment_chunks
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class Ip4TxHandler:
    """
    Packet handler for the outbound IPv4 packets.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv4 TX sub-handler.
        """

        self._if = interface

    def _next_ip4_id(self) -> int:
        """
        Generate the next IPv4 Identification value for this
        interface — an atomic, 16-bit-masked pre-increment of the
        per-interface counter. Masking wraps 0xFFFF -> 0 instead of
        overflowing the 16-bit wire field; the lock makes the
        read-modify-write atomic so concurrent fragmented sends never
        collide on an Identification (which would corrupt reassembly
        at the peer).

        Reference: RFC 791 §2.3 (Identification field).
        """

        with self._if._lock__ip4_id:
            self._if._ip4_id = (self._if._ip4_id + 1) & 0xFFFF
            return self._if._ip4_id

    def _phtx_ip4(
        self,
        *,
        ip4__dst: Ip4Address,
        ip4__src: Ip4Address,
        ip4__ttl: int | None = None,
        ip4__ecn: int = 0,
        ip4__dscp: int = 0,
        ip4__flag_df: bool = False,
        ip4__options: Ip4Options = Ip4Options(),
        ip4__payload: Ip4Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.
        """

        self._if._packet_stats_tx.ip4__pre_assemble += 1

        if ip4__ttl is None:
            # RFC 1112 §6.1: outbound multicast datagrams default
            # to TTL=1 so multicast does not escape the local link
            # unless the caller explicitly opts in. Unicast reads
            # the live 'ip4.default_ttl' sysctl via qualified
            # module access so an operator override resolves on
            # every emission (RFC 1122 §3.2.1.7 "MUST be
            # configurable").
            ip4__ttl = 1 if ip4__dst.is_multicast else ip4_const.IP4__DEFAULT_TTL

        assert 0 < ip4__ttl < 256

        # Check if IPv4 protocol support is enabled, if not then silently drop
        # the packet.
        if not self._if._ip4_support:
            self._if._packet_stats_tx.ip4__no_proto_support__drop += 1
            return TxStatus.DROPPED__IP4__NO_PROTOCOL_SUPPORT

        # Validate source address.
        result = self.__validate_src_ip4_address(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__payload=ip4__payload,
        )
        if isinstance(result, TxStatus):
            return result
        ip4__src = result

        # Validate destination address.
        result = self.__validate_dst_ip4_address(
            ip4__dst=ip4__dst,
            tracker=ip4__payload.tracker,
        )
        if isinstance(result, TxStatus):
            return result
        ip4__dst = result

        # RFC 919 §1 / RFC 922 §3: outbound broadcast emission
        # gated by 'ip4.allow_broadcast'. The DHCP-client RFC
        # 2131 §3.1 path (src=0.0.0.0, UDP sport=68/dport=67) is
        # the only consumer that legitimately broadcasts pre-
        # bind and bypasses the gate. The src check after
        # __validate_src_ip4_address pinpoints DHCP because the
        # validator preserves src=0.0.0.0 only for that specific
        # pattern.
        allow_broadcast = sysctl_iface.get_for_iface(
            "ip4.allow_broadcast",
            self._if._interface_name,
        )
        if (ip4__dst.is_limited_broadcast or ip4__dst in self._if._ip4_broadcast) and not allow_broadcast:
            is_dhcp_client = (
                ip4__src.is_unspecified
                and isinstance(ip4__payload, UdpAssembler)
                and ip4__payload.sport == 68
                and ip4__payload.dport == 67
            )
            if not is_dhcp_client:
                self._if._packet_stats_tx.ip4__dst_broadcast_disallowed__drop += 1
                __debug__ and log(
                    "ip4",
                    f"{ip4__payload.tracker} - <WARN>Outbound broadcast to "
                    f"{ip4__dst} dropped; set 'ip4.allow_broadcast=1' to permit</>",
                )
                return TxStatus.DROPPED__IP4__DST_BROADCAST_DISALLOWED

        # RFC 3927 §2.6: link-local addressing is local-only.
        # A host MUST NOT send a packet with an IPv4 Link-Local
        # source to a non-link-local destination, nor a packet
        # with a link-local destination from a non-link-local
        # source. Both halves of the rule are symmetric: any
        # scope mix between src and dst is rejected. The DHCP-
        # client path (src=0.0.0.0, dst=255.255.255.255) is
        # naturally exempt — neither address is link-local so
        # 'is_link_local != is_link_local' is False.
        if ip4__src.is_link_local != ip4__dst.is_link_local:
            self._if._packet_stats_tx.ip4__link_local_scope_mismatch__drop += 1
            __debug__ and log(
                "ip4",
                f"{ip4__payload.tracker} - <WARN>Link-local scope mismatch: "
                f"src={ip4__src} dst={ip4__dst}; dropping (RFC 3927 §2.6)</>",
            )
            return TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH

        # Assemble IPv4 packet.
        ip4_packet_tx = Ip4Assembler(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__ttl=ip4__ttl,
            ip4__ecn=ip4__ecn,
            ip4__dscp=ip4__dscp,
            ip4__flag_df=ip4__flag_df,
            ip4__options=ip4__options,
            ip4__payload=ip4__payload,
        )

        # Loopback diversion: a locally-destined packet — one to
        # 127.0.0.0/8 or to one of THIS host's own unicast addresses — is
        # delivered internally through the loopback interface, never on
        # the wire. This is the PyTCP analogue of Linux routing local
        # traffic through 'lo'; it also fixes the own-IP path, which used
        # to ARP-resolve the host's own address and drop on the cache
        # miss. Enqueue the assembled packet onto the loopback ring; its
        # consumer thread drains it into the RX path, so a whole exchange
        # never nests TX -> RX -> TX in one call stack.
        # Phase 2: a FIB HOST-scope local route supersedes this membership
        # shortcut (activating the currently-dead 'RouteScope.HOST').
        if (loopback := stack.loopback_handler()) is not None and (
            ip4__dst.is_loopback or ip4__dst in stack.local_ip4_unicast()
        ):
            self._if._packet_stats_tx.ip4__loopback__send += 1
            __debug__ and log("ip4", f"{ip4_packet_tx.tracker} - Loopback delivery of {ip4_packet_tx}")
            loopback.enqueue_loopback(PacketRx(bytes(ip4_packet_tx)))
            return TxStatus.PASSED__IP4__LOOPBACK

        # Send packet out if it's size doesn't exceed mtu.
        if len(ip4_packet_tx) <= self._if._interface_mtu:
            self._if._packet_stats_tx.ip4__mtu_ok__send += 1
            __debug__ and log("ip4", f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
            match self._if._interface_layer:
                case InterfaceLayer.L2:
                    return self._if._phtx_ethernet(
                        ethernet__src=MacAddress(),
                        ethernet__dst=MacAddress(),
                        ethernet__payload=ip4_packet_tx,
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip4_packet_tx)
                    return TxStatus.PASSED__IP4__TO_TX_RING

        # RFC 791 §3.1: a datagram with DF=1 that exceeds the link
        # MTU MUST be discarded. Fragmenting it locally would emit
        # MF=1 fragments that contradict the DF=1 contract the upper
        # layer asked for.
        if ip4__flag_df:
            self._if._packet_stats_tx.ip4__mtu_exceed__df_set__drop += 1
            __debug__ and log(
                "ip4",
                f"{ip4_packet_tx.tracker} - <CRIT>IPv4 packet len {len(ip4_packet_tx)} "
                f"bytes exceeds MTU and DF=1; dropping</>",
            )
            return TxStatus.DROPPED__IP4__MTU_EXCEED_DF

        # Fragment packet and send out.
        self._if._packet_stats_tx.ip4__mtu_exceed__frag += 1
        __debug__ and log(
            "ip4",
            f"{ip4_packet_tx.tracker} - IPv4 packet len {len(ip4_packet_tx)} " "bytes, fragmentation needed",
        )

        if isinstance(ip4_packet_tx.payload, (TcpAssembler, UdpAssembler)):
            ip4_packet_tx.payload.pshdr_sum = ip4_packet_tx.pshdr_sum

        # RFC 791 §3.1 option-copy-flag: build the per-fragment
        # options sets. First fragment carries the full original
        # options; subsequent fragments carry only the copy_flag=1
        # subset (LSRR / SSRR / Router Alert / CIPSO etc.). NOPs
        # are appended to align the subset to 4 bytes per the
        # IHL wire encoding.
        first_fragment_options = ip4_packet_tx.options
        copy_options_filtered = ip4_packet_tx.options.with_copy_flag(True)
        copy_options_padding = (-len(copy_options_filtered)) & 0b11
        non_first_fragment_options = Ip4Options(
            *copy_options_filtered,
            *(Ip4OptionNop() for _ in range(copy_options_padding)),
        )

        # One Identification per datagram, captured into a local so
        # concurrent fragmented sends can't read each other's value
        # (the generator's masked increment is atomic).
        ip4_id = self._next_ip4_id()
        outbound_tx_status: set[TxStatus] = set()
        for offset, chunk, is_last in iter_fragment_chunks(
            bytes(ip4_packet_tx.payload),
            max_chunk_bytes=self._if._interface_mtu - ip4_packet_tx.hlen,
        ):
            fragment_options = first_fragment_options if offset == 0 else non_first_fragment_options
            ip4_frag_tx = Ip4FragAssembler(
                ip4_frag__src=ip4__src,
                ip4_frag__dst=ip4__dst,
                ip4_frag__ttl=ip4__ttl,
                # RFC 791 §2.3 / RFC 2474 §3: each fragment is an
                # independent datagram and inherits the original's
                # DSCP + ECN; copy them from the source packet rather
                # than zeroing the per-fragment TOS byte.
                ip4_frag__dscp=ip4_packet_tx.dscp,
                ip4_frag__ecn=ip4_packet_tx.ecn,
                ip4_frag__options=fragment_options,
                ip4_frag__payload=chunk,
                ip4_frag__offset=offset,
                ip4_frag__flag_mf=not is_last,
                ip4_frag__id=ip4_id,
                ip4_frag__proto=ip4_packet_tx.proto,
            )
            __debug__ and log("ip4", f"{ip4_frag_tx.tracker} - {ip4_frag_tx}")
            self._if._packet_stats_tx.ip4__mtu_exceed__frag__send += 1

            match self._if._interface_layer:
                case InterfaceLayer.L2:
                    outbound_tx_status.add(
                        self._if._phtx_ethernet(
                            ethernet__src=MacAddress(),
                            ethernet__dst=MacAddress(),
                            ethernet__payload=ip4_frag_tx,
                        )
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip4_frag_tx)
                    outbound_tx_status.add(TxStatus.PASSED__IP4__TO_TX_RING)

        # Return the most severe code.
        for tx_status in [
            TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP4,
            TxStatus.DROPPED__ETHERNET__DST_ARP_CACHE_MISS,
            TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP4__TO_TX_RING,
        ]:
            if tx_status in outbound_tx_status:
                return tx_status

        return TxStatus.DROPPED__IP4__UNKNOWN

    def __validate_src_ip4_address(
        self,
        *,
        ip4__src: Ip4Address,
        ip4__dst: Ip4Address,
        ip4__payload: Ip4Payload,
    ) -> Ip4Address | TxStatus:
        """
        Make sure source ip address is valid, supplement with valid one
        as appropriate.
        """

        tracker = ip4__payload.tracker

        # Check if the the source IP address belongs to this stack or is set to all
        # zeros (for DHCP client communication).
        if ip4__src not in {
            *self._if._ip4_unicast,
            *self._if._ip4_multicast,
            *self._if._ip4_broadcast,
            Ip4Address(),
        }:
            self._if._packet_stats_tx.ip4__src_not_owned__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, stack "
                f"doesn't own IPv4 address {ip4__src}, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with
        # primary address of the stack.
        if ip4__src in self._if._ip4_multicast:
            if self._if._ip4_unicast:
                self._if._packet_stats_tx.ip4__src_multicast__replace += 1
                ip4__src = self._if._ip4_unicast[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack primary IPv4 address {ip4__src}",
                )
                return ip4__src
            self._if._packet_stats_tx.ip4__src_multicast__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
                f"primary unicast IPv4 address available, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_MULTICAST

        # If packet is a response to limited broadcast then replace source address
        # with primary address of the stack.
        if ip4__src.is_limited_broadcast:
            if self._if._ip4_unicast:
                self._if._packet_stats_tx.ip4__src_limited_broadcast__replace += 1
                ip4__src = self._if._ip4_unicast[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to limited broadcast, "
                    "replaced source with stack primary IPv4 "
                    f"address {ip4__src}",
                )
                return ip4__src
            self._if._packet_stats_tx.ip4__src_limited_broadcast__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
                f"primary unicast IPv4 address available, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_LIMITED_BROADCAST

        # If packet is a response to network broadcast then replace source address
        # with first stack address that belongs to appropriate subnet.
        if ip4__src in self._if._ip4_broadcast:
            ip4_src_list = [
                ip4_host.address for ip4_host in self._if._ip4_ifaddr if ip4_host.network.broadcast == ip4__src
            ]
            if ip4_src_list:
                self._if._packet_stats_tx.ip4__src_network_broadcast__replace += 1
                ip4__src = ip4_src_list[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to network broadcast, "
                    f"replaced source with appropriate IPv4 address {ip4__src}",
                )
                return ip4__src

        # If src is unspecified and stack is sending DHCP packet.
        # Per RFC 2131 §3.1 a DHCPDISCOVER / DHCPREQUEST MUST
        # carry src=0.0.0.0 — keep the unspec-src short-circuit
        # before RFC 6724 source selection so the selector
        # cannot replace it with an owned address.
        if (
            ip4__src.is_unspecified
            and isinstance(ip4__payload, UdpAssembler)
            and ip4__payload.sport == 68
            and ip4__payload.dport == 67
        ):
            self._if._packet_stats_tx.ip4__src_unspecified__send += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - Packet source is unspecified, DHCPv4 packet, " "sending",
            )
            return ip4__src

        # If source is unspecified, run RFC 6724 §6 default
        # source-address selection (rules 1, 2, and 8 — the
        # only ones applicable to IPv4) across the owned
        # candidate set. The local/external split is preserved
        # at the stat-counter level for backwards compatibility
        # with existing observability dashboards.
        if ip4__src.is_unspecified:
            selected = self._select_ip4_source(ip4__dst=ip4__dst)
            if selected is not None:
                if any(ip4__dst in host.network for host in self._if._ip4_ifaddr):
                    self._if._packet_stats_tx.ip4__src_network_unspecified__replace_local += 1
                else:
                    self._if._packet_stats_tx.ip4__src_network_unspecified__replace_external += 1
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet source is unspecified, RFC 6724 "
                    f"selector picked source IPv4 address {selected}",
                )
                return selected

        # If src is unspecified and stack can't replace it.
        if ip4__src.is_unspecified:
            self._if._packet_stats_tx.ip4__src_unspecified__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Packet source is unspecified, unable to " "replace with valid source, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_UNSPECIFIED

        # If nothing above applies return the src address intact.
        return ip4__src

    def _select_ip4_source(self, *, ip4__dst: Ip4Address) -> Ip4Address | None:
        """
        Run RFC 6724 §6 default source-address selection over
        the candidate set in '_ip4_ifaddr' and return the winner.

        Only rules 1 (same address), 2 (scope), and 8 (longest
        matching prefix) apply to IPv4: rule 3 (avoid
        deprecated) has no IPv4 equivalent (no SLAAC), rule 6
        (matching label) and rule 7 (temp addresses) likewise
        have no IPv4 analog, and rules 4 / 5 / 5.5 are no-ops on
        a single-interface host stack. The lex-tuple sort key
        encodes rules 2 and 8 in priority order; rule 1
        short-circuits.

        Returns None when no candidate exists. The TX path
        falls back to the existing
        DROPPED__IP4__SRC_UNSPECIFIED handling.
        """

        candidates = [host.address for host in self._if._ip4_ifaddr]
        if not candidates:
            return None

        # Rule 1 — prefer same address.
        if ip4__dst in candidates:
            return ip4__dst

        dst_scope = ip4_address_scope(ip4__dst)

        def sort_key(src: Ip4Address) -> tuple[tuple[int, int], int]:
            """
            Build the rule-2/8 lexicographic sort key. Higher
            tuples win under descending sort.
            """

            src_scope = ip4_address_scope(src)
            if src_scope >= dst_scope:
                rule2 = (1, -src_scope)
            else:
                rule2 = (0, src_scope)
            rule8 = common_prefix_len(src, ip4__dst)
            return (rule2, rule8)

        candidates.sort(key=sort_key, reverse=True)
        return candidates[0]

    def __validate_dst_ip4_address(
        self,
        *,
        ip4__dst: Ip4Address,
        tracker: Tracker,
    ) -> Ip4Address | TxStatus:
        """
        Make sure destination ip address is valid.
        """

        # Drop packet if the destination address is unspecified.
        if ip4__dst.is_unspecified:
            self._if._packet_stats_tx.ip4__dst_unspecified__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Destination address is unspecified, " "dropping</>",
            )
            return TxStatus.DROPPED__IP4__DST_UNSPECIFIED

        return ip4__dst

    def send_ip4_packet(
        self,
        *,
        ip4__local_address: Ip4Address,
        ip4__remote_address: Ip4Address,
        ip4__proto: IpProto,
        ip4__payload: bytes = bytes(),
        ip4__ttl: int | None = None,
        ip4__ecn: int = 0,
        ip4__dscp: int = 0,
        ip4__options: Ip4Options | None = None,
    ) -> None:
        """
        Interface method for RAW Socket -> Packet Assembler
        communication. Handed to the TX worker fire-and-forget via
        '_marshal_tx_async' (Phase 4b): the calling app thread does
        not block for the 'TxStatus'.

        'ip4__options' threads the socket's IP_OPTIONS block (RFC
        1122 §4.1.3.2) onto the outbound header; 'None' emits a
        plain header.
        """

        kwargs: dict[str, Any] = {
            "ip4__src": ip4__local_address,
            "ip4__dst": ip4__remote_address,
            "ip4__payload": RawAssembler(
                raw__payload=ip4__payload,
                ip_proto=ip4__proto,
            ),
            "ip4__ecn": ip4__ecn,
            "ip4__dscp": ip4__dscp,
        }
        if ip4__ttl is not None:
            kwargs["ip4__ttl"] = ip4__ttl
        if ip4__options is not None:
            kwargs["ip4__options"] = ip4__options
        self._if._marshal_tx_async(lambda: self._phtx_ip4(**kwargs))

    def __send_out_packet(
        self,
        ip4_packet_tx: Ip4Assembler | Ip4FragAssembler,
    ) -> None:
        assert self._if._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._if._tx_ring.enqueue(ip4_packet_tx)
