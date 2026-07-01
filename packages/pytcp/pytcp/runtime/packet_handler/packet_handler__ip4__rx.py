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
This module contains packet handler for the inbound IPv4 packets.

pytcp/runtime/packet_handler/packet_handler__ip4__rx.py

ver 3.0.8
"""

import struct
import time as time_module
from typing import TYPE_CHECKING

from net_proto import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageParameterProblem,
    Icmp4ParameterProblemCode,
    Ip4Parser,
    Ip4SanityError,
    PacketRx,
    PacketValidationError,
    inet_cksum,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.protocols.ip.ip_frag import IpFragFlowId
from pytcp.protocols.ip.ip_frag_table import IpFragAddOutcome
from pytcp.runtime.socket.raw__metadata import RawMetadata
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.stack import sysctl_iface

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler


class Ip4RxHandler:
    """
    Packet handler for the inbound IPv4 packets.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv4 RX sub-handler.
        """

        self._if = interface

    def _forward_or_deliver_ip4(self, packet_rx: PacketRx, /) -> bool:
        """
        RFC 1812 §5.2.1 forward-or-deliver split for an inbound IPv4
        datagram. Return True to deliver it up the local stack, False
        if the forward path consumed it.

        Phase 1 (host): deliver iff the destination is one of our
        addresses — unicast, joined multicast, or broadcast — or no
        unicast is configured yet (the DHCP-client accept-all
        bootstrap, where the OFFER / ACK arrive before an address is
        claimed). Any other destination is not ours to deliver.

        # Phase 2: the forward branch runs the FIB next-hop lookup,
        # the TTL decrement + ICMPv4 Time-Exceeded on expiry, and the
        # ICMPv4 Redirect generation. A host has no forwarding plane,
        # so it drops non-local datagrams here (counted in
        # 'ip4__dst_unknown__drop'; the forward-specific counter lands
        # with the forwarding plane).
        """

        if self._if._accepts_local_dst_ip4(packet_rx.ip4.dst):
            return True

        self._if._packet_stats_rx.ip4__dst_unknown__drop += 1
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - IP packet not destined for this stack; " "host does not forward, dropping",
        )
        return False

    def _phrx_ip4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv4 packets.
        """

        self._if._packet_stats_rx.ip4__pre_parse += 1

        try:
            Ip4Parser(packet_rx)

        except Ip4SanityError as error:
            self._if._packet_stats_rx.ip4__failed_parse__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            if error.pointer is not None:
                self.__phrx_ip4__emit_parameter_problem(packet_rx, error.pointer)
            return

        except PacketValidationError as error:
            self._if._packet_stats_rx.ip4__failed_parse__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("ip4", f"{packet_rx.tracker} - {packet_rx.ip4}")

        # Source-route gate: drop inbound packets carrying LSRR or
        # SSRR options unless the per-interface
        # 'ip4.<iface>.accept_source_route' sysctl is True.
        # Default False matches Linux's
        # 'net.ipv4.conf.<iface>.accept_source_route' default and
        # closes an attack surface that the LSRR/SSRR echo support
        # otherwise widens — the Echo Reply path stays in place
        # for operators that explicitly opt in.
        accept_source_route = sysctl_iface.get_for_iface(
            "ip4.accept_source_route",
            self._if._interface_name,
        )
        if not accept_source_route and (packet_rx.ip4.lsrr is not None or packet_rx.ip4.ssrr is not None):
            self._if._packet_stats_rx.ip4__source_route__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Dropping source-routed IPv4 packet "
                f"from {packet_rx.ip4.src} (ip4.accept_source_route=False)</>",
            )
            return

        # Martian source filter: drop inbound packets whose source
        # address is the directed broadcast of a locally configured
        # subnet (RFC 1122 §3.2.1.3 — a source address MUST NOT be a
        # broadcast address). The limited-broadcast / multicast /
        # reserved cases are caught by the parser sanity check; this
        # gate covers the per-subnet directed-broadcast class that
        # requires '_ip4_ifaddr' state to recognise.
        if packet_rx.ip4.src in self._if._ip4_broadcast:
            self._if._packet_stats_rx.ip4__src_directed_broadcast__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Dropping IPv4 packet with "
                f"directed-broadcast source {packet_rx.ip4.src} (martian source)</>",
            )
            return

        # RFC 1812 §5.2 forward-or-deliver decision. Phase 1 (host)
        # delivers locally-addressed datagrams and drops the rest;
        # Phase 2 (router) fills the forward branch — see
        # '_forward_or_deliver_ip4'. Keeping this a separable step is
        # the CLAUDE.md Phase-2 north-star constraint.
        if not self._forward_or_deliver_ip4(packet_rx):
            return

        if packet_rx.ip4.dst in self._if._ip4_unicast:
            self._if._packet_stats_rx.ip4__dst_unicast += 1

        if packet_rx.ip4.dst in self._if._ip4_multicast:
            self._if._packet_stats_rx.ip4__dst_multicast += 1

        if packet_rx.ip4.dst in self._if._ip4_broadcast:
            self._if._packet_stats_rx.ip4__dst_broadcast += 1

        # Check if packet is a fragment and if so process it accordingly.
        if packet_rx.ip4.offset != 0 or packet_rx.ip4.flag_mf:
            self._if._packet_stats_rx.ip4__frag += 1
            if not (defragmented_packet_rx := self.__defragment_ip4_packet(packet_rx)):
                return
            packet_rx = defragmented_packet_rx
            self._if._packet_stats_rx.ip4__defrag += 1

        # Create RawMetadata object and try to find matching RAW socket.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=packet_rx.ip4.proto,
            ip__ttl=packet_rx.ip4.ttl,
            # Linux 'SOCK_RAW' delivers the FULL IPv4 packet (header +
            # payload) to the application on receive -- unlike IPv6 raw,
            # which delivers payload only. Prepend the on-wire IPv4 header
            # so 'recv' / 'recvfrom' match the kernel.
            raw__data=bytes(packet_rx.ip4.header_bytes) + bytes(packet_rx.ip4.payload_bytes),
            tracker=packet_rx.tracker,
        )

        # Linux 'raw_local_deliver': clone the datagram to EVERY matching
        # RAW socket, then continue to the normal transport handler — raw
        # delivery is a copy that does NOT consume. 'raw_delivered' is the
        # Linux 'raw' flag: it suppresses the Protocol Unreachable below
        # only when no RAW socket received the datagram.
        raw_delivered = False
        delivered: set[int] = set()
        for socket_id in packet_rx_md.socket_ids:
            socket = stack.sockets.get(socket_id, None)
            if not isinstance(socket, RawSocket) or id(socket) in delivered:
                continue
            # RFC 3376 §3.1 data-plane source-delivery filter (Linux
            # 'ip_mc_sf_allow' in raw_v4_input): a matched RAW socket whose
            # source filter rejects the datagram's source is skipped — it
            # does not receive the datagram, but delivery to other matching
            # sockets and the transport handler still proceeds.
            if packet_rx.ip4.dst.is_multicast and not socket.ip4_multicast_source_admits(
                ifindex=self._if._ifindex, group=packet_rx.ip4.dst, source=packet_rx.ip4.src
            ):
                self._if._packet_stats_rx.raw__multicast_source_filtered__drop += 1
                continue
            delivered.add(id(socket))
            self._if._packet_stats_rx.raw__socket_match += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
            )
            socket.process_raw_packet(packet_rx_md)
            raw_delivered = True

        # IpProto -> transport-handler demux via the per-interface
        # dispatch registry (ICMPv4 / UDP / TCP). A registry miss is an
        # unsupported transport protocol — RFC 1122 §3.2.2.1 Protocol
        # Unreachable, suppressed when a RAW socket already received the
        # datagram (Linux 'raw' flag).
        handler = self._if._ip4_proto_registry.get(packet_rx.ip4.proto)
        if handler is None:
            self._if._packet_stats_rx.ip4__no_proto_support__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - Unsupported protocol " f"{packet_rx.ip4.proto}, dropping.",
            )
            if not raw_delivered:
                self.__phrx_ip4__emit_protocol_unreachable(packet_rx)
            return
        handler(packet_rx)

    def __phrx_ip4__emit_protocol_unreachable(self, packet_rx: PacketRx) -> None:
        """
        Emit ICMPv4 Destination Unreachable code 2 (Protocol
        Unreachable) in response to an inbound IPv4 datagram whose
        'proto' field designates a transport protocol the host does
        not implement, subject to the host-requirements gates and
        rate limit.

        Reference: RFC 1122 §3.2.2.1 (host SHOULD generate Code 2).
        Reference: RFC 1122 §3.2.2 (gates: bcast/mcast destination,
        non-initial fragment, invalid source).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        # DHCP-client mode: no configured unicast IPv4 address. Cannot
        # emit ICMP errors because the source-IP reflection from
        # packet_rx.ip4.dst would not be a valid stack address.
        if not self._if._ip4_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp4_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._if._packet_stats_rx.ip4__no_proto_support__icmp4_unreachable_suppressed += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv4 Protocol Unreachable "
                f"to {packet_rx.ip4.src}: {verdict}</>",
            )
            return

        self._if._packet_stats_rx.ip4__no_proto_support__respond_icmp4_unreachable += 1
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp4(
                ip4__src=packet_rx.ip4.dst,
                ip4__dst=packet_rx.ip4.src,
                icmp4__message=Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PROTOCOL,
                    data=packet_rx.ip.packet_bytes,
                ),
                echo_tracker=packet_rx.tracker,
            )
        )

    def __phrx_ip4__emit_parameter_problem(self, packet_rx: PacketRx, pointer: int) -> None:
        """
        Emit ICMPv4 Parameter Problem (Code 0) in response to an
        inbound IPv4 datagram whose header field at byte offset
        'pointer' fails sanity validation, subject to the host-
        requirements gates and rate limit.

        Reference: RFC 1122 §3.2.2.5 (host SHOULD generate Param Problem).
        Reference: RFC 792 (Parameter Problem pointer).
        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP error generation).
        """

        # DHCP-client mode: no configured unicast IPv4 address. Cannot
        # emit ICMP errors because the source-IP reflection from
        # packet_rx.ip4.dst would not be a valid stack address.
        if not self._if._ip4_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp4_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._if._packet_stats_rx.ip4__sanity_error__icmp4_param_problem_suppressed += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv4 Parameter Problem "
                f"to {packet_rx.ip4.src}: {verdict}</>",
            )
            return

        self._if._packet_stats_rx.ip4__sanity_error__respond_icmp4_param_problem += 1
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp4(
                ip4__src=packet_rx.ip4.dst,
                ip4__dst=packet_rx.ip4.src,
                icmp4__message=Icmp4MessageParameterProblem(
                    code=Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
                    pointer=pointer,
                    data=packet_rx.ip.packet_bytes,
                ),
                echo_tracker=packet_rx.tracker,
            )
        )

    def __defragment_ip4_packet(self, packet_rx: PacketRx) -> PacketRx | None:
        """
        Defragment IPv4 packet.
        """

        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - IPv4 packet fragment, offset "
            f"{packet_rx.ip4.offset}, dlen {packet_rx.ip4.payload_len}"
            f"{'' if packet_rx.ip4.flag_mf else ', last'}",
        )

        result = self._if._ip4_frag_table.add_fragment(
            flow_id=IpFragFlowId(
                src=packet_rx.ip4.src,
                dst=packet_rx.ip4.dst,
                id=packet_rx.ip4.id,
                proto=packet_rx.ip4.proto,
            ),
            offset=packet_rx.ip4.offset,
            payload=packet_rx.ip4.payload_bytes,
            flag_mf=packet_rx.ip4.flag_mf,
            # Pass the full IHL-bounded header (base + options)
            # so RFC 815 §6 option preservation works on
            # reassembly. 'header_bytes' returns only the base
            # 20 bytes; 'packet_bytes[:hlen]' captures options.
            header=packet_rx.ip4.packet_bytes[: packet_rx.ip4.hlen],
            ecn=packet_rx.ip4.ecn,
        )
        if result.outcome in (IpFragAddOutcome.OVERLAP, IpFragAddOutcome.DISCARDED):
            self._if._packet_stats_rx.ip4__frag__overlap__drop += 1
            return None
        if result.outcome is IpFragAddOutcome.ECN_MIXED__DROP:
            self._if._packet_stats_rx.ip4__frag__ecn_mixed__drop += 1
            __debug__ and log(
                "ip4",
                f"{packet_rx.tracker} - <WARN>Dropping reassembled IPv4 datagram: "
                f"fragments carry inconsistent ECN bits (RFC 3168 §5.3)</>",
            )
            return None
        if result.outcome is not IpFragAddOutcome.COMPLETE:
            return None
        header_bytes = result.header
        payload = result.payload

        # Reassembled IPv4 header rewrite: preserve the first
        # fragment's IHL + options per RFC 815 §6 (the first
        # fragment carries the canonical options for the
        # reassembled datagram); rewrite Total Length to
        # 'len(header) + len(payload)' so the options bytes are
        # accounted for; clear Flags / Fragment Offset; patch
        # the TOS byte to carry the RFC 3168 §5.3 aggregated
        # ECN (DSCP preserved from first fragment); recompute
        # Header Checksum.
        header = bytearray(header_bytes)
        header[1] = (header[1] & 0xFC) | (result.ecn & 0x03)
        struct.pack_into("!H", header, 2, len(header) + len(payload))
        header[6] = header[7] = header[10] = header[11] = 0
        struct.pack_into("!H", header, 10, inet_cksum(memoryview(header)))
        packet_rx = PacketRx(bytes(header) + payload)
        Ip4Parser(packet_rx)
        __debug__ and log(
            "ip4",
            f"{packet_rx.tracker} - Reasembled fragmented IPv4 packet, " f"dlen {len(payload)} bytes",
        )
        return packet_rx
