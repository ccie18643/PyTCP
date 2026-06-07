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
This module contains packet handler for the inbound IPv6 packets.

pytcp/runtime/packet_handler/packet_handler__ip6__rx.py

ver 3.0.8
"""

import time as time_module
from typing import TYPE_CHECKING

from net_proto import (
    Icmp6MessageParameterProblem,
    Icmp6ParameterProblemCode,
    Ip6Parser,
    Ip6SanityError,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import (
    Ip6DestOptsIntegrityError,
    Ip6DestOptsSanityError,
)
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__parser import (
    Ip6DestOptsParser,
)
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import (
    Ip6HbhIntegrityError,
    Ip6HbhSanityError,
)
from net_proto.protocols.ip6_hbh.ip6_hbh__parser import Ip6HbhParser
from net_proto.protocols.ip6_routing.ip6_routing__errors import (
    Ip6RoutingIntegrityError,
)
from net_proto.protocols.ip6_routing.ip6_routing__parser import Ip6RoutingParser
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.icmp.icmp__error_emitter import try_emit_icmp_error
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound
from pytcp.protocols.ip6.ip6__ext_hdr_limits import (
    Ip6ExtHdrCapViolation,
    check_ext_hdr_option_caps,
)
from pytcp.runtime.socket.raw__metadata import RawMetadata
from pytcp.runtime.socket.raw__socket import RawSocket

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# RFC 8200 §4.1 — IPv6 extension headers walked in chain order.
_IP6_EXTENSION_HEADERS: frozenset[IpProto] = frozenset(
    {
        IpProto.IP6_HBH,
        IpProto.IP6_ROUTING,
        IpProto.IP6_FRAG,
        IpProto.IP6_DEST_OPTS,
    }
)

# Offset of the IPv6 main header's Next Header field. Used as the
# Param Problem pointer when an unrecognized next header appears
# directly after the main IPv6 header (no extension headers walked).
_IP6__NEXT_HEADER__OFFSET = 6

# Length of the fixed IPv6 main header, used for absolute-pointer
# computation (extension-header offsets are added to this base).
_IP6__HEADER__LEN = 40


class Ip6RxHandler:
    """
    Packet handler for the inbound IPv6 packets.
    """

    _if: PacketHandler

    def __init__(self, *, interface: PacketHandler) -> None:
        """
        Initialize the IPv6 RX sub-handler.
        """

        self._if = interface

    def _forward_or_deliver_ip6(self, packet_rx: PacketRx, /) -> bool:
        """
        RFC 1812 §5.2.1 forward-or-deliver split for an inbound IPv6
        datagram (the host equivalent). Return True to deliver it up
        the local stack, False if the forward path consumed it.

        Phase 1 (host): deliver iff the destination is one of our
        addresses — unicast or joined multicast (which covers
        link-local, solicited-node, and the all-nodes group). Any
        other destination is not ours to deliver.

        # Phase 2: the forward branch runs the FIB next-hop lookup,
        # the Hop-Limit decrement + ICMPv6 Time-Exceeded on expiry,
        # and ICMPv6 Redirect generation. A host has no forwarding
        # plane, so it drops non-local datagrams here (counted in
        # 'ip6__dst_unknown__drop').
        """

        if packet_rx.ip6.dst in {*self._if._ip6_unicast, *self._if._ip6_multicast}:
            return True

        self._if._packet_stats_rx.ip6__dst_unknown__drop += 1
        __debug__ and log(
            "ip6",
            f"{packet_rx.tracker} - IP packet not destined for this stack; " "host does not forward, dropping",
        )
        return False

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound IPv6 packets.
        """

        self._if._packet_stats_rx.ip6__pre_parse += 1

        try:
            Ip6Parser(packet_rx)

        except Ip6SanityError as error:
            self._if._packet_stats_rx.ip6__failed_parse__drop += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            if error.pointer is not None:
                self.__phrx_ip6__emit_parameter_problem(packet_rx, error.pointer)
            return

        except PacketValidationError as error:
            self._if._packet_stats_rx.ip6__failed_parse__drop += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            return

        __debug__ and log("ip6", f"{packet_rx.tracker} - {packet_rx.ip6}")

        # RFC 1812 §5.2 forward-or-deliver decision (the IPv6 host
        # equivalent). Phase 1 delivers locally-addressed datagrams
        # and drops the rest; Phase 2 fills the forward branch — see
        # '_forward_or_deliver_ip6'. Keeping this a separable step is
        # the CLAUDE.md Phase-2 north-star constraint.
        if not self._forward_or_deliver_ip6(packet_rx):
            return

        if packet_rx.ip6.dst in self._if._ip6_unicast:
            self._if._packet_stats_rx.ip6__dst_unicast += 1

        if packet_rx.ip6.dst in self._if._ip6_multicast:
            self._if._packet_stats_rx.ip6__dst_multicast += 1

        # Create RawMetadata object and try to find matching RAW socket.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=packet_rx.ip6.next,
            ip__ttl=packet_rx.ip6.hop,
            raw__data=bytes(packet_rx.ip6.payload_bytes),  # memoryview: conversion for end-user interface.
            tracker=packet_rx.tracker,
        )

        # Linux 'raw6_local_deliver': clone the datagram to EVERY matching
        # RAW socket, then continue to the extension-header chain walker /
        # transport handler — raw delivery is a copy that does NOT consume.
        # 'raw_delivered' is the Linux 'raw' flag: it suppresses the
        # unrecognized-next-header Parameter Problem in the walker only
        # when no RAW socket received the datagram.
        raw_delivered = False
        delivered: set[int] = set()
        for socket_id in packet_rx_md.socket_ids:
            socket = stack.sockets.get(socket_id, None)
            if not isinstance(socket, RawSocket) or id(socket) in delivered:
                continue
            delivered.add(id(socket))
            self._if._packet_stats_rx.raw__socket_match += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
            )
            socket.process_raw_packet(packet_rx_md)
            raw_delivered = True

        self._phrx_ip6__walk_chain(packet_rx, raw_delivered=raw_delivered)

    def _phrx_ip6__walk_chain(self, packet_rx: PacketRx, /, *, raw_delivered: bool = False) -> None:
        """
        Walk the IPv6 extension-header chain in RFC 8200 §4.1 order.

        'raw_delivered' is the Linux 'raw' flag — when a RAW socket
        already received the datagram, the unrecognized-next-header
        Parameter Problem at the chain terminator is suppressed.

        The walker advances 'packet_rx.frame' through HBH / Routing /
        Frag / DestOpts in turn, applying each header's parser, and
        dispatches to the transport handler when the chain ends with
        a transport protocol. The Frag re-entry pattern is preserved
        verbatim — Frag handler reassembles and re-enters '_phrx_ip6'
        from the top with the synthetic reassembled packet.
        """

        current_next: IpProto = packet_rx.ip6.next
        # Running offset of the *next* header byte within the IPv6
        # packet, used for ICMPv6 Parameter Problem pointer arithmetic
        # when an extension-header parser raises with a relative offset.
        chain_offset: int = _IP6__HEADER__LEN
        # Whether at least one non-HBH extension header was processed —
        # gates RFC 8200 §4.3 "HBH MUST be first" enforcement.
        non_hbh_seen: bool = False

        while current_next in _IP6_EXTENSION_HEADERS:
            match current_next:
                case IpProto.IP6_HBH:
                    if non_hbh_seen:
                        # RFC 8200 §4.3: HBH must be the first extension
                        # header. Out-of-order HBH is a §4 unrecognized-
                        # next-header equivalent — emit Param Problem
                        # code 1 with pointer at this header byte.
                        self._if._packet_stats_rx.ip6__hbh__not_first__drop += 1
                        self.__phrx_ip6__emit_parameter_problem_unrecognized_next_header(
                            packet_rx, pointer=chain_offset
                        )
                        return
                    if not self._phrx_ip6_hbh(packet_rx, chain_offset=chain_offset):
                        return
                    chain_offset += (packet_rx.ip6_hbh.hdr_ext_len + 1) * 8
                    current_next = packet_rx.ip6_hbh.next
                case IpProto.IP6_ROUTING:
                    if not self._phrx_ip6_routing(packet_rx, chain_offset=chain_offset):
                        return
                    non_hbh_seen = True
                    chain_offset += (packet_rx.ip6_routing.hdr_ext_len + 1) * 8
                    current_next = packet_rx.ip6_routing.next
                case IpProto.IP6_FRAG:
                    self._if._phrx_ip6_frag(packet_rx)
                    return  # Frag handles re-entry on reassembly.
                case IpProto.IP6_DEST_OPTS:
                    if not self._phrx_ip6_dest_opts(packet_rx, chain_offset=chain_offset):
                        return
                    non_hbh_seen = True
                    chain_offset += (packet_rx.ip6_dest_opts.hdr_ext_len + 1) * 8
                    current_next = packet_rx.ip6_dest_opts.next

            # Re-anchor 'packet_rx.ip6._payload' onto the post-
            # extension-header frame so downstream transport
            # parsers (Icmp6Parser, UdpParser, TcpParser) see the
            # correct 'payload_len' / 'dlen' for THEIR header. The
            # parsers' integrity checks compare 'len(frame)' against
            # 'ip6.dlen'; without this mutation the dlen still
            # reflects the original IPv6 payload (including the
            # consumed extension headers) and the upper-bound check
            # trips on a chain-walked frame.
            packet_rx.ip6._payload = packet_rx.frame

        # Transport / chain-terminator dispatch. The IpProto ->
        # transport-handler demux goes through the per-interface
        # dispatch registry (ICMPv6 / UDP / TCP); the No-Next-Header
        # terminator and the unrecognized-next-header error path are
        # not registry handlers and stay inline below.
        handler = self._if._ip6_proto_registry.get(current_next)
        if handler is not None:
            handler(packet_rx)
        elif current_next is IpProto.IP6_NO_NEXT_HEADER:
            # RFC 8200 §4.7: chain terminator. Drop silently;
            # nothing to dispatch.
            self._if._packet_stats_rx.ip6__no_next_header += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - IP6_NO_NEXT_HEADER terminator, dropping silently.",
            )
        else:
            self._if._packet_stats_rx.ip6__no_proto_support__drop += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - Unsupported protocol {current_next}, dropping.",
            )
            if not raw_delivered:
                self.__phrx_ip6__emit_parameter_problem_unrecognized_next_header(packet_rx, pointer=chain_offset)

    def _phrx_ip6_hbh(self, packet_rx: PacketRx, /, *, chain_offset: int) -> bool:
        """
        Parse the IPv6 Hop-by-Hop Options extension header. Returns
        True on successful parse (chain walker may continue), False
        on parse error (chain walker must stop).
        """

        self._if._packet_stats_rx.ip6_hbh__pre_parse += 1
        try:
            Ip6HbhParser(packet_rx, ip6_dst_is_multicast=packet_rx.ip6.dst.is_multicast)
        except Ip6HbhIntegrityError as error:
            self._if._packet_stats_rx.ip6_hbh__failed_parse += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            return False
        except Ip6HbhSanityError as error:
            return self.__phrx_ip6__handle_options_sanity_error(
                packet_rx, error_pointer=error.pointer, chain_offset=chain_offset
            )
        # RFC 8504 §5.3 resource-exhaustion option-cap gate. Caps
        # are configurable via 'ip6.ext_hdr_max_*' sysctls.
        try:
            check_ext_hdr_option_caps(packet_rx.ip6_hbh.options)
        except Ip6ExtHdrCapViolation as error:
            self._if._packet_stats_rx.ip6_hbh__option_cap_exceeded__drop += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            return False
        return True

    def _phrx_ip6_routing(self, packet_rx: PacketRx, /, *, chain_offset: int) -> bool:
        """
        Parse the IPv6 Routing extension header. Catches the RFC 5095
        §3 RH0 hard-drop error (raised with a relative pointer) and
        emits ICMPv6 Parameter Problem code 0.
        """

        self._if._packet_stats_rx.ip6_routing__pre_parse += 1
        try:
            Ip6RoutingParser(packet_rx)
        except Ip6RoutingIntegrityError as error:
            self._if._packet_stats_rx.ip6_routing__failed_parse += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            if error.pointer is not None:
                # RFC 5095 §3: RH0 hard-drop emits Param Problem
                # code 0 (erroneous header field) with pointer at
                # the Routing Type byte.
                self._if._packet_stats_rx.ip6_routing__rh0__drop += 1
                self.__phrx_ip6__emit_parameter_problem(packet_rx, pointer=chain_offset + error.pointer)
            return False
        return True

    def _phrx_ip6_dest_opts(self, packet_rx: PacketRx, /, *, chain_offset: int) -> bool:
        """
        Parse the IPv6 Destination Options extension header.
        """

        self._if._packet_stats_rx.ip6_dest_opts__pre_parse += 1
        try:
            Ip6DestOptsParser(packet_rx, ip6_dst_is_multicast=packet_rx.ip6.dst.is_multicast)
        except Ip6DestOptsIntegrityError as error:
            self._if._packet_stats_rx.ip6_dest_opts__failed_parse += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            return False
        except Ip6DestOptsSanityError as error:
            return self.__phrx_ip6__handle_options_sanity_error(
                packet_rx, error_pointer=error.pointer, chain_offset=chain_offset
            )
        # RFC 8504 §5.3 resource-exhaustion option-cap gate. Caps
        # are configurable via 'ip6.ext_hdr_max_*' sysctls.
        try:
            check_ext_hdr_option_caps(packet_rx.ip6_dest_opts.options)
        except Ip6ExtHdrCapViolation as error:
            self._if._packet_stats_rx.ip6_dest_opts__option_cap_exceeded__drop += 1
            __debug__ and log("ip6", f"{packet_rx.tracker} - <CRIT>{error}</>")
            return False
        return True

    def __phrx_ip6__handle_options_sanity_error(
        self,
        packet_rx: PacketRx,
        /,
        *,
        error_pointer: int | None,
        chain_offset: int,
    ) -> bool:
        """
        Handle an HBH / DestOpts options-walker sanity error per RFC
        8200 §4.2 action-on-unrecognized:

          - 'pointer is None' → silent discard. Either action 01, or
            action 11 on a multicast destination (the options walker
            was given the destination's multicast bit and raised with
            'multicast_only=True' / no pointer per RFC 8200 §4.2).
          - 'pointer' set → discard + Param Problem code 2 (action 10
            for any destination, or action 11 on a unicast
            destination). The emit site flags the classifier so the
            RFC 4443 §2.4(e.3) exception (2) lets a code-2 Parameter
            Problem reach a multicast destination.

        Returns False unconditionally — the chain walker must stop on
        any options sanity error.
        """

        if error_pointer is not None:
            # The pointer the parser reported is the offset within the
            # options block. Translate to the absolute IPv6-packet
            # pointer: chain_offset (start of this extension header)
            # + 2 (skip Next Header + Hdr Ext Len) + error_pointer.
            absolute_pointer = chain_offset + 2 + error_pointer
            self.__phrx_ip6__emit_parameter_problem_unrecognized_option(packet_rx, pointer=absolute_pointer)
        return False

    def __phrx_ip6__emit_parameter_problem_unrecognized_next_header(
        self, packet_rx: PacketRx, /, *, pointer: int = _IP6__NEXT_HEADER__OFFSET
    ) -> None:
        """
        Emit ICMPv6 Parameter Problem code 1 (Unrecognized Next Header)
        in response to an inbound IPv6 datagram whose Next Header field
        designates a transport protocol the host does not implement,
        or whose extension-header chain places HBH out of position
        (RFC 8200 §4.3).

        Per RFC 8200 §4 the pointer field carries the byte offset of
        the offending Next Header within the IPv6 packet. The chain
        walker passes this offset; if not provided, defaults to 6
        (the offset of the IPv6 main header's Next Header field).

        Subject to the host-requirements gates and rate limit.

        Reference: RFC 8200 §4 (IPv6 node MUST send Param Problem
        code 1 on unrecognized Next Header).
        Reference: RFC 4443 §3.4 (Parameter Problem code 1 wire format).
        Reference: RFC 4443 §2.4(e/f) (gate + rate-limit requirements).
        """

        # No configured unicast IPv6 address: cannot emit because the
        # source-IP reflection from packet_rx.ip6.dst would not be a
        # valid stack address.
        if not self._if._ip6_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp6_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._if._packet_stats_rx.ip6__no_proto_support__icmp6_param_problem_suppressed += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv6 Unrecognized Next Header "
                f"to {packet_rx.ip6.src}: {verdict}</>",
            )
            return

        self._if._packet_stats_rx.ip6__no_proto_support__respond_icmp6_param_problem += 1
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp6(
                ip6__src=packet_rx.ip6.dst,
                ip6__dst=packet_rx.ip6.src,
                icmp6__message=Icmp6MessageParameterProblem(
                    code=Icmp6ParameterProblemCode.UNRECOGNIZED_NEXT_HEADER,
                    pointer=pointer,
                    data=packet_rx.ip.packet_bytes,
                ),
                echo_tracker=packet_rx.tracker,
            )
        )

    def __phrx_ip6__emit_parameter_problem_unrecognized_option(self, packet_rx: PacketRx, /, *, pointer: int) -> None:
        """
        Emit ICMPv6 Parameter Problem code 2 (Unrecognized IPv6 Option)
        in response to an HBH or DestOpts options-walker sanity error
        whose top-2-bit action-on-unrecognized code mandates ICMP per
        RFC 8200 §4.2.

        Subject to the host-requirements gates and rate limit.

        Reference: RFC 8200 §4.2 (action 10/11: discard + Param Problem code 2).
        Reference: RFC 4443 §3.4 (Parameter Problem code 2 wire format).
        """

        if not self._if._ip6_unicast:
            return

        # RFC 4443 §2.4(e.3) exception (2): a Parameter Problem code 2
        # (Unrecognized IPv6 Option) MAY be sent in response to a
        # packet destined to a multicast address — unlike most ICMPv6
        # errors, which §2.4(e.3) bars for multicast destinations.
        # Flag the classifier so the multicast-dst gate is bypassed
        # for this code only. (RFC 8200 §4.2 action-11 multicast
        # suppression is handled earlier, at the options-walker layer,
        # so an action-11 option on a multicast dst never reaches here.)
        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx, is_param_problem_code_2=True),
            rate_limiter=stack.icmp6_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._if._packet_stats_rx.ip6__sanity_error__icmp6_param_problem_suppressed += 1
            return

        self._if._packet_stats_rx.ip6__sanity_error__respond_icmp6_param_problem += 1
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp6(
                ip6__src=packet_rx.ip6.dst,
                ip6__dst=packet_rx.ip6.src,
                icmp6__message=Icmp6MessageParameterProblem(
                    code=Icmp6ParameterProblemCode.UNRECOGNIZED_IPV6_OPTION,
                    pointer=pointer,
                    data=packet_rx.ip.packet_bytes,
                ),
                echo_tracker=packet_rx.tracker,
            )
        )

    def __phrx_ip6__emit_parameter_problem(self, packet_rx: PacketRx, pointer: int) -> None:
        """
        Emit ICMPv6 Parameter Problem (Code 0, erroneous header field
        encountered) in response to an inbound IPv6 datagram whose
        header field at byte offset 'pointer' fails sanity validation,
        subject to the host-requirements gates and rate limit.

        Reference: RFC 1122 §3.2.2.5 (host SHOULD generate Param Problem).
        Reference: RFC 4443 §3.4 (Parameter Problem code 0 wire format).
        Reference: RFC 4443 §2.4(e/f) (gate + rate-limit requirements).
        """

        # No configured unicast IPv6 address: cannot emit because the
        # source-IP reflection from packet_rx.ip6.dst would not be a
        # valid stack address.
        if not self._if._ip6_unicast:
            return

        verdict = try_emit_icmp_error(
            classify_inbound(packet_rx),
            rate_limiter=stack.icmp6_error_rate_limiter,
            now=time_module.monotonic(),
        )
        if verdict is not None:
            self._if._packet_stats_rx.ip6__sanity_error__icmp6_param_problem_suppressed += 1
            __debug__ and log(
                "ip6",
                f"{packet_rx.tracker} - <WARN>Suppressing ICMPv6 Parameter Problem "
                f"to {packet_rx.ip6.src}: {verdict}</>",
            )
            return

        self._if._packet_stats_rx.ip6__sanity_error__respond_icmp6_param_problem += 1
        self._if._marshal_tx(
            lambda: self._if._phtx_icmp6(
                ip6__src=packet_rx.ip6.dst,
                ip6__dst=packet_rx.ip6.src,
                icmp6__message=Icmp6MessageParameterProblem(
                    code=Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
                    pointer=pointer,
                    data=packet_rx.ip.packet_bytes,
                ),
                echo_tracker=packet_rx.tracker,
            )
        )
