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
This module contains the 'IcmpTestCase' base class used by the
ICMP integration tests, layering ICMPv4 / ICMPv6 decode helpers and
fluent message-level assertions on top of 'NetworkTestCase'. Mirrors
the shape of 'TcpTestCase' so future ICMP-related work writes
fluent integration tests instead of byte-comparing TX frames against
hand-built golden buffers.

pytcp/tests/lib/icmp_testcase.py

ver 3.0.8
"""

from dataclasses import dataclass
from typing import Any, cast, override
from unittest.mock import _patch, patch

from net_addr import Ip4Address, Ip6Address, MacAddress
from net_proto import (
    Icmp4Message,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp4Parser,
    Icmp6Message,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6Parser,
)
from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.protocols.tcp.tcp__stack import TcpStack
from pytcp.runtime.timer import Timer
from pytcp.tests.lib.fake_timer import FakeTimer
from pytcp.tests.lib.network_testcase import NetworkTestCase

# Sentinel used by the '_assert_icmp*_message' helpers to distinguish
# "caller supplied no expected value, skip this check" from "caller
# explicitly asserted the field is None". Plain 'None' is ambiguous
# because some fields ('icmp_id', 'icmp_seq', 'icmp_mtu',
# 'icmp_target') legitimately use 'None' to mean "not applicable for
# this message type".
_UNSET: object = object()


@dataclass(frozen=True, slots=True)
class Icmp4Probe:
    """
    Decoded snapshot of a single Ethernet/IPv4/ICMPv4 frame produced by
    the stack under test, used by 'IcmpTestCase' assertions.
    """

    eth_src: MacAddress
    eth_dst: MacAddress
    ip_src: Ip4Address
    ip_dst: Ip4Address
    ip_ttl: int
    ip_id: int
    ip_dscp: int
    ip_ecn: int
    # RFC 791 IPv4 flags / fragment offset. 'ip_df' becomes the
    # canonical observable for the upcoming "DF=1 default on outbound
    # IPv4" change (see icmp_demux_pmtud_plan.md Phase 8).
    ip_df: bool
    ip_mf: bool
    ip_offset: int
    icmp_type: int
    icmp_code: int
    # Echo Request / Reply identifier and sequence; None for non-echo
    # message types.
    icmp_id: int | None
    icmp_seq: int | None
    # RFC 1191 §4 Frag-Needed link MTU; None when the message does not
    # carry one.
    icmp_mtu: int | None
    # Echo data payload OR the embedded "data" field of an error
    # message (original IP header + first 8 octets of L4 per RFC 792).
    icmp_data: bytes
    # Parsed message object — exposes message-type-specific fields
    # (e.g. NA flag_r/flag_s/flag_o, RA options, MLD2 records) without
    # forcing the probe to enumerate every variant. Tests pull
    # whatever fields they need.
    message: Icmp4Message


@dataclass(frozen=True, slots=True)
class Icmp6Probe:
    """
    Decoded snapshot of a single Ethernet/IPv6/ICMPv6 frame produced by
    the stack under test, used by 'IcmpTestCase' assertions.
    """

    eth_src: MacAddress
    eth_dst: MacAddress
    ip_src: Ip6Address
    ip_dst: Ip6Address
    ip_hop: int
    ip_dscp: int
    ip_ecn: int
    ip_flow: int
    icmp_type: int
    icmp_code: int
    icmp_id: int | None
    icmp_seq: int | None
    # RFC 4443 §3.2 Packet-Too-Big MTU; None when the message does not
    # carry one. Will start carrying decoded values once Phase 4 of
    # the refactor adds PacketTooBig message type support.
    icmp_mtu: int | None
    # ND target address for NS/NA; None for other message types.
    icmp_target: Ip6Address | None
    # Echo data payload OR the embedded "data" field of an error
    # message (original IPv6 header + first octets of payload per
    # RFC 4443 §3).
    icmp_data: bytes
    # Parsed message object — exposes message-type-specific fields
    # (e.g. NA flag_r/flag_s/flag_o, RA flag_m/flag_o/options/lifetime,
    # MLD2 records) without forcing the probe to enumerate every
    # variant. Tests pull whatever fields they need.
    message: Icmp6Message


class IcmpTestCase(NetworkTestCase):
    """
    Base class for ICMP-focused integration tests. Adds a deterministic
    'FakeTimer' replacement for 'stack.timer' on top of the parent
    mock-network setup, snapshot+clear+restore for the module-global
    'stack.tcp_stack' / 'stack.pmtu_cache' state so each test starts with
    a clean slate (the 'stack.sockets' table is snapshotted/cleared by the
    parent 'NetworkTestCase'), helpers to drive RX frames
    into the packet handler and capture the TX frames the stack
    emits, and ICMPv4 / ICMPv6 probe parsers for fluent message-level
    assertions.

    The 'stack.pmtu_cache' snapshot is a forward-compat hook: the
    attribute does not exist in the codebase yet (it lands in Phase 3
    of the ICMP demux + PMTUD refactor); 'setUp' / 'tearDown' guard
    on its presence so this harness can ship before the substrate.
    """

    _timer: FakeTimer
    _patches: list[_patch[Any]]
    _tcp_stack_prior: TcpStack
    _pmtu_cache_prior: dict[Any, Any]
    _pmtu_state_prior: dict[Any, Any]
    _icmp4_error_rate_limiter_prior: IcmpErrorRateLimiter
    _icmp6_error_rate_limiter_prior: IcmpErrorRateLimiter

    @override
    def setUp(self) -> None:
        """
        Install a 'FakeTimer' over 'stack.timer' on top of the parent
        mock-network setup, snapshot+clear the module-global
        'stack.tcp_stack' / 'stack.pmtu_cache' state so tests start with
        no leftover registrations, and initialize the patch tracking list
        so per-test 'mock.patch' handles get torn down deterministically.
        ('stack.sockets' is snapshotted/cleared by the parent
        'NetworkTestCase.setUp'.)
        """

        super().setUp()

        self._timer = FakeTimer()
        stack.mock__init(mock__timer=cast(Timer, self._timer))

        # 'stack.tcp_stack' aggregates per-stack TCP state. Replace
        # with a fresh instance so any registrations from earlier
        # tests do not leak into TCP-bearing ICMP demux test cases.
        self._tcp_stack_prior = stack.tcp_stack
        stack.tcp_stack = TcpStack()

        # 'stack.pmtu_cache' is the per-destination Path-MTU dict
        # used by the ICMP PMTUD callbacks (Phase 4 onward).
        self._pmtu_cache_prior = dict(stack.pmtu_cache)
        stack.pmtu_cache.clear()

        # 'stack.pmtu_state' is the unified PLPMTUD engine registry
        # added by Phase 2 of the PLPMTUD plan; snapshot/clear it
        # alongside the legacy pmtu_cache so tests start with no
        # leftover PmtuSearch instances and assertions on a per-
        # destination engine state stay isolated.
        self._pmtu_state_prior = dict(stack.pmtu_state)
        stack.pmtu_state.clear()

        # ICMP error rate limiters: snapshot the prior instances and
        # install fresh ones so each test starts with a full burst
        # quota and tests that exhaust the bucket cannot leak state
        # into unrelated tests.
        self._icmp4_error_rate_limiter_prior = stack.icmp4_error_rate_limiter
        stack.icmp4_error_rate_limiter = IcmpErrorRateLimiter()
        self._icmp6_error_rate_limiter_prior = stack.icmp6_error_rate_limiter
        stack.icmp6_error_rate_limiter = IcmpErrorRateLimiter()

        self._patches = []

    @override
    def tearDown(self) -> None:
        """
        Stop any 'mock.patch' handle started by '_start_patch', restore
        every snapshotted module-global to its pre-test value, then
        defer to the parent teardown so test-only state does not leak
        between tests.
        """

        while self._patches:
            self._patches.pop().stop()

        stack.tcp_stack = self._tcp_stack_prior

        stack.pmtu_cache.clear()
        stack.pmtu_cache.update(self._pmtu_cache_prior)

        stack.pmtu_state.clear()
        stack.pmtu_state.update(self._pmtu_state_prior)

        stack.icmp4_error_rate_limiter = self._icmp4_error_rate_limiter_prior
        stack.icmp6_error_rate_limiter = self._icmp6_error_rate_limiter_prior

        super().tearDown()

    def _start_patch(self, target: str, new: object) -> None:
        """
        Start a 'mock.patch' on 'target' replacing it with 'new' and
        register the patch so 'tearDown' stops it automatically.
        """

        handle = patch(target, new)
        handle.start()
        self._patches.append(handle)

    def _drive_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into 'PacketHandler._phrx_ethernet' and return the
        list of TX frames the stack produced as a direct result.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def _advance(self, *, ms: int) -> list[bytes]:
        """
        Advance the virtual clock by 'ms' milliseconds and return the
        list of TX frames produced during the tick.
        """

        before = len(self._frames_tx)
        self._timer.advance(ms)
        return list(self._frames_tx[before:])

    def _parse_tx_icmp4(self, frame: bytes, /) -> Icmp4Probe:
        """
        Parse a TX frame back into an 'Icmp4Probe' covering the IPv4
        and ICMPv4 fields the integration tests need to assert on.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        if packet_rx.ethernet.type is not EtherType.IP4:
            raise AssertionError(
                f"_parse_tx_icmp4: expected EtherType.IP4 in TX frame, got {packet_rx.ethernet.type!r}",
            )

        Ip4Parser(packet_rx)
        Icmp4Parser(packet_rx)

        message = packet_rx.icmp4.message
        icmp_id: int | None = None
        icmp_seq: int | None = None
        icmp_mtu: int | None = None
        icmp_data: bytes = b""

        if isinstance(message, (Icmp4MessageEchoRequest, Icmp4MessageEchoReply)):
            icmp_id = message.id
            icmp_seq = message.seq
            icmp_data = bytes(message.data)
        elif isinstance(message, Icmp4MessageDestinationUnreachable):
            icmp_mtu = message.mtu
            icmp_data = bytes(message.data)

        return Icmp4Probe(
            eth_src=packet_rx.ethernet.src,
            eth_dst=packet_rx.ethernet.dst,
            ip_src=packet_rx.ip4.src,
            ip_dst=packet_rx.ip4.dst,
            ip_ttl=packet_rx.ip4.ttl,
            ip_id=packet_rx.ip4.id,
            ip_dscp=packet_rx.ip4.dscp,
            ip_ecn=packet_rx.ip4.ecn,
            ip_df=packet_rx.ip4.flag_df,
            ip_mf=packet_rx.ip4.flag_mf,
            ip_offset=packet_rx.ip4.offset,
            icmp_type=int(message.type),
            icmp_code=int(message.code),
            icmp_id=icmp_id,
            icmp_seq=icmp_seq,
            icmp_mtu=icmp_mtu,
            icmp_data=icmp_data,
            message=message,
        )

    def _parse_tx_icmp6(self, frame: bytes, /) -> Icmp6Probe:
        """
        Parse a TX frame back into an 'Icmp6Probe' covering the IPv6
        and ICMPv6 fields the integration tests need to assert on.

        The ICMPv6 parser's '_validate_sanity' step enforces RX-side
        invariants (e.g. RFC 4861 §6.1.2 requires the RA source to be
        link-local). The codebase emits some TX frames that would fail
        these RX-only sanity rules — the canonical Router Advertisement
        emission uses the global stack address as source. To let
        integration tests inspect those frames without triggering the
        RX-only checks, the parse is performed with '_validate_sanity'
        monkey-patched to a no-op.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        if packet_rx.ethernet.type is not EtherType.IP6:
            raise AssertionError(
                f"_parse_tx_icmp6: expected EtherType.IP6 in TX frame, got {packet_rx.ethernet.type!r}",
            )

        Ip6Parser(packet_rx)

        # Walk past any Hop-by-Hop Options extension header (e.g. the
        # HBH+RouterAlert wrapper used on outbound MLDv2 reports per
        # RFC 3810 §5 + RFC 2711). Other extension-header types are
        # not currently emitted by PyTCP's TX path; if one appears
        # here we let the parser raise so we surface the gap loudly.
        hbh_seen = packet_rx.ip6.next is IpProto.IP6_HBH
        if hbh_seen:
            from net_proto.protocols.ip6_hbh.ip6_hbh__parser import Ip6HbhParser

            Ip6HbhParser(packet_rx)

        # Icmp6Parser's '_validate_integrity' compares the parsed
        # IPv6 dlen against 'len(frame)'; for chain-walked frames
        # the latter has already been advanced past the consumed
        # extension headers so the upper-bound check trips. Patch
        # it to a no-op when an extension header was consumed —
        # the on-the-wire frame integrity has already been verified
        # by the upstream IPv6 + extension-header parsers.
        with patch.object(Icmp6Parser, "_validate_sanity", lambda _self: None):
            if hbh_seen:
                with patch.object(Icmp6Parser, "_validate_integrity", lambda _self: None):
                    Icmp6Parser(packet_rx)
            else:
                Icmp6Parser(packet_rx)

        message = packet_rx.icmp6.message
        icmp_id: int | None = None
        icmp_seq: int | None = None
        icmp_mtu: int | None = None
        icmp_target: Ip6Address | None = None
        icmp_data: bytes = b""

        if isinstance(message, (Icmp6MessageEchoRequest, Icmp6MessageEchoReply)):
            icmp_id = message.id
            icmp_seq = message.seq
            icmp_data = bytes(message.data)
        elif isinstance(message, Icmp6MessageDestinationUnreachable):
            icmp_data = bytes(message.data)
        elif isinstance(
            message,
            (
                Icmp6NdMessageNeighborSolicitation,
                Icmp6NdMessageNeighborAdvertisement,
            ),
        ):
            icmp_target = message.target_address

        return Icmp6Probe(
            eth_src=packet_rx.ethernet.src,
            eth_dst=packet_rx.ethernet.dst,
            ip_src=packet_rx.ip6.src,
            ip_dst=packet_rx.ip6.dst,
            ip_hop=packet_rx.ip6.hop,
            ip_dscp=packet_rx.ip6.dscp,
            ip_ecn=packet_rx.ip6.ecn,
            ip_flow=packet_rx.ip6.flow,
            icmp_type=int(message.type),
            icmp_code=int(message.code),
            icmp_id=icmp_id,
            icmp_seq=icmp_seq,
            icmp_mtu=icmp_mtu,
            icmp_target=icmp_target,
            icmp_data=icmp_data,
            message=message,
        )

    def _assert_icmp4_message(
        self,
        probe: Icmp4Probe,
        *,
        type: object = _UNSET,
        code: object = _UNSET,
        id: object = _UNSET,
        seq: object = _UNSET,
        mtu: object = _UNSET,
        data: object = _UNSET,
        ip_src: object = _UNSET,
        ip_dst: object = _UNSET,
        ip_ttl: object = _UNSET,
        ip_id: object = _UNSET,
        ip_dscp: object = _UNSET,
        ip_ecn: object = _UNSET,
        ip_df: object = _UNSET,
        ip_mf: object = _UNSET,
        ip_offset: object = _UNSET,
        eth_src: object = _UNSET,
        eth_dst: object = _UNSET,
    ) -> None:
        """
        Assert that the given 'Icmp4Probe' matches every supplied
        field. Fields left at the '_UNSET' sentinel are not checked.
        Pass 'None' explicitly to assert that an optional field
        ('id', 'seq', 'mtu') is absent / not applicable for the
        message type.
        """

        if type is not _UNSET:
            self.assertEqual(
                probe.icmp_type,
                type,
                msg=f"Unexpected ICMPv4 type on outbound message: {probe!r}",
            )
        if code is not _UNSET:
            self.assertEqual(
                probe.icmp_code,
                code,
                msg=f"Unexpected ICMPv4 code on outbound message: {probe!r}",
            )
        if id is not _UNSET:
            self.assertEqual(
                probe.icmp_id,
                id,
                msg=f"Unexpected ICMPv4 id on outbound message: {probe!r}",
            )
        if seq is not _UNSET:
            self.assertEqual(
                probe.icmp_seq,
                seq,
                msg=f"Unexpected ICMPv4 seq on outbound message: {probe!r}",
            )
        if mtu is not _UNSET:
            self.assertEqual(
                probe.icmp_mtu,
                mtu,
                msg=f"Unexpected ICMPv4 mtu on outbound message: {probe!r}",
            )
        if data is not _UNSET:
            self.assertEqual(
                probe.icmp_data,
                data,
                msg=f"Unexpected ICMPv4 data on outbound message: {probe!r}",
            )
        if ip_src is not _UNSET:
            self.assertEqual(
                probe.ip_src,
                ip_src,
                msg=f"Unexpected IPv4 source on outbound ICMPv4: {probe!r}",
            )
        if ip_dst is not _UNSET:
            self.assertEqual(
                probe.ip_dst,
                ip_dst,
                msg=f"Unexpected IPv4 destination on outbound ICMPv4: {probe!r}",
            )
        if ip_ttl is not _UNSET:
            self.assertEqual(
                probe.ip_ttl,
                ip_ttl,
                msg=f"Unexpected IPv4 TTL on outbound ICMPv4: {probe!r}",
            )
        if ip_id is not _UNSET:
            self.assertEqual(
                probe.ip_id,
                ip_id,
                msg=f"Unexpected IPv4 Identification on outbound ICMPv4: {probe!r}",
            )
        if ip_dscp is not _UNSET:
            self.assertEqual(
                probe.ip_dscp,
                ip_dscp,
                msg=f"Unexpected IPv4 DSCP on outbound ICMPv4: {probe!r}",
            )
        if ip_ecn is not _UNSET:
            self.assertEqual(
                probe.ip_ecn,
                ip_ecn,
                msg=f"Unexpected IPv4 ECN on outbound ICMPv4: {probe!r}",
            )
        if ip_df is not _UNSET:
            self.assertEqual(
                probe.ip_df,
                ip_df,
                msg=f"Unexpected IPv4 DF flag on outbound ICMPv4: {probe!r}",
            )
        if ip_mf is not _UNSET:
            self.assertEqual(
                probe.ip_mf,
                ip_mf,
                msg=f"Unexpected IPv4 MF flag on outbound ICMPv4: {probe!r}",
            )
        if ip_offset is not _UNSET:
            self.assertEqual(
                probe.ip_offset,
                ip_offset,
                msg=f"Unexpected IPv4 fragment offset on outbound ICMPv4: {probe!r}",
            )
        if eth_src is not _UNSET:
            self.assertEqual(
                probe.eth_src,
                eth_src,
                msg=f"Unexpected Ethernet source on outbound ICMPv4: {probe!r}",
            )
        if eth_dst is not _UNSET:
            self.assertEqual(
                probe.eth_dst,
                eth_dst,
                msg=f"Unexpected Ethernet destination on outbound ICMPv4: {probe!r}",
            )

    def _assert_icmp6_message(
        self,
        probe: Icmp6Probe,
        *,
        type: object = _UNSET,
        code: object = _UNSET,
        id: object = _UNSET,
        seq: object = _UNSET,
        mtu: object = _UNSET,
        target: object = _UNSET,
        data: object = _UNSET,
        ip_src: object = _UNSET,
        ip_dst: object = _UNSET,
        ip_hop: object = _UNSET,
        ip_dscp: object = _UNSET,
        ip_ecn: object = _UNSET,
        ip_flow: object = _UNSET,
        eth_src: object = _UNSET,
        eth_dst: object = _UNSET,
    ) -> None:
        """
        Assert that the given 'Icmp6Probe' matches every supplied
        field. Fields left at the '_UNSET' sentinel are not checked.
        Pass 'None' explicitly to assert that an optional field
        ('id', 'seq', 'mtu', 'target') is absent / not applicable
        for the message type.
        """

        if type is not _UNSET:
            self.assertEqual(
                probe.icmp_type,
                type,
                msg=f"Unexpected ICMPv6 type on outbound message: {probe!r}",
            )
        if code is not _UNSET:
            self.assertEqual(
                probe.icmp_code,
                code,
                msg=f"Unexpected ICMPv6 code on outbound message: {probe!r}",
            )
        if id is not _UNSET:
            self.assertEqual(
                probe.icmp_id,
                id,
                msg=f"Unexpected ICMPv6 id on outbound message: {probe!r}",
            )
        if seq is not _UNSET:
            self.assertEqual(
                probe.icmp_seq,
                seq,
                msg=f"Unexpected ICMPv6 seq on outbound message: {probe!r}",
            )
        if mtu is not _UNSET:
            self.assertEqual(
                probe.icmp_mtu,
                mtu,
                msg=f"Unexpected ICMPv6 mtu on outbound message: {probe!r}",
            )
        if target is not _UNSET:
            self.assertEqual(
                probe.icmp_target,
                target,
                msg=f"Unexpected ICMPv6 ND target on outbound message: {probe!r}",
            )
        if data is not _UNSET:
            self.assertEqual(
                probe.icmp_data,
                data,
                msg=f"Unexpected ICMPv6 data on outbound message: {probe!r}",
            )
        if ip_src is not _UNSET:
            self.assertEqual(
                probe.ip_src,
                ip_src,
                msg=f"Unexpected IPv6 source on outbound ICMPv6: {probe!r}",
            )
        if ip_dst is not _UNSET:
            self.assertEqual(
                probe.ip_dst,
                ip_dst,
                msg=f"Unexpected IPv6 destination on outbound ICMPv6: {probe!r}",
            )
        if ip_hop is not _UNSET:
            self.assertEqual(
                probe.ip_hop,
                ip_hop,
                msg=f"Unexpected IPv6 hop limit on outbound ICMPv6: {probe!r}",
            )
        if ip_dscp is not _UNSET:
            self.assertEqual(
                probe.ip_dscp,
                ip_dscp,
                msg=f"Unexpected IPv6 DSCP on outbound ICMPv6: {probe!r}",
            )
        if ip_ecn is not _UNSET:
            self.assertEqual(
                probe.ip_ecn,
                ip_ecn,
                msg=f"Unexpected IPv6 ECN on outbound ICMPv6: {probe!r}",
            )
        if ip_flow is not _UNSET:
            self.assertEqual(
                probe.ip_flow,
                ip_flow,
                msg=f"Unexpected IPv6 flow label on outbound ICMPv6: {probe!r}",
            )
        if eth_src is not _UNSET:
            self.assertEqual(
                probe.eth_src,
                eth_src,
                msg=f"Unexpected Ethernet source on outbound ICMPv6: {probe!r}",
            )
        if eth_dst is not _UNSET:
            self.assertEqual(
                probe.eth_dst,
                eth_dst,
                msg=f"Unexpected Ethernet destination on outbound ICMPv6: {probe!r}",
            )

    def _assert_packet_stats_rx(self, *, exact: bool = True, **fields: int) -> None:
        """
        Assert that the live 'packet_handler.packet_stats_rx' state
        matches the supplied 'fields'.

        When 'exact' is True (default), every counter not in 'fields'
        must be zero — i.e. the test pins both the counters that
        SHOULD have incremented and the absence of any unrelated
        side-effect counters. When 'exact' is False, only the named
        counters are checked; other counters are allowed to be any
        value. The strict default mirrors the byte-equality behaviour
        of the legacy parametrized integration tests, so migrating
        cases onto this helper does not silently lose coverage.
        """

        actual = self._packet_handler.packet_stats_rx
        if exact:
            expected = PacketStatsRx(**fields)
            self.assertEqual(
                actual,
                expected,
                msg=(
                    f"Unexpected packet_stats_rx (exact match required, "
                    f"unspecified counters must be zero). Expected: {expected!r} "
                    f"Got: {actual!r}"
                ),
            )
            return

        for name, value in fields.items():
            self.assertEqual(
                getattr(actual, name),
                value,
                msg=f"Unexpected packet_stats_rx.{name}: expected {value!r}, got {getattr(actual, name)!r}",
            )

    def _assert_packet_stats_tx(self, *, exact: bool = True, **fields: int) -> None:
        """
        Assert that the live 'packet_handler.packet_stats_tx' state
        matches the supplied 'fields'. See '_assert_packet_stats_rx'
        for the 'exact' semantics — the strict default likewise
        mirrors the byte-equality regression net of the legacy
        parametrized integration tests.
        """

        actual = self._packet_handler.packet_stats_tx
        if exact:
            expected = PacketStatsTx(**fields)
            self.assertEqual(
                actual,
                expected,
                msg=(
                    f"Unexpected packet_stats_tx (exact match required, "
                    f"unspecified counters must be zero). Expected: {expected!r} "
                    f"Got: {actual!r}"
                ),
            )
            return

        for name, value in fields.items():
            self.assertEqual(
                getattr(actual, name),
                value,
                msg=f"Unexpected packet_stats_tx.{name}: expected {value!r}, got {getattr(actual, name)!r}",
            )

    def _assert_no_tx(self) -> None:
        """
        Assert that no TX frames have been recorded since the last
        explicit drain (tests that drain via '_drive_rx' / '_advance'
        get a fresh list back; this method checks the global slot).
        """

        self.assertEqual(
            self._frames_tx,
            [],
            msg=f"Expected no TX frames, got {len(self._frames_tx)}: {self._frames_tx!r}",
        )
