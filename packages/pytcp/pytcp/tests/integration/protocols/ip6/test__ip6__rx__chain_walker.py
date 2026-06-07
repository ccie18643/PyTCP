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
Integration tests for the IPv6 RX chain-walker dispatch.

Drives Ethernet/IPv6 frames carrying HBH / Routing / DestOpts /
NoNextHeader extension headers through 'PacketHandler._phrx_ethernet'
and asserts the chain walker's behaviour: parsers run, counters
update, and ICMPv6 Parameter Problem responses are emitted with
the correct codes and pointer offsets.

pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Buffer, Ip6Address
from net_proto import Icmp6MessageParameterProblem, IpProto
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

# Helpers to build test frames. Hand-crafted byte sequences are used
# for the extension-header content so the chain-walker behaviour can
# be exercised without depending on extension-header assemblers
# whose own tests already cover their wire format.


def _ethernet_ip6(
    *,
    ip6_payload: object,
    ip6_next: IpProto = IpProto.RAW,
    ip6_dst: Ip6Address | None = None,
) -> bytes:
    """
    Wrap any IPv6 assembler-style payload in Ethernet/IPv6 framing
    addressed from HOST_A to 'ip6_dst' (defaulting to the stack's
    unicast IPv6 address; pass a multicast group the stack has joined
    — e.g. the all-nodes 'ff02::1' — to exercise multicast-dst paths).

    Accepts either an existing assembler (used as the IPv6 payload
    directly so 'IpProto.from_proto' derives the Next Header field)
    or raw 'bytes' (wrapped in a 'RawAssembler' tagged with
    'ip6_next' so the Next Header field reflects the caller-chosen
    extension-header / transport type).
    """

    if isinstance(ip6_payload, (bytes, bytearray)):
        payload: object = RawAssembler(raw__payload=ip6_payload, ip_proto=ip6_next)
    else:
        payload = ip6_payload
    ip6 = Ip6Assembler(
        ip6__src=HOST_A__IP6_ADDRESS,
        ip6__dst=STACK__IP6_HOST.address if ip6_dst is None else ip6_dst,
        ip6__payload=payload,  # type: ignore[arg-type]
    )
    eth = EthernetAssembler(
        ethernet__src=HOST_A__MAC_ADDRESS,
        ethernet__dst=STACK__MAC_ADDRESS,
        ethernet__payload=ip6,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


def _build_hbh_then_unrecognized_next_frame() -> bytes:
    """
    Build Ethernet/IPv6/HBH(PadN)/<unsupported next header> — exercises
    the chain walker advancing past HBH and only THEN emitting Param
    Problem code 1 with the absolute pointer past the HBH region.
    """

    hbh = Ip6HbhAssembler(
        ip6_hbh__next=IpProto.from_int(142),  # unsupported transport
        ip6_hbh__options=Ip6HbhOptions(Ip6HbhOptionPadN(b"\x00\x00\x00\x00")),
        ip6_hbh__payload=b"opaque",
    )
    return _ethernet_ip6(ip6_payload=hbh)


def _build_rh0_frame() -> bytes:
    """
    Build Ethernet/IPv6 with the next-header chain set to Routing
    type=0 (RH0), which RFC 5095 §3 mandates the receiver hard-drop
    with Param Problem code 0 pointing at the Routing Type byte.
    """

    # Routing wire frame (8 bytes, header-only):
    #   Byte 0    : 0x06 -> next=TCP (irrelevant; RH0 dropped before parsing further)
    #   Byte 1    : 0x00 -> hdr_ext_len=0 (8-byte total)
    #   Byte 2    : 0x00 -> routing_type=RH0 (DEPRECATED)
    #   Byte 3    : 0x02 -> segments_left=2
    #   Bytes 4-7 : 00 00 00 00 -> reserved/unused
    rh0_bytes = b"\x06\x00\x00\x02\x00\x00\x00\x00"
    return _ethernet_ip6(ip6_payload=rh0_bytes, ip6_next=IpProto.IP6_ROUTING)


def _build_hbh_unknown_action_10_frame(*, ip6_dst: Ip6Address | None = None) -> bytes:
    """
    Build Ethernet/IPv6/HBH where the HBH options block contains an
    unrecognized option whose top-2-bit action code is 10 (discard +
    Param Problem). RFC 8200 §4.2 mandates an ICMPv6 Param Problem
    code 2 response. 'ip6_dst' selects a unicast (default) or
    multicast destination.
    """

    # HBH wire frame (8 bytes):
    #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
    #   Byte 2    : 0x85 -> unknown type, top-2-bits=10 (discard + ICMP)
    #   Byte 3    : 0x04 -> opt_data_len=4
    #   Bytes 4-7 : 00 00 00 00 -> data
    hbh_bytes = b"\x06\x00\x85\x04\x00\x00\x00\x00"
    return _ethernet_ip6(ip6_payload=hbh_bytes, ip6_next=IpProto.IP6_HBH, ip6_dst=ip6_dst)


def _build_hbh_unknown_action_11_frame(*, ip6_dst: Ip6Address | None = None) -> bytes:
    """
    Build Ethernet/IPv6/HBH where the HBH options block contains an
    unrecognized option whose top-2-bit action code is 11 (discard +
    Param Problem code 2 only when the destination is NOT multicast,
    RFC 8200 §4.2). 'ip6_dst' selects a unicast (default) or multicast
    destination.
    """

    # HBH wire frame (8 bytes):
    #   Bytes 0-1 : 06 00 -> next=TCP, hdr_ext_len=0
    #   Byte 2    : 0xc5 -> unknown type, top-2-bits=11 (discard + ICMP unless mcast)
    #   Byte 3    : 0x04 -> opt_data_len=4
    #   Bytes 4-7 : 00 00 00 00 -> data
    hbh_bytes = b"\x06\x00\xc5\x04\x00\x00\x00\x00"
    return _ethernet_ip6(ip6_payload=hbh_bytes, ip6_next=IpProto.IP6_HBH, ip6_dst=ip6_dst)


def _build_no_next_header_frame() -> bytes:
    """
    Build Ethernet/IPv6 with Next Header = 59 (No Next Header,
    RFC 8200 §4.7). Receiver must drop silently — no transport
    handler runs, no ICMPv6 emitted.
    """

    return _ethernet_ip6(ip6_payload=b"", ip6_next=IpProto.IP6_NO_NEXT_HEADER)


class TestIp6Rx__ChainWalker__Hbh(IcmpTestCase, TestCase):
    """
    The IPv6 RX chain walker — Hop-by-Hop Options dispatch tests.
    """

    def test__ip6__rx__hbh_pre_parse_counter_bumps(self) -> None:
        """
        Ensure an inbound IPv6 packet whose Next Header is HBH is
        parsed by the new chain walker (not rejected by the legacy
        unrecognized-next-header path). The 'ip6_hbh__pre_parse'
        counter must bump and the 'no_proto_support' counter must
        NOT bump for an HBH followed by an unrecognized transport.

        Reference: RFC 8200 §4.3 (Hop-by-Hop Options Extension Header).
        """

        self._drive_rx(frame=_build_hbh_then_unrecognized_next_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__pre_parse,
            1,
            msg="Chain walker must run the HBH parser exactly once.",
        )

    def test__ip6__rx__hbh_action_10_emits_param_problem_code_2(self) -> None:
        """
        Ensure an unrecognized HBH option whose top-2-bit action
        code is 10 elicits an ICMPv6 Parameter Problem code 2
        (Unrecognized IPv6 Option).

        Reference: RFC 8200 §4.2 (action 10: discard + Param Problem code 2).
        Reference: RFC 4443 §3.4 (Parameter Problem code 2 wire format).
        """

        frames_tx = self._drive_rx(frame=_build_hbh_unknown_action_10_frame())

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Action-10 HBH option must produce exactly one ICMPv6 error.",
        )
        probe = self._parse_tx_icmp6(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            4,
            msg=f"Outbound ICMPv6 must be Parameter Problem (type 4). Got: {probe.icmp_type}.",
        )
        self.assertEqual(
            probe.icmp_code,
            2,
            msg=f"Outbound ICMPv6 must be Unrecognized IPv6 Option (code 2). Got: {probe.icmp_code}.",
        )
        # Pointer is the absolute byte offset of the offending option
        # within the IPv6 packet:
        #   40 (IPv6 header) + 0 (HBH at chain start) + 2 (skip HBH
        #   Next Header + Hdr Ext Len) + 0 (option offset within HBH
        #   options block) = 42.
        assert isinstance(probe.message, Icmp6MessageParameterProblem)
        self.assertEqual(
            probe.message.pointer,
            42,
            msg=(
                f"Param Problem pointer must be 42 (40 IPv6 header + 2 HBH prefix "
                f"+ option offset 0). Got: {probe.message.pointer}."
            ),
        )

    def test__ip6__rx__hbh_action_11_unicast_emits_param_problem_code_2(self) -> None:
        """
        Ensure an unrecognized HBH option with action code 11 on a
        unicast-destined packet elicits an ICMPv6 Parameter Problem
        code 2 — the "discard + ICMP" half of the action-11 rule.

        Reference: RFC 8200 §4.2 (action 11: discard + Param Problem
        code 2 unless destination is multicast).
        """

        frames_tx = self._drive_rx(frame=_build_hbh_unknown_action_11_frame())

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Action-11 HBH option on a unicast dst must emit one ICMPv6 error.",
        )
        probe = self._parse_tx_icmp6(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            4,
            msg=f"Outbound ICMPv6 must be Parameter Problem (type 4). Got: {probe.icmp_type}.",
        )
        self.assertEqual(
            probe.icmp_code,
            2,
            msg=f"Outbound ICMPv6 must be Unrecognized IPv6 Option (code 2). Got: {probe.icmp_code}.",
        )

    def test__ip6__rx__hbh_action_10_multicast_emits_param_problem(self) -> None:
        """
        Ensure an unrecognized HBH option with action code 10 on a
        multicast-destined packet still emits an ICMPv6 Parameter
        Problem code 2 — action 10 has no multicast exception, and
        the code-2 Parameter Problem is the permitted exception to
        the no-ICMP-error-to-multicast rule.

        Reference: RFC 8200 §4.2 (action 10: discard + Param Problem
        regardless of destination).
        Reference: RFC 4443 §2.4 (e.3 exception 2: code-2 Param
        Problem may be sent in response to a multicast packet).
        """

        frames_tx = self._drive_rx(
            frame=_build_hbh_unknown_action_10_frame(ip6_dst=Ip6Address("ff02::1")),
        )

        self.assertEqual(
            len(frames_tx),
            1,
            msg=(
                "Action-10 HBH option on a multicast dst MUST still emit a "
                f"code-2 Param Problem (RFC 4443 §2.4 exception 2). Got {len(frames_tx)} frame(s)."
            ),
        )
        probe = self._parse_tx_icmp6(frames_tx[0])
        self.assertEqual(
            probe.icmp_code,
            2,
            msg=f"Outbound ICMPv6 must be Unrecognized IPv6 Option (code 2). Got: {probe.icmp_code}.",
        )

    def test__ip6__rx__hbh_action_11_multicast_suppresses_param_problem(self) -> None:
        """
        Ensure an unrecognized HBH option with action code 11 on a
        multicast-destined packet (the all-nodes 'ff02::1', which the
        stack has joined) is discarded WITHOUT emitting an ICMPv6
        Parameter Problem — the multicast-suppression half of the
        action-11 rule.

        Reference: RFC 8200 §4.2 (action 11: no ICMP when destination
        is a multicast address).
        """

        frames_tx = self._drive_rx(
            frame=_build_hbh_unknown_action_11_frame(ip6_dst=Ip6Address("ff02::1")),
        )

        self.assertEqual(
            len(frames_tx),
            0,
            msg=(
                "Action-11 HBH option on a multicast dst MUST be silently "
                f"discarded with no ICMPv6 error. Got {len(frames_tx)} frame(s)."
            ),
        )


class TestIp6Rx__ChainWalker__Rh0(IcmpTestCase, TestCase):
    """
    The IPv6 RX chain walker — Routing Type 0 hard-drop tests.
    """

    def test__ip6__rx__rh0_emits_param_problem_code_0(self) -> None:
        """
        Ensure a Type 0 Routing Header (RH0) is hard-dropped per RFC
        5095 §3 with an ICMPv6 Parameter Problem code 0 (Erroneous
        Header Field) response. The pointer must point at the
        Routing Type byte: absolute offset 42 (40 IPv6 main header
        + 2 within the Routing Header).

        Reference: RFC 5095 §3 (Type 0 Routing Header hard-drop).
        Reference: RFC 4443 §3.4 (Parameter Problem code 0 wire format).
        """

        frames_tx = self._drive_rx(frame=_build_rh0_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_routing__rh0__drop,
            1,
            msg="RH0 hard-drop counter must bump exactly once.",
        )
        self.assertEqual(
            len(frames_tx),
            1,
            msg="RH0 hard-drop must produce exactly one ICMPv6 error.",
        )
        probe = self._parse_tx_icmp6(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            4,
            msg=f"Outbound ICMPv6 must be Parameter Problem (type 4). Got: {probe.icmp_type}.",
        )
        self.assertEqual(
            probe.icmp_code,
            0,
            msg=f"Outbound ICMPv6 must be Erroneous Header Field (code 0). Got: {probe.icmp_code}.",
        )
        assert isinstance(probe.message, Icmp6MessageParameterProblem)
        self.assertEqual(
            probe.message.pointer,
            42,
            msg=(
                f"Param Problem pointer must be 42 (40 IPv6 header + 2 RH offset "
                f"of Routing Type byte). Got: {probe.message.pointer}."
            ),
        )


class TestIp6Rx__ChainWalker__NoNextHeader(IcmpTestCase, TestCase):
    """
    The IPv6 RX chain walker — No Next Header (terminator) tests.
    """

    def test__ip6__rx__no_next_header_silent_drop(self) -> None:
        """
        Ensure an IPv6 packet whose chain ends with Next Header = 59
        (No Next Header) is dropped silently — no transport handler
        runs, no ICMPv6 response is emitted.

        Reference: RFC 8200 §4.7 (No Next Header chain terminator).
        """

        frames_tx = self._drive_rx(frame=_build_no_next_header_frame())

        self.assertEqual(
            len(frames_tx),
            0,
            msg="IP6_NO_NEXT_HEADER must drop silently with no TX.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6__no_next_header,
            1,
            msg="ip6__no_next_header counter must bump exactly once.",
        )
