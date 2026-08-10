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
This module contains the 'Ip6TestCase' base class used by the
IPv6 integration tests, layering IPv6 frame builders, RX/TX
probe helpers, and source-selection plumbing on top of
'NetworkTestCase'.

pytcp/tests/lib/ip6_testcase.py

ver 3.0.10
"""

from dataclasses import dataclass
from typing import Any

from net_addr import Ip6Address, Ip6IfAddr, MacAddress
from net_proto import (
    EthernetAssembler,
    Ip6Assembler,
    Ip6Parser,
    IpProto,
    RawAssembler,
)
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP6_ADDRESS,
    HOST_C__IP6_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)


@dataclass(frozen=True, slots=True)
class Ip6Probe:
    """
    Decoded snapshot of a single Ethernet/IPv6 frame produced
    by the stack under test, used by 'Ip6TestCase' assertions.
    """

    ip_src: Ip6Address
    ip_dst: Ip6Address
    # RFC 8200 §3 Hop Limit.
    hop: int
    # RFC 2474 §3 DSCP (6 high bits of Traffic Class byte).
    dscp: int
    # RFC 3168 §5 ECN (low 2 bits of Traffic Class byte).
    ecn: int
    # RFC 6437 Flow Label (20-bit).
    flow_label: int
    # Next-header value (UDP / TCP / ICMP6 / HBH / etc.).
    next_header: IpProto
    # Application payload following the IPv6 header (no
    # extension-header walking — that's the chain walker's
    # job).
    payload: bytes


class Ip6TestCase(NetworkTestCase):
    """
    Base class for IPv6 integration tests. Adds IPv6 frame
    builders, an RX driver helper, and an 'Ip6Probe' TX parser
    for fluent assertions on outbound IPv6 frames. Source-
    selection tests use '_set_ip6_hosts' to populate the
    stack's owned-address list before exercising
    '_select_ip6_source'.

    IPv6-specific behaviour that depends on ICMPv6 machinery
    (PMTUD, flow-label generation gates, extension-header
    handling) should continue to use 'IcmpTestCase' instead —
    'Ip6TestCase' is for pure IPv6-layer tests (source
    selection, martian-source filtering, parser sanity
    drops, raw-frame TX assertions).
    """

    def _set_ip6_hosts(self, *hosts: Ip6IfAddr) -> None:
        """
        Replace the stack's '_ip6_ifaddr' list with the given
        hosts. Used by source-selection tests that exercise
        'Ip6TxHandler._select_ip6_source' against a controlled
        owned-address list.
        """

        self._packet_handler._ip6_ifaddr = list(hosts)

    def _drive_ip6_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into 'PacketHandler._phrx_ethernet' and
        return the list of TX frames the stack produced as a
        direct result. Mirrors
        'UdpTestCase._drive_udp_rx' / 'IcmpTestCase._drive_rx'
        for the IPv6 family.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def _build_ip6_frame(
        self,
        *,
        src: Ip6Address = HOST_A__IP6_ADDRESS,
        dst: Ip6Address | None = None,
        payload: Any = RawAssembler(),
        dscp: int = 0,
        ecn: int = 0,
        flow_label: int = 0,
        hop: int | None = None,
        ethernet_src: MacAddress = HOST_A__MAC_ADDRESS,
        ethernet_dst: MacAddress = STACK__MAC_ADDRESS,
    ) -> bytes:
        """
        Build an Ethernet/IPv6 frame on the canonical fixture
        4-tuple. Defaults: HOST_A → STACK with DSCP/ECN=0,
        flow_label=0, hop default (assembler picks). Override
        any kwarg for variant frames; 'payload' accepts any
        IPv6 payload assembler (UDP, TCP, ICMPv6, extension
        header, raw).
        """

        if dst is None:
            dst = STACK__IP6_HOST.address

        ip6_kwargs: dict[str, Any] = {
            "ip6__src": src,
            "ip6__dst": dst,
            "ip6__dscp": dscp,
            "ip6__ecn": ecn,
            "ip6__flow": flow_label,
            "ip6__payload": payload,
        }
        if hop is not None:
            ip6_kwargs["ip6__hop"] = hop

        return bytes(
            EthernetAssembler(
                ethernet__src=ethernet_src,
                ethernet__dst=ethernet_dst,
                ethernet__payload=Ip6Assembler(**ip6_kwargs),
            )
        )

    def _parse_tx_ip6(self, frame: bytes, /) -> Ip6Probe:
        """
        Parse a TX frame back into an 'Ip6Probe' covering the
        IPv6 fields the IPv6 integration tests need to assert
        on. Strips the Ethernet header and the IPv6 header;
        'payload' is the bytes following the IPv6 header (which
        for extension-header-bearing frames is the first ext
        header — the parser does not walk the chain).
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        if packet_rx.ethernet.type is not EtherType.IP6:
            raise AssertionError(f"Expected IPv6 frame, got EtherType {packet_rx.ethernet.type!r}.")
        Ip6Parser(packet_rx)

        return Ip6Probe(
            ip_src=packet_rx.ip6.src,
            ip_dst=packet_rx.ip6.dst,
            hop=packet_rx.ip6.hop,
            dscp=packet_rx.ip6.dscp,
            ecn=packet_rx.ip6.ecn,
            flow_label=packet_rx.ip6.flow,
            next_header=packet_rx.ip6.next,
            payload=bytes(packet_rx.ip6.payload_bytes),
        )


# Re-export the canonical IPv6 fixtures so IPv6 integration
# tests can import addresses from one place without round-
# tripping through 'network_testcase'.
__all__ = [
    "HOST_A__IP6_ADDRESS",
    "HOST_A__MAC_ADDRESS",
    "HOST_B__IP6_ADDRESS",
    "HOST_C__IP6_ADDRESS",
    "Ip6Probe",
    "Ip6TestCase",
    "STACK__IP6_HOST",
    "STACK__MAC_ADDRESS",
]
