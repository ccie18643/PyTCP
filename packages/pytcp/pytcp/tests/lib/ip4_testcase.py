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
This module contains the 'Ip4TestCase' base class used by the
IPv4 integration tests, layering IPv4 frame builders, RX/TX
probe helpers, and source-selection plumbing on top of
'NetworkTestCase'.

pytcp/tests/lib/ip4_testcase.py

ver 3.0.9
"""

from dataclasses import dataclass
from typing import Any

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import (
    EthernetAssembler,
    Ip4Assembler,
    Ip4Options,
    Ip4Parser,
    IpProto,
    RawAssembler,
)
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    HOST_C__IP4_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)


@dataclass(frozen=True, slots=True)
class Ip4Probe:
    """
    Decoded snapshot of a single Ethernet/IPv4 frame produced
    by the stack under test, used by 'Ip4TestCase' assertions.
    """

    ip_src: Ip4Address
    ip_dst: Ip4Address
    # RFC 791 §3.1 IPv4 TTL.
    ttl: int
    # RFC 2474 §3 DSCP (6 high bits of TOS byte).
    dscp: int
    # RFC 3168 §5 ECN (low 2 bits of TOS byte).
    ecn: int
    # RFC 791 §3.1 Don't Fragment and More Fragments flags.
    flag_df: bool
    flag_mf: bool
    # RFC 791 §3.1 fragment offset (in 8-byte units).
    offset: int
    # Next-header protocol (UDP / TCP / ICMP / etc.).
    proto: IpProto
    # IPv4 options block as raw bytes; 'b""' for no options.
    options: bytes
    # Application payload following the IPv4 header (+ options).
    payload: bytes


class Ip4TestCase(NetworkTestCase):
    """
    Base class for IPv4 integration tests. Adds IPv4 frame
    builders, an RX driver helper, and a 'Ip4Probe' TX parser
    for fluent assertions on outbound IPv4 frames. Source-
    selection tests use '_set_ip4_hosts' to populate the
    stack's owned-address list before exercising
    '_select_ip4_source'.
    """

    def _set_ip4_hosts(self, *hosts: Ip4IfAddr) -> None:
        """
        Replace the stack's '_ip4_ifaddr' list with the given
        hosts. Used by source-selection tests that exercise
        'PacketHandler._select_ip4_source' against a controlled
        owned-address list.
        """

        self._packet_handler._ip4_ifaddr = list(hosts)

    def _drive_ip4_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into 'PacketHandler._phrx_ethernet' and
        return the list of TX frames the stack produced as a
        direct result. Mirrors
        'UdpTestCase._drive_udp_rx' / 'IcmpTestCase._drive_rx'
        for the IPv4 family.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def _build_ip4_frame(
        self,
        *,
        src: Ip4Address = HOST_A__IP4_ADDRESS,
        dst: Ip4Address | None = None,
        payload: Any = RawAssembler(),
        dscp: int = 0,
        ecn: int = 0,
        ttl: int | None = None,
        flag_df: bool = False,
        options: Ip4Options | None = None,
        ethernet_src: MacAddress = HOST_A__MAC_ADDRESS,
        ethernet_dst: MacAddress = STACK__MAC_ADDRESS,
    ) -> bytes:
        """
        Build an Ethernet/IPv4 frame on the canonical fixture
        4-tuple. Defaults: HOST_A → STACK with no IPv4 options,
        DSCP/ECN=0, TTL default (assembler picks). Override any
        kwarg for variant frames; 'payload' accepts any IPv4
        payload assembler (UDP, TCP, ICMPv4, raw).
        """

        if dst is None:
            dst = STACK__IP4_HOST.address

        ip4_kwargs: dict[str, Any] = {
            "ip4__src": src,
            "ip4__dst": dst,
            "ip4__dscp": dscp,
            "ip4__ecn": ecn,
            "ip4__flag_df": flag_df,
            "ip4__payload": payload,
        }
        if ttl is not None:
            ip4_kwargs["ip4__ttl"] = ttl
        if options is not None:
            ip4_kwargs["ip4__options"] = options

        return bytes(
            EthernetAssembler(
                ethernet__src=ethernet_src,
                ethernet__dst=ethernet_dst,
                ethernet__payload=Ip4Assembler(**ip4_kwargs),
            )
        )

    def _parse_tx_ip4(self, frame: bytes, /) -> Ip4Probe:
        """
        Parse a TX frame back into an 'Ip4Probe' covering the
        IPv4 fields the IPv4 integration tests need to assert
        on. Strips the Ethernet header and the IPv4 header /
        options; 'payload' is the bytes following the IPv4
        header (the L4 segment, not yet parsed).
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        if packet_rx.ethernet.type is not EtherType.IP4:
            raise AssertionError(f"Expected IPv4 frame, got EtherType {packet_rx.ethernet.type!r}.")
        Ip4Parser(packet_rx)

        return Ip4Probe(
            ip_src=packet_rx.ip4.src,
            ip_dst=packet_rx.ip4.dst,
            ttl=packet_rx.ip4.ttl,
            dscp=packet_rx.ip4.dscp,
            ecn=packet_rx.ip4.ecn,
            flag_df=packet_rx.ip4.flag_df,
            flag_mf=packet_rx.ip4.flag_mf,
            offset=packet_rx.ip4.offset,
            proto=packet_rx.ip4.proto,
            options=bytes(packet_rx.ip4.options),
            payload=bytes(packet_rx.ip4.payload_bytes),
        )


# Re-export the canonical IPv4 fixtures so IPv4 integration
# tests can import addresses from one place without round-
# tripping through 'network_testcase'.
__all__ = [
    "HOST_A__IP4_ADDRESS",
    "HOST_A__MAC_ADDRESS",
    "HOST_B__IP4_ADDRESS",
    "HOST_C__IP4_ADDRESS",
    "Ip4Probe",
    "Ip4TestCase",
    "STACK__IP4_HOST",
    "STACK__MAC_ADDRESS",
]
