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
This module contains integration tests for the ICMPv4 outbound-error
eligibility gates and rate limiter, as exercised through the UDP
closed-port Port-Unreachable emitter.

pytcp/tests/integration/protocols/icmp4/test__icmp4__error_gates.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp import stack
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.parameterized import parameterized_class


def _build_udp4_frame(
    *,
    eth_src: MacAddress = HOST_A__MAC_ADDRESS,
    eth_dst: MacAddress = STACK__MAC_ADDRESS,
    ip_src: str = str(HOST_A__IP4_ADDRESS),
    ip_dst: str = str(STACK__IP4_HOST.address),
    sport: int = 12345,
    dport: int = 65000,
    payload: bytes = b"X" * 16,
) -> bytes:
    """
    Build an Ethernet/IPv4/UDP frame with the specified addressing.
    Defaults aim a unicast UDP probe at the stack's listening
    address with a deliberately closed destination port so the RX
    path lands on the Port-Unreachable emitter.
    """

    udp = UdpAssembler(udp__sport=sport, udp__dport=dport, udp__payload=payload)
    ip4 = Ip4Assembler(
        ip4__src=Ip4Address(ip_src),
        ip4__dst=Ip4Address(ip_dst),
        ip4__payload=udp,
    )
    eth = EthernetAssembler(
        ethernet__src=eth_src,
        ethernet__dst=eth_dst,
        ethernet__payload=ip4,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


class TestIcmp4ErrorGates__CleanUnicast(IcmpTestCase, TestCase):
    """
    The ICMPv4 outbound-error gates IcmpTestCase clean-unicast tests.
    """

    def test__icmp4__gates__clean_unicast_emits_port_unreachable(self) -> None:
        """
        Ensure a clean unicast UDP probe to a closed port still triggers
        a Port-Unreachable. Pins the regression that the new gates do
        NOT block legitimate emissions.

        Reference: RFC 1122 §3.2.2 (clean unicast permits emission).
        """

        frames_tx = self._drive_rx(frame=_build_udp4_frame())

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Clean unicast UDP-to-closed-port must emit exactly one TX frame.",
        )
        probe = self._parse_tx_icmp4(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            3,
            msg=f"Outbound ICMPv4 must be Destination-Unreachable (type 3). Got: {probe!r}",
        )
        self.assertEqual(
            probe.icmp_code,
            3,
            msg=f"Outbound ICMPv4 must be Port-Unreachable (code 3). Got: {probe!r}",
        )


@parameterized_class(
    [
        {
            "_description": "Limited-broadcast destination 255.255.255.255.",
            "_kwargs": {"ip_dst": "255.255.255.255", "eth_dst": MacAddress("ff:ff:ff:ff:ff:ff")},
        },
    ]
)
class TestIcmp4ErrorGates__Suppressed(IcmpTestCase, TestCase):
    """
    The ICMPv4 outbound-error gates IcmpTestCase suppression tests.
    Covers the cases where the IP-layer parser/handler permits the
    inbound packet to reach UDP RX, so the new UDP-RX gate is the
    line of defense that prevents Port-Unreachable emission.
    """

    _description: str
    _kwargs: dict[str, Any]

    def test__icmp4__gates__suppress_port_unreachable(self) -> None:
        """
        Ensure an inbound UDP probe whose IP-layer state trips a
        host-requirements gate produces no outbound Port-Unreachable
        and bumps the UDP-side suppression counter.

        Reference: RFC 1122 §3.2.2 (host MUST NOT send ICMP error in
        response to: bcast/mcast destination, or source not defining
        a single host).
        """

        frames_tx = self._drive_rx(frame=_build_udp4_frame(**self._kwargs))

        self.assertEqual(
            frames_tx,
            [],
            msg=f"Expected NO outbound ICMP error for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__no_socket_match__icmp4_unreachable_suppressed,
            1,
            msg=f"Suppression counter must bump exactly once. Case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Loopback source 127.0.0.1 — IP4 parser rejects (RFC 1122 §3.2.1.3(g)).",
            "_kwargs": {"ip_src": "127.0.0.1"},
        },
        {
            "_description": "Multicast source 224.0.0.1 — IP4 parser rejects.",
            "_kwargs": {"ip_src": "224.0.0.1"},
        },
        {
            "_description": "Class E (reserved) source 240.0.0.1 — IP4 parser rejects.",
            "_kwargs": {"ip_src": "240.0.0.1"},
        },
    ]
)
class TestIcmp4ErrorGates__DefenseInDepth(IcmpTestCase, TestCase):
    """
    The ICMPv4 outbound-error defense-in-depth tests. Covers the
    cases where the IP-layer parser drops the inbound packet before
    UDP RX is reached; no Port-Unreachable can be emitted regardless
    of the UDP-RX gate.
    """

    _description: str
    _kwargs: dict[str, Any]

    def test__icmp4__defense_in_depth__no_outbound_icmp(self) -> None:
        """
        Ensure that an invalid-source packet rejected by the IPv4
        parser produces no outbound ICMP error of any kind. The UDP-
        side suppression counter does NOT bump (the packet never
        reaches UDP RX), but the absence of a Port-Unreachable is
        the security-relevant observable.

        Reference: RFC 1122 §3.2.2 (host MUST NOT send ICMP error in
        response to source not defining a single host).
        """

        frames_tx = self._drive_rx(frame=_build_udp4_frame(**self._kwargs))

        self.assertEqual(
            frames_tx,
            [],
            msg=f"Expected NO outbound ICMP error for case: {self._description}",
        )


class TestIcmp4ErrorGates__RateLimit(IcmpTestCase, TestCase):
    """
    The ICMPv4 outbound-error rate-limit IcmpTestCase tests.
    """

    def test__icmp4__rate_limit__exhausted_bucket_suppresses(self) -> None:
        """
        Ensure that once the per-stack rate-limit bucket is exhausted,
        further closed-port UDP probes no longer trigger Port-
        Unreachable emissions until the bucket refills.

        Reference: RFC 1812 §4.3.2.8 (rate-limit ICMP errors).
        """

        # Replace the framework default with a tiny burst so we can
        # exhaust it deterministically without needing time injection.
        stack.icmp4_error_rate_limiter = IcmpErrorRateLimiter(rate_pps=1, burst=2)

        # First two probes consume the burst — Port-Unreachable IS emitted.
        for _ in range(2):
            frames_tx = self._drive_rx(frame=_build_udp4_frame())
            self.assertEqual(
                len(frames_tx),
                1,
                msg="Within-burst probes must emit Port-Unreachable.",
            )

        # Third probe at the same instant — bucket exhausted — IS suppressed.
        frames_tx = self._drive_rx(frame=_build_udp4_frame())
        self.assertEqual(
            frames_tx,
            [],
            msg="Beyond-burst probe must be suppressed by the rate limiter.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__no_socket_match__icmp4_unreachable_suppressed,
            1,
            msg="Rate-limit suppression must bump the suppression counter.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__no_socket_match__respond_icmp4_unreachable,
            2,
            msg="Within-burst probes must each bump the success counter.",
        )
