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
Integration test for the RFC 6437 §3 IPv6 Flow Label
TX-path auto-wire. With the
'ip6.flow_label_generation' sysctl flipped to 1, the
'_phtx_ip6' path computes a non-zero 20-bit Flow Label
from the (src, dst) pair via 'compute_ip6_flow_label';
the outbound frame's IPv6 header word reflects the
derived value.

The default 'NetworkTestCase' setUp pins the sysctl to 0
so existing golden-frame fixtures continue to match
without per-fixture regeneration; this test overrides
the override to flip it back to 1 for its own test
methods.

pytcp/tests/integration/protocols/ip6/test__ip6__rfc6437_flow_label.py

ver 3.0.8
"""

from typing import override

from net_addr import Ip6Address
from net_proto import Icmp6Assembler, Icmp6MessageEchoRequest
from net_proto.lib.buffer import Buffer
from pytcp.protocols.ip6 import ip6__constants as ip6__constants_module
from pytcp.protocols.ip6.ip6__flow_label import compute_ip6_flow_label
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


class TestIp6Rfc6437FlowLabelAutoWire(IcmpTestCase):
    """
    Verify that '_phtx_ip6' emits a non-zero RFC 6437 §3
    Flow Label when the 'ip6.flow_label_generation' sysctl
    is enabled.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        # The default harness setUp pins the sysctl to 0 for
        # golden-frame stability. Flip it back to 1 for this
        # test class so the auto-wire is exercised.
        ip6__constants_module.IP6__FLOW_LABEL_GENERATION = 1

    def _decode_flow_label(self, frame: bytes) -> int:
        """
        Extract the 20-bit Flow Label from an Ethernet/IPv6
        frame's IPv6 header. Layout: 14-byte Ethernet
        header + IPv6 header. The version/TC/FL word is the
        first 4 bytes of the IPv6 header — version (4) +
        TC (8) + Flow Label (20).
        """

        ip6_header_word = int.from_bytes(frame[14:18], "big")
        return ip6_header_word & 0xFFFFF

    def test__ip6__rfc6437__flow_label_nonzero_when_enabled(self) -> None:
        """
        Ensure an outbound IPv6 packet (driven via an Echo
        Reply to an inbound Echo Request) carries a
        non-zero Flow Label when the sysctl is enabled.

        Reference: RFC 6437 §3 (Flow Label MUST be chosen
        from an approximation to a discrete uniform
        distribution).
        """

        # Build an inbound Echo Request that drives one
        # outbound Echo Reply.
        echo_request = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoRequest(id=0x1234, seq=1, data=b"x" * 16),
        )
        # Use the harness helper to drive a wire frame.
        # An echo request from HOST_A → STACK elicits a
        # reply from STACK → HOST_A.
        # The harness's _drive_rx returns the TX frames.
        # Construct the inbound frame via the harness's
        # ip6 wrapper.
        from net_proto import EthernetAssembler, Ip6Assembler
        from pytcp.tests.lib.network_testcase import (
            HOST_A__IP6_ADDRESS,
            HOST_A__MAC_ADDRESS,
            STACK__IP6_HOST,
            STACK__MAC_ADDRESS,
        )

        ip6_packet = Ip6Assembler(
            ip6__src=HOST_A__IP6_ADDRESS,
            ip6__dst=STACK__IP6_HOST.address,
            ip6__hop=64,
            ip6__payload=echo_request,
        )
        ethernet_frame = EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=ip6_packet,
        )
        buffers: list[Buffer] = []
        ethernet_frame.assemble(buffers)
        frame_rx = b"".join(bytes(buf) for buf in buffers)

        tx_frames = self._drive_rx(frame=frame_rx)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=f"Echo Request must elicit exactly one Echo Reply; got {len(tx_frames)}.",
        )

        flow_label = self._decode_flow_label(tx_frames[0])

        # The (src, dst) pair STACK→HOST_A yields the
        # generator's deterministic-but-secret-keyed flow
        # label. We don't assert a specific value (the
        # secret is per-process random) — just non-zero.
        self.assertGreater(
            flow_label,
            0,
            msg=f"Flow Label must be non-zero when generation is enabled; got {flow_label}.",
        )

    def test__ip6__rfc6437__flow_label_matches_generator(self) -> None:
        """
        Ensure the on-wire Flow Label equals the value
        returned by 'compute_ip6_flow_label' for the same
        (src, dst) pair — confirming the TX path uses the
        documented generator and not some other hash.

        Reference: RFC 6437 §3 (per-flow stability).
        """

        echo_request = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoRequest(id=0x1234, seq=1, data=b"x" * 16),
        )
        from net_proto import EthernetAssembler, Ip6Assembler
        from pytcp.tests.lib.network_testcase import (
            HOST_A__IP6_ADDRESS,
            HOST_A__MAC_ADDRESS,
            STACK__IP6_HOST,
            STACK__MAC_ADDRESS,
        )

        ip6_packet = Ip6Assembler(
            ip6__src=HOST_A__IP6_ADDRESS,
            ip6__dst=STACK__IP6_HOST.address,
            ip6__hop=64,
            ip6__payload=echo_request,
        )
        ethernet_frame = EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=ip6_packet,
        )
        buffers: list[Buffer] = []
        ethernet_frame.assemble(buffers)
        frame_rx = b"".join(bytes(buf) for buf in buffers)

        tx_frames = self._drive_rx(frame=frame_rx)
        on_wire_flow = self._decode_flow_label(tx_frames[0])

        # Echo Reply src/dst is STACK → HOST_A.
        expected_flow = compute_ip6_flow_label(
            src=STACK__IP6_HOST.address,
            dst=Ip6Address(HOST_A__IP6_ADDRESS),
        )

        self.assertEqual(
            on_wire_flow,
            expected_flow,
            msg=(
                f"On-wire Flow Label ({on_wire_flow:#07x}) must equal the "
                f"generator output ({expected_flow:#07x}) for the same (src, dst)."
            ),
        )

    def test__ip6__rfc6437__flow_label_zero_when_disabled(self) -> None:
        """
        Ensure an outbound IPv6 packet carries flow=0 when
        the 'ip6.flow_label_generation' sysctl is flipped
        off (the harness default, but assert it explicitly
        for regression coverage).

        Reference: RFC 6437 §2 (Flow Label is zero when no
        specific flow is defined).
        """

        ip6__constants_module.IP6__FLOW_LABEL_GENERATION = 0

        echo_request = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoRequest(id=0x1234, seq=1, data=b"x" * 16),
        )
        from net_proto import EthernetAssembler, Ip6Assembler
        from pytcp.tests.lib.network_testcase import (
            HOST_A__IP6_ADDRESS,
            HOST_A__MAC_ADDRESS,
            STACK__IP6_HOST,
            STACK__MAC_ADDRESS,
        )

        ip6_packet = Ip6Assembler(
            ip6__src=HOST_A__IP6_ADDRESS,
            ip6__dst=STACK__IP6_HOST.address,
            ip6__hop=64,
            ip6__payload=echo_request,
        )
        ethernet_frame = EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=ip6_packet,
        )
        buffers: list[Buffer] = []
        ethernet_frame.assemble(buffers)
        frame_rx = b"".join(bytes(buf) for buf in buffers)

        tx_frames = self._drive_rx(frame=frame_rx)

        flow_label = self._decode_flow_label(tx_frames[0])

        self.assertEqual(
            flow_label,
            0,
            msg=f"Flow Label must be 0 when generation is disabled; got {flow_label}.",
        )
