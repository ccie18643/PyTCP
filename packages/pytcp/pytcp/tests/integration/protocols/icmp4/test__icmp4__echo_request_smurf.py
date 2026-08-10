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
This module contains integration tests for the ICMPv4 Echo Request
handler's Smurf-attack mitigation: an Echo Request received with a
broadcast or multicast destination IP address must NOT be answered.

pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_request_smurf.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import Icmp4MessageEchoRequest
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)


def _build_icmp4_echo_frame(
    *,
    eth_src: MacAddress = HOST_A__MAC_ADDRESS,
    eth_dst: MacAddress = STACK__MAC_ADDRESS,
    ip_src: str = str(HOST_A__IP4_ADDRESS),
    ip_dst: str = str(STACK__IP4_HOST.address),
    icmp_id: int = 0xCAFE,
    icmp_seq: int = 1,
    icmp_data: bytes = b"ping",
) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Echo Request frame with the
    specified addressing. Defaults aim a unicast probe at the stack.
    """

    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageEchoRequest(
            id=icmp_id,
            seq=icmp_seq,
            data=icmp_data,
        ),
    )
    ip4 = Ip4Assembler(
        ip4__src=Ip4Address(ip_src),
        ip4__dst=Ip4Address(ip_dst),
        ip4__payload=icmp,
    )
    eth = EthernetAssembler(
        ethernet__src=eth_src,
        ethernet__dst=eth_dst,
        ethernet__payload=ip4,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


class TestIcmp4EchoSmurf__UnicastRegression(IcmpTestCase, TestCase):
    """
    The ICMPv4 Echo Request handler unicast-regression tests.
    """

    def test__icmp4__echo_request__unicast_emits_reply(self) -> None:
        """
        Ensure a clean unicast Echo Request still triggers an Echo
        Reply. Pins the regression that the new Smurf gate does NOT
        block legitimate replies.

        Reference: RFC 1122 §3.2.2.6 (host SHOULD reply to unicast Echo).
        """

        frames_tx = self._drive_rx(frame=_build_icmp4_echo_frame())

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Unicast Echo Request must still produce exactly one Echo Reply.",
        )
        probe = self._parse_tx_icmp4(frames_tx[0])
        self.assertEqual(
            probe.icmp_type,
            0,
            msg=f"Outbound ICMPv4 must be Echo Reply (type 0). Got: {probe!r}",
        )
        self.assertEqual(
            probe.icmp_id,
            0xCAFE,
            msg=f"Echo Reply must reflect the Echo Request id. Got: {probe!r}",
        )


class TestIcmp4EchoSmurf__BroadcastSuppressed(IcmpTestCase, TestCase):
    """
    The ICMPv4 Echo Request handler Smurf-mitigation tests against
    a limited-broadcast destination. The handler also drops multicast
    destinations symmetrically, but the multicast case cannot be
    integration-tested through the current harness because the test
    'NetworkTestCase' does not register the IPv4 multicast group MAC
    in '_mac_multicast', so Ethernet RX drops the frame before it
    reaches the ICMP layer.
    """

    def test__icmp4__echo_request__bcast_dst_no_reply(self) -> None:
        """
        Ensure that an Echo Request with a limited-broadcast
        destination IP address is silently dropped — no Echo Reply
        is sent and the dedicated drop counter bumps. Mitigates the
        classic Smurf reflective-amplification attack.

        Reference: RFC 1122 §3.2.2.6 (host MUST NOT reply to Echo
        Request received on a broadcast/multicast destination).
        Reference: RFC 1812 §4.3.3.6 (analogous router rule, applies
        to hosts via RFC 1122).
        """

        frames_tx = self._drive_rx(
            frame=_build_icmp4_echo_frame(
                ip_dst="255.255.255.255",
                eth_dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            ),
        )

        self.assertEqual(
            frames_tx,
            [],
            msg="Expected NO Echo Reply for limited-broadcast destination.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__echo_request__bcast_or_mcast__drop,
            1,
            msg="Smurf-drop counter must bump exactly once.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp4__echo_request__respond_echo_reply,
            0,
            msg="Reply counter must remain zero on Smurf-drop path.",
        )


class TestIcmp4EchoSmurf__KnobOverride(IcmpTestCase, TestCase):
    """
    The ICMPv4 multicast Echo Reply 'icmp4.echo_ignore_broadcasts' knob
    tests.
    """

    def test__icmp4__echo_request__mcast_dst_replies_from_unicast_when_knob_zero(self) -> None:
        """
        Ensure that with 'icmp4.echo_ignore_broadcasts' set to 0 an Echo
        Request to a joined multicast group is answered, and the Echo
        Reply is sourced from the stack's unicast address (not the
        multicast group, which cannot source a datagram).

        Reference: Linux 'net.ipv4.icmp_echo_ignore_broadcasts' (0 answers multicast echo).
        Reference: RFC 1122 §3.2.2.6 (a multicast-echo reply is sourced from a host unicast address).
        """

        group = Ip4Address("239.1.1.1")
        self._packet_handler._assign_ip4_multicast(group)

        with sysctl.override("icmp4.echo_ignore_broadcasts", 0):
            frames_tx = self._drive_rx(
                frame=_build_icmp4_echo_frame(
                    ip_dst=str(group),
                    eth_dst=MacAddress("01:00:5e:01:01:01"),
                ),
            )

        self.assertEqual(len(frames_tx), 1, msg="Knob 0 must let a multicast Echo Request be answered.")

        reply = frames_tx[0]
        # Ethernet (14) + IPv4 src at offset 12, dst at 16.
        reply_src = Ip4Address(reply[26:30])
        reply_dst = Ip4Address(reply[30:34])

        self.assertEqual(
            reply_src,
            STACK__IP4_HOST.address,
            msg="A multicast Echo Reply must be sourced from the stack's unicast address.",
        )
        self.assertEqual(
            reply_dst,
            HOST_A__IP4_ADDRESS,
            msg="The Echo Reply must be addressed to the requester.",
        )
