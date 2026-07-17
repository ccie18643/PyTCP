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
This module contains unit tests for the daemon-independent parts of the
'pytcp tcpdump' capture engine: the pure frame decoder ('describe_frame'),
the direction-prefixed line formatter ('format_capture_line'), and the
'run_tcpdump' loop driven over a fake capture socket.

pytcp/tests/unit/cli/test__cli__tcpdump.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address, MacAddress
from net_proto import (
    ArpAssembler,
    ArpOperation,
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp6Assembler,
    Icmp6MessageEchoRequest,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
    IpProto,
)
from net_proto.protocols.tcp.tcp__assembler import TcpAssembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp.cli.cli__tcpdump import (
    describe_frame,
    format_capture_line,
    run_tcpdump,
)
from pytcp.runtime.socket import PacketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

_SRC_MAC = MacAddress("02:00:00:00:00:07")
_DST_MAC = MacAddress("02:00:00:00:00:91")
_SRC4 = Ip4Address("10.0.1.7")
_DST4 = Ip4Address("10.0.1.91")


def _tcp_frame() -> bytes:
    """
    Build an IPv4/TCP SYN-ACK frame from 10.0.1.7:7 to 10.0.1.91:54321.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_SRC_MAC,
            ethernet__dst=_DST_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_SRC4,
                ip4__dst=_DST4,
                ip4__payload=TcpAssembler(tcp__sport=7, tcp__dport=54321, tcp__flag_syn=True, tcp__flag_ack=True),
            ),
        )
    )


def _udp_frame() -> bytes:
    """
    Build an IPv4/UDP frame from 10.0.1.7:7 to 10.0.1.91:12345, payload
    'hello' (5 bytes).
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_SRC_MAC,
            ethernet__dst=_DST_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_SRC4,
                ip4__dst=_DST4,
                ip4__payload=UdpAssembler(udp__sport=7, udp__dport=12345, udp__payload=b"hello"),
            ),
        )
    )


def _ip6_udp_frame() -> bytes:
    """
    Build an IPv6/UDP frame from fd00:1::7.7 to fd00:1::1.12345, payload
    'hello'.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_SRC_MAC,
            ethernet__dst=_DST_MAC,
            ethernet__payload=Ip6Assembler(
                ip6__src=Ip6Address("fd00:1::7"),
                ip6__dst=Ip6Address("fd00:1::1"),
                ip6__payload=UdpAssembler(udp__sport=7, udp__dport=12345, udp__payload=b"hello"),
            ),
        )
    )


def _icmp4_echo_request_frame() -> bytes:
    """
    Build an IPv4/ICMPv4 Echo Request from 10.0.1.91 to 10.0.1.7, id
    0x1234, seq 1, with a 4-byte payload.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_DST_MAC,
            ethernet__dst=_SRC_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_DST4,
                ip4__dst=_SRC4,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoRequest(id=0x1234, seq=1, data=b"ping"),
                ),
            ),
        )
    )


def _icmp4_echo_reply_frame() -> bytes:
    """
    Build an IPv4/ICMPv4 Echo Reply from 10.0.1.7 to 10.0.1.91, id
    0x1234, seq 1, with a 4-byte payload.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_SRC_MAC,
            ethernet__dst=_DST_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_SRC4,
                ip4__dst=_DST4,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoReply(id=0x1234, seq=1, data=b"ping"),
                ),
            ),
        )
    )


def _icmp6_echo_request_frame() -> bytes:
    """
    Build an IPv6/ICMPv6 Echo Request from fd00:1::1 to fd00:1::7, id
    0x1234, seq 7, with a 4-byte payload.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_DST_MAC,
            ethernet__dst=_SRC_MAC,
            ethernet__payload=Ip6Assembler(
                ip6__src=Ip6Address("fd00:1::1"),
                ip6__dst=Ip6Address("fd00:1::7"),
                ip6__payload=Icmp6Assembler(
                    icmp6__message=Icmp6MessageEchoRequest(id=0x1234, seq=7, data=b"ping"),
                ),
            ),
        )
    )


def _ip4_fragment_frame(*, offset: int, flag_mf: bool, proto: IpProto) -> bytes:
    """
    Build an IPv4 fragment from 10.0.1.91 to 10.0.1.7 with id 0x1234 and a
    520-byte payload, at 'offset' with the given 'flag_mf' / next-protocol.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_DST_MAC,
            ethernet__dst=_SRC_MAC,
            ethernet__payload=Ip4FragAssembler(
                ip4_frag__src=_DST4,
                ip4_frag__dst=_SRC4,
                ip4_frag__id=0x1234,
                ip4_frag__offset=offset,
                ip4_frag__flag_mf=flag_mf,
                ip4_frag__proto=proto,
                ip4_frag__payload=b"x" * 520,
            ),
        )
    )


def _arp_request_frame() -> bytes:
    """
    Build an ARP request: who-has 10.0.1.7, tell 10.0.1.91.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_DST_MAC,
            ethernet__dst=MacAddress("ff:ff:ff:ff:ff:ff"),
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REQUEST,
                arp__sha=_DST_MAC,
                arp__spa=_DST4,
                arp__tpa=_SRC4,
            ),
        )
    )


def _arp_reply_frame() -> bytes:
    """
    Build an ARP reply: 10.0.1.7 is-at 02:00:00:00:00:07.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_SRC_MAC,
            ethernet__dst=_DST_MAC,
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REPLY,
                arp__sha=_SRC_MAC,
                arp__spa=_SRC4,
                arp__tha=_DST_MAC,
                arp__tpa=_DST4,
            ),
        )
    )


class TestCliTcpdumpDescribeFrame(TestCase):
    """
    The 'pytcp tcpdump' pure frame-decoder tests.
    """

    def test__cli__tcpdump__describe_ipv4_tcp(self) -> None:
        """
        Ensure an IPv4/TCP segment renders with both endpoints' ports, a
        tcpdump-style flags block, and the segment data length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_tcp_frame()),
            "IP 10.0.1.7.7 > 10.0.1.91.54321: Flags [S.], length 0",
            msg="An IPv4/TCP SYN-ACK must render endpoints, flags, and length.",
        )

    def test__cli__tcpdump__describe_ipv4_udp(self) -> None:
        """
        Ensure an IPv4/UDP datagram renders with both endpoints' ports and
        the UDP payload length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_udp_frame()),
            "IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5",
            msg="An IPv4/UDP datagram must render endpoints and payload length.",
        )

    def test__cli__tcpdump__describe_ipv6_udp(self) -> None:
        """
        Ensure an IPv6/UDP datagram renders with the 'IP6' prefix, both
        endpoints' ports, and the payload length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_ip6_udp_frame()),
            "IP6 fd00:1::7.7 > fd00:1::1.12345: UDP, length 5",
            msg="An IPv6/UDP datagram must render with the IP6 prefix.",
        )

    def test__cli__tcpdump__describe_ipv4_icmp_echo_request(self) -> None:
        """
        Ensure an IPv4/ICMPv4 Echo Request renders its endpoints and the
        message's type, id, seq, and length.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_icmp4_echo_request_frame()),
            "IP 10.0.1.91 > 10.0.1.7: ICMPv4 Echo Request, id 4660, seq 1, len 12 (8+4)",
            msg="An IPv4/ICMPv4 Echo Request must render type, id, seq, and length.",
        )

    def test__cli__tcpdump__describe_ipv4_icmp_echo_reply(self) -> None:
        """
        Ensure an IPv4/ICMPv4 Echo Reply renders as a reply rather than a
        bare next-protocol name.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_icmp4_echo_reply_frame()),
            "IP 10.0.1.7 > 10.0.1.91: ICMPv4 Echo Reply, id 4660, seq 1, len 12 (8+4)",
            msg="An IPv4/ICMPv4 Echo Reply must render as a reply.",
        )

    def test__cli__tcpdump__describe_ipv6_icmp_echo_request(self) -> None:
        """
        Ensure an IPv6/ICMPv6 Echo Request renders with the 'IP6' prefix and
        the ICMPv6 message detail.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_icmp6_echo_request_frame()),
            "IP6 fd00:1::1 > fd00:1::7: ICMPv6 Echo Request, id 4660, seq 7, len 12 (8+4)",
            msg="An IPv6/ICMPv6 Echo Request must render with the IP6 prefix and message detail.",
        )

    def test__cli__tcpdump__describe_ipv4_first_fragment(self) -> None:
        """
        Ensure the first fragment of a fragmented datagram (offset 0, MF
        set) renders as a fragment — id, this-fragment length, offset, and
        a trailing '+' for more — rather than being mis-parsed as a
        complete L4 datagram on partial data.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_ip4_fragment_frame(offset=0, flag_mf=True, proto=IpProto.UDP)),
            "IP 10.0.1.91 > 10.0.1.7: UDP, frag 4660:520@0+",
            msg="A first IPv4 fragment must render as a fragment, not a parsed L4 datagram.",
        )

    def test__cli__tcpdump__describe_ipv4_middle_fragment(self) -> None:
        """
        Ensure a non-first fragment (offset > 0, MF set — no L4 header)
        renders as a fragment with its byte offset and a trailing '+'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_ip4_fragment_frame(offset=1480, flag_mf=True, proto=IpProto.ICMP4)),
            "IP 10.0.1.91 > 10.0.1.7: ICMPv4, frag 4660:520@1480+",
            msg="A middle IPv4 fragment must render with its offset and a trailing '+'.",
        )

    def test__cli__tcpdump__describe_ipv4_last_fragment(self) -> None:
        """
        Ensure the last fragment (offset > 0, MF clear) renders without the
        trailing '+' that marks more fragments.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_ip4_fragment_frame(offset=1480, flag_mf=False, proto=IpProto.ICMP4)),
            "IP 10.0.1.91 > 10.0.1.7: ICMPv4, frag 4660:520@1480",
            msg="A last IPv4 fragment must render without a trailing '+'.",
        )

    def test__cli__tcpdump__describe_arp_request(self) -> None:
        """
        Ensure an ARP request renders in tcpdump 'who-has ... tell ...' form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_arp_request_frame()),
            "ARP, Request who-has 10.0.1.7 tell 10.0.1.91",
            msg="An ARP request must render as who-has/tell.",
        )

    def test__cli__tcpdump__describe_arp_reply(self) -> None:
        """
        Ensure an ARP reply renders in tcpdump 'is-at' form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(_arp_reply_frame()),
            "ARP, Reply 10.0.1.7 is-at 02:00:00:00:00:07",
            msg="An ARP reply must render as is-at.",
        )

    def test__cli__tcpdump__describe_unparsable_frame_falls_back(self) -> None:
        """
        Ensure a frame the parser rejects yields a length-tagged fallback
        line instead of raising, so the capture loop never dies on a bad
        frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            describe_frame(b"\x00" * 20),
            "(unparsable frame, length 20)",
            msg="An unparsable frame must yield a fallback line, not raise.",
        )


class TestCliTcpdumpFormatLine(TestCase):
    """
    The 'pytcp tcpdump' direction-prefixed line-formatter tests.
    """

    def test__cli__tcpdump__outbound_frame_is_prefixed_out(self) -> None:
        """
        Ensure a frame captured on egress (pkttype PACKET_OUTGOING) is
        prefixed 'Out' — the direction the TX tap makes visible.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_capture_line(pkttype=PacketType.PACKET_OUTGOING, frame=_udp_frame()),
            "Out IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5",
            msg="An outbound frame must be prefixed 'Out'.",
        )

    def test__cli__tcpdump__inbound_frame_is_prefixed_in(self) -> None:
        """
        Ensure a frame captured on ingress (any non-outgoing pkttype) is
        prefixed 'In'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_capture_line(pkttype=PacketType.PACKET_HOST, frame=_udp_frame()),
            "In IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5",
            msg="An inbound frame must be prefixed 'In'.",
        )

    def test__cli__tcpdump__timestamp_is_prepended_when_supplied(self) -> None:
        """
        Ensure a supplied relative timestamp is rendered as a fixed-width
        seconds column ahead of the direction tag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            format_capture_line(pkttype=PacketType.PACKET_HOST, frame=_udp_frame(), timestamp=1.5),
            " 1.500000 In IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5",
            msg="A supplied timestamp must render as a fixed-width seconds column.",
        )


class _FakeCaptureSocket:
    """
    A fake capture socket yielding a fixed queue of '(frame, sockaddr_ll)'
    pairs from 'recvfrom', for driving 'run_tcpdump' without a daemon.
    """

    def __init__(self, packets: list[tuple[bytes, SockAddrLl]], /) -> None:
        self._packets = list(packets)

    def recvfrom(self) -> tuple[bytes, SockAddrLl]:
        return self._packets.pop(0)


class TestCliTcpdumpRunLoop(TestCase):
    """
    The 'run_tcpdump' capture-loop tests over a fake socket.
    """

    @override
    def setUp(self) -> None:
        """
        Build an outbound-UDP and an inbound-ARP capture pair.
        """

        self._packets = [
            (_udp_frame(), SockAddrLl(pkttype=PacketType.PACKET_OUTGOING)),
            (_arp_request_frame(), SockAddrLl(pkttype=PacketType.PACKET_HOST)),
        ]

    def test__cli__tcpdump__run_yields_formatted_lines_both_directions(self) -> None:
        """
        Ensure 'run_tcpdump' yields a direction-prefixed, decoded line per
        captured frame, in order, for both egress and ingress captures.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lines = list(run_tcpdump(_FakeCaptureSocket(self._packets), count=2))

        self.assertEqual(
            lines,
            [
                "Out IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5",
                "In ARP, Request who-has 10.0.1.7 tell 10.0.1.91",
            ],
            msg="run_tcpdump must yield one decoded, direction-tagged line per frame.",
        )

    def test__cli__tcpdump__run_honors_count_limit(self) -> None:
        """
        Ensure 'run_tcpdump' stops after 'count' frames rather than draining
        every available packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        lines = list(run_tcpdump(_FakeCaptureSocket(self._packets), count=1))

        self.assertEqual(len(lines), 1, msg="run_tcpdump must stop after 'count' frames.")

    def test__cli__tcpdump__run_rebases_timestamps_to_first_frame(self) -> None:
        """
        Ensure a supplied clock is rebased so the first captured frame reads
        0.0 s and later frames carry their delta from it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        clock = iter([100.0, 100.25]).__next__

        lines = list(run_tcpdump(_FakeCaptureSocket(self._packets), count=2, clock=clock))

        self.assertEqual(
            lines,
            [
                " 0.000000 Out IP 10.0.1.7.7 > 10.0.1.91.12345: UDP, length 5",
                " 0.250000 In ARP, Request who-has 10.0.1.7 tell 10.0.1.91",
            ],
            msg="run_tcpdump must rebase a supplied clock to the first captured frame.",
        )
