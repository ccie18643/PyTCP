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
Integration tests for the UDP IP_OPTIONS / IP_RECVOPTS socket
options. Together they implement RFC 1122 §4.1.3.2 — UDP MUST
pass any IP option received from the IP layer transparently to
the application layer, an application MUST be able to specify
IP options to be sent in its UDP datagrams, and UDP MUST pass
these options to the IP layer.

PyTCP's surface:
- 'setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)' stores the
  per-socket options block; 'sendto()' threads it into the
  outbound IPv4 packet handler.
- 'setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)' enables
  IP_OPTIONS cmsg emission on 'recvmsg(ancbufsize=...)'.

pytcp/tests/integration/protocols/udp/test__udp__ip_options.py

ver 3.0.9
"""

from typing import override

from net_addr import Ip4Address, Ip6Address, IpVersion, MacAddress
from net_proto import (
    EthernetAssembler,
    Ip4Assembler,
    Ip4OptionRouterAlert,
    Ip4Options,
    Ip4Parser,
    Ip6Assembler,
    UdpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp.runtime.socket import (
    IP_OPTIONS,
    IP_RECVOPTS,
    IP_RECVTOS,
    IP_TOS,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_RECVTCLASS,
    IPV6_TCLASS,
    AddressFamily,
)
from pytcp.tests.lib.udp_testcase import UdpTestCase

_STACK_MAC = MacAddress("02:00:00:00:00:07")
_STACK_IP4 = Ip4Address("10.0.1.7")
_STACK_IP6 = Ip6Address("2001:db8:0:1::7")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_HOST_A_IP4 = Ip4Address("10.0.1.91")
_HOST_A_IP6 = Ip6Address("2001:db8:0:1::91")
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555
_ROUTER_ALERT_BYTES = b"\x94\x04\x00\x00"


def _build_udp_frame_with_router_alert(*, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP datagram from HOST_A → STACK
    carrying a Router Alert IPv4 option (RFC 2113).
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_HOST_A_IP4,
                ip4__dst=_STACK_IP4,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


def _build_udp_frame_plain(*, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP datagram from HOST_A → STACK
    with no IPv4 options.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_HOST_A_IP4,
                ip4__dst=_STACK_IP4,
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


class TestUdpIpOptionsRecvmsgPassThrough(UdpTestCase):
    """
    Inbound IPv4 options surface via 'recvmsg' as IP_OPTIONS cmsg.
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv4 UdpSocket on the canonical fixture address so
        the RX dispatch hands the inbound datagram to the
        application-layer queue. 'UdpTestCase' snapshots
        'stack.sockets' so the registration does not leak.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=_STACK_IP4,
            local_port=_LOCAL_PORT,
        )

    def test__udp__ip_options__recvmsg_returns_cmsg_when_recvopts_enabled(self) -> None:
        """
        Ensure an inbound UDP datagram carrying IPv4 options
        surfaces through 'recvmsg(ancbufsize>0)' as an IP_OPTIONS
        ancillary-data cmsg when 'IP_RECVOPTS' is enabled on the
        receiving socket. The cmsg level / type / raw-bytes
        triple matches Linux's '<sys/socket.h>' shape.

        Reference: RFC 1122 §4.1.3.2 (UDP MUST pass received IP
        options to the application layer).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_with_router_alert(payload=b"hello")))

        data, ancdata, _flags, address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="recvmsg() must return the inbound UDP payload as bytes.",
        )
        self.assertEqual(
            address,
            (str(_HOST_A_IP4), _REMOTE_PORT),
            msg="recvmsg() address must be (host, port) for AF_INET.",
        )
        self.assertEqual(
            len(ancdata),
            1,
            msg="Datagram with IPv4 options must surface exactly one cmsg when IP_RECVOPTS=1.",
        )
        level, type_, value = ancdata[0]
        self.assertEqual(
            (level, type_, value),
            (int(IPPROTO_IP), int(IP_OPTIONS), _ROUTER_ALERT_BYTES),
            msg="IP_OPTIONS cmsg must carry (IPPROTO_IP, IP_OPTIONS, raw_options_bytes).",
        )

    def test__udp__ip_options__recvmsg_suppresses_cmsg_when_recvopts_disabled(self) -> None:
        """
        Ensure an inbound UDP datagram carrying IPv4 options
        delivers the payload through 'recvmsg' but omits the
        IP_OPTIONS cmsg when 'IP_RECVOPTS' is NOT set on the
        socket. Matches Linux's per-socket opt-in semantics —
        applications that do not request the cmsg do not see it.

        Reference: RFC 1122 §4.1.3.2 (IP_RECVOPTS gates the
        ancillary-data pass-through).
        """

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_with_router_alert(payload=b"hello")))

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="Payload must be delivered regardless of IP_RECVOPTS.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when IP_RECVOPTS is not set.",
        )

    def test__udp__ip_options__recvmsg_no_cmsg_when_no_options(self) -> None:
        """
        Ensure 'recvmsg' returns empty ancdata when the inbound
        datagram carries no IPv4 options, even with IP_RECVOPTS=1
        on the socket. The cmsg is only emitted for datagrams
        that actually carried options.

        Reference: RFC 1122 §4.1.3.2 (cmsg surface limited to
        options actually carried).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_plain(payload=b"hello")))

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="Payload must be delivered when the datagram carried no IPv4 options.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when no IPv4 options were carried.",
        )


class TestUdpIpOptionsSendto(UdpTestCase):
    """
    Outbound UDP datagrams carry the per-socket IP_OPTIONS block.
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv4 UdpSocket so 'sendto' has a stack-known
        local address / port to source from. 'UdpTestCase'
        snapshots 'stack.sockets'.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=_STACK_IP4,
            local_port=_LOCAL_PORT,
        )

    def test__udp__ip_options__sendto_emits_options_block_on_wire(self) -> None:
        """
        Ensure a UDP socket with 'setsockopt(IP_OPTIONS, bytes)'
        emits the options block on every outbound datagram. The
        outbound IPv4 header carries the configured options;
        'hlen' is bumped to cover them; the parsed options block
        round-trips back to the configured bytes.

        Reference: RFC 1122 §4.1.3.2 (application MUST be able to
        specify IP options to be sent).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_OPTIONS, _ROUTER_ALERT_BYTES)

        sent = self._socket.sendto(b"hello", (str(_HOST_A_IP4), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"hello"),
            msg="sendto() must report the full payload length when accepted by TxRing.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="One outbound UDP datagram must be emitted.",
        )

        # Strip Ethernet header to feed the IPv4 portion into the parser.
        ip4_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        self.assertEqual(
            ip4_parser.ver,
            IpVersion.IP4,
            msg="Outbound frame must be IPv4.",
        )
        self.assertEqual(
            ip4_parser.hlen,
            24,
            msg="hlen must be 24 (20-byte header + 4-byte Router Alert option).",
        )
        self.assertEqual(
            bytes(ip4_parser.options),
            _ROUTER_ALERT_BYTES,
            msg="Outbound IPv4 options block must equal the configured IP_OPTIONS bytes.",
        )

    def test__udp__ip_options__sendto_no_options_emits_unchanged_header(self) -> None:
        """
        Ensure a UDP socket without 'setsockopt(IP_OPTIONS, ...)'
        emits datagrams with the default 20-byte IPv4 header (no
        options). The default-empty IP_OPTIONS storage must not
        leak as an empty options block on the wire.

        Reference: RFC 1122 §4.1.3.2 (options are opt-in per
        socket).
        """

        sent = self._socket.sendto(b"hello", (str(_HOST_A_IP4), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"hello"),
            msg="sendto() must report the full payload length when accepted by TxRing.",
        )

        ip4_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        self.assertEqual(
            ip4_parser.hlen,
            20,
            msg="hlen must be 20 (default IPv4 header, no options) when IP_OPTIONS is unset.",
        )
        self.assertEqual(
            bytes(ip4_parser.options),
            b"",
            msg="Outbound IPv4 options block must be empty when IP_OPTIONS is unset.",
        )


def _build_udp_frame_ipv4_with_tos(*, dscp: int, ecn: int, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP datagram from HOST_A → STACK with
    the supplied DSCP and ECN bits (combined as the IPv4 TOS
    byte via '(dscp << 2) | ecn' on the wire).
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_HOST_A_IP4,
                ip4__dst=_STACK_IP4,
                ip4__dscp=dscp,
                ip4__ecn=ecn,
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


def _build_udp_frame_ipv6_with_tclass(*, dscp: int, ecn: int, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv6/UDP datagram from HOST_A → STACK
    with the supplied DSCP and ECN bits (combined as the IPv6
    Traffic Class byte via '(dscp << 2) | ecn' on the wire).
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip6Assembler(
                ip6__src=_HOST_A_IP6,
                ip6__dst=_STACK_IP6,
                ip6__dscp=dscp,
                ip6__ecn=ecn,
                ip6__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


class TestUdpIpRecvTos(UdpTestCase):
    """
    Inbound IPv4 TOS byte surfaces via 'recvmsg' as IP_TOS cmsg.
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv4 UdpSocket on the canonical fixture address.
        'UdpTestCase' snapshots 'stack.sockets'.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=_STACK_IP4,
            local_port=_LOCAL_PORT,
        )

    def test__udp__ip_recvtos__returns_tos_byte_when_enabled(self) -> None:
        """
        Ensure an inbound IPv4 UDP datagram with DSCP=48 / ECN=2
        surfaces through 'recvmsg(ancbufsize>0)' as an IP_TOS
        cmsg carrying the combined byte 0xC2 (one byte per
        Linux's 'ip(7)' wire shape) when 'IP_RECVTOS' is set on
        the receiving socket.

        Reference: RFC 1122 §4.1.4 (UDP MAY pass received TOS up
        to the application layer).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_ipv4_with_tos(dscp=48, ecn=2, payload=b"hello")))

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="recvmsg() must return the inbound UDP payload as bytes.",
        )
        self.assertEqual(
            ancdata,
            [(int(IPPROTO_IP), int(IP_TOS), b"\xc2")],
            msg="IP_TOS cmsg must carry the single-byte TOS value (DSCP<<2 | ECN).",
        )

    def test__udp__ip_recvtos__suppresses_cmsg_when_disabled(self) -> None:
        """
        Ensure an inbound IPv4 UDP datagram with a non-zero TOS
        byte delivers the payload through 'recvmsg' but omits
        the IP_TOS cmsg when 'IP_RECVTOS' is NOT set on the
        socket.

        Reference: RFC 1122 §4.1.4 (IP_RECVTOS gates the
        ancillary-data pass-through).
        """

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_ipv4_with_tos(dscp=48, ecn=2, payload=b"hello")))

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="Payload must be delivered regardless of IP_RECVTOS.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when IP_RECVTOS is not set.",
        )


class TestUdpIpV6RecvTClass(UdpTestCase):
    """
    Inbound IPv6 Traffic Class byte surfaces via 'recvmsg' as
    IPV6_TCLASS cmsg.
    """

    @override
    def setUp(self) -> None:
        """
        Bind an IPv6 UdpSocket on the canonical fixture address.
        'UdpTestCase' snapshots 'stack.sockets'.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET6,
            local_ip=_STACK_IP6,
            local_port=_LOCAL_PORT,
        )

    def test__udp__ipv6_recvtclass__returns_tclass_int_when_enabled(self) -> None:
        """
        Ensure an inbound IPv6 UDP datagram with DSCP=48 / ECN=2
        surfaces through 'recvmsg(ancbufsize>0)' as an
        IPV6_TCLASS cmsg carrying the combined byte 0xC2 as a
        4-byte big-endian integer (matching Linux's 'ipv6(7)'
        wire shape — sizeof(int)) when 'IPV6_RECVTCLASS' is
        set on the receiving socket.

        Reference: RFC 3542 §6.5 (IPv6 Traffic Class ancillary
        data).
        """

        self._socket.setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 1)

        self._packet_handler._phrx_ethernet(
            PacketRx(_build_udp_frame_ipv6_with_tclass(dscp=48, ecn=2, payload=b"hello"))
        )

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="recvmsg() must return the inbound IPv6 UDP payload as bytes.",
        )
        self.assertEqual(
            len(ancdata),
            1,
            msg="Datagram with non-zero TClass must surface one cmsg when IPV6_RECVTCLASS=1.",
        )
        level, type_, value = ancdata[0]
        self.assertEqual(
            (level, type_),
            (int(IPPROTO_IPV6), int(IPV6_TCLASS)),
            msg="IPV6_TCLASS cmsg must use (IPPROTO_IPV6, IPV6_TCLASS).",
        )
        self.assertEqual(
            int.from_bytes(value, "big"),
            0xC2,
            msg="IPV6_TCLASS cmsg value must be a 4-byte big-endian int matching the TClass byte.",
        )

    def test__udp__ipv6_recvtclass__suppresses_cmsg_when_disabled(self) -> None:
        """
        Ensure an inbound IPv6 UDP datagram with a non-zero
        Traffic Class byte delivers the payload through
        'recvmsg' but omits the IPV6_TCLASS cmsg when
        'IPV6_RECVTCLASS' is NOT set on the socket.

        Reference: RFC 3542 §6.5 (IPV6_RECVTCLASS gates the
        ancillary-data pass-through).
        """

        self._packet_handler._phrx_ethernet(
            PacketRx(_build_udp_frame_ipv6_with_tclass(dscp=48, ecn=2, payload=b"hello"))
        )

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="Payload must be delivered regardless of IPV6_RECVTCLASS.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when IPV6_RECVTCLASS is not set.",
        )
