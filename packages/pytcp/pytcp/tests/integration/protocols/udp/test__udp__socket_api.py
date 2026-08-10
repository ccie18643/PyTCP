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
End-to-end integration tests for the BSD UDP socket API.
Exercises the cross-module wiring between 'UdpSocket',
'PacketHandlerUdp' (RX + TX), the IPv4 / IPv6 layers, and the
ICMP error-delivery path — surfaces that are individually
unit-tested but only fully exercised end-to-end here.

Covers:
- bind() + inbound RX → recvfrom returns payload + sender address
- sendto() → outbound wire frame carries the correct fields
- Per-socket IP_TTL appears on the outbound IPv4 header
- ICMPv4 Destination Unreachable → next recv() raises
  ConnectionRefusedError on a connected socket

pytcp/tests/integration/protocols/udp/test__udp__socket_api.py

ver 3.0.9
"""

from typing import override

from net_addr import MacAddress
from net_proto import (
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Ip4Assembler,
    UdpAssembler,
)
from pytcp.runtime.socket import (
    IP_MTU,
    IP_TOS,
    IP_TTL,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_TCLASS,
    AddressFamily,
)
from pytcp.tests.lib.udp_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    UdpTestCase,
)

_STACK_MAC = MacAddress("02:00:00:00:00:07")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555


def _build_udp_frame_ipv4(*, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP datagram from HOST_A → STACK on
    the canonical fixture 4-tuple, no IP options, default TOS.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=HOST_A__IP4_ADDRESS,
                ip4__dst=STACK__IP4_HOST.address,
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


def _build_icmp4_unreachable_for_udp(
    *,
    code: Icmp4DestinationUnreachableCode,
    triggering_udp_4tuple_payload: bytes,
) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Destination Unreachable from
    HOST_A → STACK whose embedded payload is the IPv4+UDP header
    of an outbound datagram the stack sent to HOST_A:5555. The
    ICMP demux uses that embedded 4-tuple to find the matching
    UdpSocket and notify it.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=HOST_A__IP4_ADDRESS,
                ip4__dst=STACK__IP4_HOST.address,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageDestinationUnreachable(
                        code=code,
                        data=triggering_udp_4tuple_payload,
                    ),
                ),
            ),
        )
    )


class TestUdpSocketApiBindRx(UdpTestCase):
    """
    A bound UdpSocket receives inbound datagrams via the RX path.
    """

    @override
    def setUp(self) -> None:
        """
        Bind a UDP socket on STACK:4444 so the RX demux delivers
        the inbound datagram to it.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
        )

    def test__udp_socket_api__bind_recvfrom__round_trip(self) -> None:
        """
        Ensure an inbound IPv4 UDP datagram addressed to a bound
        socket appears on the socket's RX queue and 'recvfrom()'
        returns the payload paired with the sender's
        '(host, port)' tuple.

        Reference: RFC 9293 §3.9 (User/TCP interface; socket API
        bind / recv semantics apply to UDP via the same surface).
        """

        frame = _build_udp_frame_ipv4(payload=b"hello world")
        self._drive_udp_rx(frame=frame)

        data, address = self._recvfrom(self._socket)

        self.assertEqual(
            data,
            b"hello world",
            msg="recvfrom() must return the inbound UDP payload as bytes.",
        )
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT),
            msg="recvfrom() address must be the sender's (host, port).",
        )


class TestUdpSocketApiSendto(UdpTestCase):
    """
    sendto() emits a well-formed UDP datagram on the wire.
    """

    @override
    def setUp(self) -> None:
        """
        Bind a UDP socket on STACK:4444 with no remote so
        'sendto()' is the supported send path.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
        )

    def test__udp_socket_api__sendto__wire_frame_round_trip(self) -> None:
        """
        Ensure 'sendto()' emits a single Ethernet/IPv4/UDP frame
        whose source 4-tuple matches the socket's local address
        and port, whose destination 4-tuple matches the argument
        passed to 'sendto', and whose payload matches the
        supplied bytes.

        Reference: RFC 768 (UDP datagram structure on the wire).
        """

        sent = self._socket.sendto(b"hello", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"hello"),
            msg="sendto() must report the full payload length when accepted by TxRing.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="sendto() must emit exactly one outbound UDP frame.",
        )

        probe = self._parse_tx(self._frames_tx[0])
        self.assertEqual(
            probe.ip_src,
            STACK__IP4_HOST.address,
            msg="Outbound IPv4 src must be the socket's local IP address.",
        )
        self.assertEqual(
            probe.ip_dst,
            HOST_A__IP4_ADDRESS,
            msg="Outbound IPv4 dst must be the sendto() target IP.",
        )
        self.assertEqual(
            probe.sport,
            _LOCAL_PORT,
            msg="Outbound UDP sport must be the socket's local port.",
        )
        self.assertEqual(
            probe.dport,
            _REMOTE_PORT,
            msg="Outbound UDP dport must be the sendto() target port.",
        )
        self.assertEqual(
            probe.payload,
            b"hello",
            msg="Outbound UDP payload must be the sendto() argument bytes.",
        )


class TestUdpSocketApiSend(UdpTestCase):
    """
    send() on a connected UdpSocket emits a well-formed UDP
    datagram on the wire. Exercises the connected-socket send
    path which differs from sendto() in that it uses the
    pre-set '_remote_ip_address' / '_remote_port' instead of
    taking the destination as an argument.
    """

    @override
    def setUp(self) -> None:
        """
        Bind + connect a UDP socket to HOST_A:5555 so the
        'send()' API has a destination set.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )

    def test__udp_socket_api__send__on_connected_socket_emits_wire_frame(self) -> None:
        """
        Ensure 'send()' on a connected UdpSocket emits a single
        Ethernet/IPv4/UDP frame whose 4-tuple matches the
        socket's connected pair and whose payload matches the
        argument bytes. Exercises the connected-socket send
        path that 'sendto()' bypasses.

        Reference: RFC 9293 §3.9 (BSD socket connect+send
        semantics; applies to UDP via the same surface).
        """

        sent = self._socket.send(b"connected payload")

        self.assertEqual(
            sent,
            len(b"connected payload"),
            msg="send() must report the full payload length when accepted by TxRing.",
        )

        probe = self._parse_tx(self._frames_tx[0])
        self.assertEqual(
            probe.ip_dst,
            HOST_A__IP4_ADDRESS,
            msg="Outbound IPv4 dst must equal the socket's connected remote address.",
        )
        self.assertEqual(
            probe.dport,
            _REMOTE_PORT,
            msg="Outbound UDP dport must equal the socket's connected remote port.",
        )
        self.assertEqual(
            probe.payload,
            b"connected payload",
            msg="Outbound UDP payload must equal the send() argument bytes.",
        )


class TestUdpSocketApiSendmsg(UdpTestCase):
    """
    sendmsg() concatenates its scatter-gather buffers into one
    datagram that lands on the wire intact.
    """

    @override
    def setUp(self) -> None:
        """
        Bind a UDP socket on STACK:4444 with no remote so the
        'sendmsg(address=...)' send path is exercised.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
        )

    def test__udp_socket_api__sendmsg__concatenated_buffers_round_trip(self) -> None:
        """
        Ensure 'sendmsg()' concatenates its scatter-gather buffer
        list into a single Ethernet/IPv4/UDP frame whose payload is
        the buffers joined in order and whose destination 4-tuple
        matches the 'address' argument.

        Reference: RFC 768 (UDP datagram structure on the wire).
        """

        sent = self._socket.sendmsg(
            [b"foo", b"bar", b"baz"],
            address=(str(HOST_A__IP4_ADDRESS), _REMOTE_PORT),
        )

        self.assertEqual(
            sent,
            len(b"foobarbaz"),
            msg="sendmsg() must report the total length of all concatenated buffers.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="sendmsg() must emit exactly one outbound UDP frame.",
        )

        probe = self._parse_tx(self._frames_tx[0])
        self.assertEqual(
            probe.ip_dst,
            HOST_A__IP4_ADDRESS,
            msg="Outbound IPv4 dst must be the sendmsg() target IP.",
        )
        self.assertEqual(
            probe.dport,
            _REMOTE_PORT,
            msg="Outbound UDP dport must be the sendmsg() target port.",
        )
        self.assertEqual(
            probe.payload,
            b"foobarbaz",
            msg="Outbound UDP payload must be the sendmsg() buffers concatenated in order.",
        )


class TestUdpSocketApiIpTtlOnWire(UdpTestCase):
    """
    A per-socket IP_TTL override appears on the outbound IPv4
    header. The plumbing from setsockopt(IP_TTL) → send_udp_packet
    is unit-tested; this integration test pins the value as it
    actually appears on the wire.
    """

    @override
    def setUp(self) -> None:
        """Bind an IPv4 UDP socket on the canonical fixture."""

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
        )

    def test__udp_socket_api__ip_ttl__appears_on_outbound_wire(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IP, IP_TTL, N)' makes every
        outbound IPv4 UDP datagram from that socket carry 'N' in
        its TTL field, not the stack default.

        Reference: RFC 791 §3.1 (TTL field); RFC 1122 §4.1.4
        (application MUST be able to specify TTL per-datagram).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_TTL, 7)

        self._socket.sendto(b"x", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        probe = self._parse_tx(self._frames_tx[0])
        self.assertEqual(
            probe.ip_ttl,
            7,
            msg="setsockopt(IP_TTL, 7) must thread through to the outbound IPv4 TTL field.",
        )


class TestUdpSocketApiIpDscpOnWire(UdpTestCase):
    """
    A per-socket IP_TOS / IPV6_TCLASS DSCP marking appears on the
    outbound IP header. Pins the DSCP (high 6 bits) threading from
    setsockopt → the wire, alongside the already-shipped ECN (low 2).
    """

    def test__udp_socket_api__ip_tos_dscp__appears_on_outbound_ipv4_wire(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IP, IP_TOS, dscp<<2 | ecn)' makes
        every outbound IPv4 UDP datagram carry the DSCP value in the
        high 6 bits of the TOS byte and the ECN in the low 2.

        Reference: RFC 2474 §3 (DS field — DSCP high 6 / ECN low 2).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
        )
        # DSCP 46 (EF) with ECN ECT(0) = (46 << 2) | 2 = 0xBA.
        sock.setsockopt(IPPROTO_IP, IP_TOS, (46 << 2) | 2)

        sock.sendto(b"x", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        probe = self._parse_tx(self._frames_tx[0])
        self.assertEqual(
            probe.ip_dscp,
            46,
            msg="setsockopt(IP_TOS) DSCP bits must thread through to the outbound IPv4 'dscp' field.",
        )
        self.assertEqual(
            probe.ip_ecn,
            2,
            msg="The IP_TOS ECN bits must still appear on the outbound IPv4 'ecn' field.",
        )

    def test__udp_socket_api__ipv6_tclass_dscp__appears_on_outbound_ipv6_wire(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IPV6, IPV6_TCLASS, dscp<<2 | ecn)'
        makes every outbound IPv6 UDP datagram carry the DSCP value in
        the high 6 bits of the Traffic Class field and the ECN in the
        low 2.

        Reference: RFC 2474 §3 (DS field — DSCP high 6 / ECN low 2).
        """

        sock = self._bind_udp_socket(
            family=AddressFamily.INET6,
            local_ip=STACK__IP6_HOST.address,
            local_port=_LOCAL_PORT,
        )
        sock.setsockopt(IPPROTO_IPV6, IPV6_TCLASS, (46 << 2) | 2)

        sock.sendto(b"x", (str(HOST_A__IP6_ADDRESS), _REMOTE_PORT))

        probe = self._parse_tx(self._frames_tx[0])
        self.assertEqual(
            probe.ip_dscp,
            46,
            msg="setsockopt(IPV6_TCLASS) DSCP bits must thread through to the outbound IPv6 'dscp' field.",
        )
        self.assertEqual(
            probe.ip_ecn,
            2,
            msg="The IPV6_TCLASS ECN bits must still appear on the outbound IPv6 'ecn' field.",
        )


class TestUdpSocketApiIpMtuGetsockopt(UdpTestCase):
    """
    getsockopt(IP_MTU) on a connected UDP socket returns the
    cached Path-MTU updated by an inbound ICMPv4 Frag-Needed.
    Pins the end-to-end wiring: ICMPv4 RX demux → pmtu_cache
    update → getsockopt readback.
    """

    @override
    def setUp(self) -> None:
        """
        Bind + connect a UDP socket to HOST_A:5555 so the
        ICMPv4 demux finds it via the embedded 4-tuple. The
        egress interface's MTU (1500 in the harness) is the
        "no cache entry" fallback the assertions below pin.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )

    def test__udp_socket_api__ip_mtu__fallback_to_interface_mtu_without_pmtud(self) -> None:
        """
        Ensure getsockopt(IPPROTO_IP, IP_MTU) returns the egress
        interface's link MTU when no ICMPv4 Frag-Needed has
        landed for the connected peer yet.

        Reference: RFC 1122 §3.4 (GET_MAXSIZES; link-MTU is the
        baseline before PMTUD narrows it).
        """

        self.assertEqual(
            self._socket.getsockopt(IPPROTO_IP, IP_MTU),
            1500,
            msg="IP_MTU must return the egress interface MTU when pmtu_cache is empty.",
        )

    def test__udp_socket_api__ip_mtu__updates_after_icmp_frag_needed(self) -> None:
        """
        Ensure an inbound ICMPv4 Type 3 Code 4 (Fragmentation
        Needed) frame whose embedded IPv4+UDP header matches
        the connected socket's 4-tuple updates
        'stack.pmtu_cache' for the remote address, and a
        subsequent getsockopt(IP_MTU) returns the advertised
        next-hop MTU.

        Reference: RFC 1191 §3 (Path-MTU discovery).
        Reference: RFC 1122 §3.4 (GET_MAXSIZES surfaces the
        learned PMTU to the application).
        """

        # Stage 1: emit a UDP datagram so the ICMPv4 demux can
        # match the embedded 4-tuple to our socket.
        self._socket.sendto(b"probe", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        outbound_frame = self._frames_tx[-1]
        embedded_ip4_and_udp = outbound_frame[14:]

        # Stage 2: ICMPv4 Frag-Needed carrying that embedded
        # datagram + the new next-hop MTU.
        frag_needed_frame = bytes(
            EthernetAssembler(
                ethernet__src=_HOST_A_MAC,
                ethernet__dst=_STACK_MAC,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__payload=Icmp4Assembler(
                        icmp4__message=Icmp4MessageDestinationUnreachable(
                            code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                            mtu=1280,
                            data=embedded_ip4_and_udp,
                        ),
                    ),
                ),
            )
        )
        self._drive_udp_rx(frame=frag_needed_frame)

        # Stage 3: the pmtu_cache update is now visible via
        # IP_MTU.
        self.assertEqual(
            self._socket.getsockopt(IPPROTO_IP, IP_MTU),
            1280,
            msg="IP_MTU must return the ICMPv4-advertised next-hop MTU after PMTUD.",
        )


class TestUdpSocketApiIcmpUnreachable(UdpTestCase):
    """
    ICMPv4 Destination Unreachable for an outbound UDP datagram
    is delivered to the originating socket via notify_unreachable;
    the next recv() raises ConnectionRefusedError per BSD
    semantics on a connected socket.
    """

    @override
    def setUp(self) -> None:
        """
        Bind a UDP socket on STACK:4444 and connect it to
        HOST_A:5555 — the connected pair is the 4-tuple the
        ICMP demux uses to find the socket from the embedded
        UDP header.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )

    def test__udp_socket_api__icmp4_unreachable__next_recv_raises(self) -> None:
        """
        Ensure an inbound ICMPv4 Destination Unreachable whose
        embedded payload identifies a UDP datagram sent from the
        connected socket flags the socket unreachable; the next
        'recv()' raises 'ConnectionRefusedError' (errno ECONNREFUSED)
        and clears the flag.

        Reference: RFC 1122 §4.1.3.3 (UDP MUST pass ICMP errors
        up to the application layer).
        """

        # Stage 1: outbound UDP datagram so the ICMP demux has a
        # real wire frame to embed in the unreachable reply.
        self._socket.sendto(b"probe", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        outbound_frame = self._frames_tx[-1]
        # Strip Ethernet header (14 bytes) — ICMP embeds the IPv4
        # header onward.
        embedded_ip4_and_udp = outbound_frame[14:]

        # Stage 2: ICMPv4 Port Unreachable referencing that
        # datagram.
        unreachable_frame = _build_icmp4_unreachable_for_udp(
            code=Icmp4DestinationUnreachableCode.PORT,
            triggering_udp_4tuple_payload=embedded_ip4_and_udp,
        )
        self._drive_udp_rx(frame=unreachable_frame)

        # Stage 3: next recv() must raise.
        with self.assertRaises(ConnectionRefusedError) as ctx:
            self._socket.recv(timeout=0.1)

        import errno

        self.assertEqual(
            ctx.exception.errno,
            errno.ECONNREFUSED,
            msg="recv() after notify_unreachable must raise ConnectionRefusedError with ECONNREFUSED.",
        )

        # Stage 4: the unreachable flag must be cleared by the
        # raise so a subsequent recv() does not re-raise.
        self.assertFalse(
            self._socket._unreachable,
            msg="The unreachable flag must be cleared after raising ConnectionRefusedError.",
        )


class TestUdpSocketApiIpRecverr(UdpTestCase):
    """
    Inbound ICMPv4 Destination Unreachable populates the
    per-socket error queue when IP_RECVERR=1; the queued
    entry surfaces via 'recvmsg(MSG_ERRQUEUE)' with the
    embedded datagram + Linux-shape cmsg.
    """

    @override
    def setUp(self) -> None:
        """
        Bind + connect a UDP socket so the ICMPv4 demux can
        match the embedded 4-tuple to this socket.
        """

        super().setUp()
        self._socket = self._bind_udp_socket(
            family=AddressFamily.INET4,
            local_ip=STACK__IP4_HOST.address,
            local_port=_LOCAL_PORT,
            remote_ip=HOST_A__IP4_ADDRESS,
            remote_port=_REMOTE_PORT,
        )

    def test__udp_socket_api__ip_recverr__port_unreachable_surfaces_via_errqueue(self) -> None:
        """
        Ensure an inbound ICMPv4 Port Unreachable matched to a
        connected UDP socket with 'IP_RECVERR=1' appears on the
        per-socket error queue and dequeues via
        'recvmsg(flags=MSG_ERRQUEUE)' with the embedded
        outbound datagram as the data portion and an
        'IP_RECVERR' cmsg whose 32-byte payload packs the
        Linux 'sock_extended_err' (origin=ICMP, type=3,
        code=3, errno=ECONNREFUSED) + offender 'sockaddr_in'.

        Reference: RFC 1122 §4.1.3.3 (UDP MUST pass ICMP
        errors up to the application).
        Reference: Linux 'ip(7)' (IP_RECVERR cmsg wire shape).
        """

        from pytcp.runtime.socket import IP_RECVERR, IPPROTO_IP, MSG_ERRQUEUE

        self._socket.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        # Stage 1: outbound UDP datagram (drives the demux's
        # embedded-4-tuple matcher).
        self._socket.sendto(b"probe", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        outbound_frame = self._frames_tx[-1]
        embedded_ip4_and_udp = outbound_frame[14:]

        # Stage 2: ICMPv4 Port Unreachable referencing that
        # datagram.
        unreachable_frame = _build_icmp4_unreachable_for_udp(
            code=Icmp4DestinationUnreachableCode.PORT,
            triggering_udp_4tuple_payload=embedded_ip4_and_udp,
        )
        self._drive_udp_rx(frame=unreachable_frame)

        # Stage 3: dequeue via recvmsg(MSG_ERRQUEUE). Data is
        # the embedded triggering datagram (the IPv4+UDP
        # header + payload from stage 1).
        data, ancdata, flags, address = self._socket.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        self.assertEqual(
            data,
            embedded_ip4_and_udp,
            msg="recvmsg(MSG_ERRQUEUE) data must be the embedded triggering datagram.",
        )
        self.assertEqual(
            flags,
            int(MSG_ERRQUEUE),
            msg="msg_flags must include the MSG_ERRQUEUE bit.",
        )
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), 0),
            msg="recvmsg address must be the ICMP offender's IP (port=0).",
        )

        self.assertEqual(len(ancdata), 1)
        level, type_, value = ancdata[0]
        self.assertEqual(level, int(IPPROTO_IP))
        self.assertEqual(type_, int(IP_RECVERR))
        self.assertEqual(
            len(value),
            32,
            msg="sock_extended_err (16) + sockaddr_in (16) = 32 bytes.",
        )

        # Unpack ee_errno / ee_origin / ee_type / ee_code from
        # the cmsg payload to verify Linux-shape parity.
        import struct

        ee_errno, ee_origin, ee_type, ee_code = struct.unpack("=IBBB", value[:7])
        import errno as errno_mod

        self.assertEqual(
            ee_errno,
            errno_mod.ECONNREFUSED,
            msg="ee_errno must map ICMPv4 type=3 code=3 to ECONNREFUSED.",
        )
        self.assertEqual(ee_origin, 2, msg="SoEeOrigin.ICMP == 2")
        self.assertEqual(ee_type, 3, msg="ICMPv4 Destination Unreachable type=3")
        self.assertEqual(ee_code, 3, msg="ICMPv4 Port Unreachable code=3")

    def test__udp_socket_api__ip_recverr__disabled_empty_queue(self) -> None:
        """
        Ensure an inbound ICMPv4 Port Unreachable does NOT
        populate the error queue when 'IP_RECVERR=0' (default).
        The legacy 'ConnectionRefusedError' path on next
        'recv()' still fires (covered by
        TestUdpSocketApiIcmpUnreachable above).

        Reference: RFC 1122 §4.1.3.3 (per-socket opt-in to
        the error-queue surface).
        """

        from pytcp.runtime.socket import MSG_ERRQUEUE

        self._socket.sendto(b"probe", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        embedded_ip4_and_udp = self._frames_tx[-1][14:]

        unreachable_frame = _build_icmp4_unreachable_for_udp(
            code=Icmp4DestinationUnreachableCode.PORT,
            triggering_udp_4tuple_payload=embedded_ip4_and_udp,
        )
        self._drive_udp_rx(frame=unreachable_frame)

        with self.assertRaises(TimeoutError):
            self._socket.recvmsg(ancbufsize=256, flags=MSG_ERRQUEUE, timeout=0.01)
