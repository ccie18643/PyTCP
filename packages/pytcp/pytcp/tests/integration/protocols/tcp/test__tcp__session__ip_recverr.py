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
End-to-end integration tests for the TCP IP_RECVERR / IPV6_RECVERR
socket-API surface. Exercises:

  * 'setsockopt(IPPROTO_IP, IP_RECVERR, 1)' / IPV6 round-trip on a
    TcpSocket.
  * ICMPv4 Destination Unreachable / Time Exceeded / Parameter
    Problem / Fragmentation Needed targeting an embedded TCP
    4-tuple matched to an installed TcpSocket appends an
    'ErrorQueueEntry' with the Linux 'sock_extended_err' field
    mapping (origin, type, code, errno, ee_info=MTU on PMTU).
  * ICMPv6 Destination Unreachable / Packet Too Big parallel.
  * 'recvmsg(flags=MSG_ERRQUEUE)' dequeues with the Linux wire
    shape: (embedded_datagram, [(IPPROTO_IP, IP_RECVERR,
    packed_sock_extended_err)], MSG_ERRQUEUE, (offender_ip, 0)).
  * Gating: without IP_RECVERR set, errors don't accumulate.
  * Bounded queue: 33rd entry drops the oldest (FIFO).
  * FSM-independence: errors queued during SYN_SENT survive
    transition to CLOSED.

pytcp/tests/integration/protocols/tcp/test__tcp__session__ip_recverr.py

ver 3.0.8
"""

import errno as errno_mod
import struct

from net_addr import Ip4Address, Ip6Address
from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageParameterProblem,
    Icmp4MessageTimeExceeded,
    Icmp4ParameterProblemCode,
    Icmp4TimeExceededCode,
    Icmp6Assembler,
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessagePacketTooBig,
    Ip4Assembler,
    Ip6Assembler,
    TcpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.socket import (
    IP_RECVERR,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPV6_RECVERR,
    MSG_ERRQUEUE,
    AddressFamily,
)
from pytcp.socket.error_queue import ERROR_QUEUE__MAX_LEN, SoEeOrigin
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP4: Ip4Address = STACK__IP4_HOST.address
STACK__IP6: Ip6Address = STACK__IP6_HOST.address
STACK__PORT: int = 12345
PEER__IP4: Ip4Address = HOST_A__IP4_ADDRESS
PEER__IP6: Ip6Address = HOST_A__IP6_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000
NEXT_HOP_MTU: int = 1400


# ---------------------------------------------------------------------------
# Frame builders.
# ---------------------------------------------------------------------------


def _embedded_tcp4(*, embedded_seq: int) -> bytes:
    """
    Build the IPv4+TCP SYN segment quoted inside an ICMPv4 error
    targeting the (STACK → PEER : STACK__PORT → PEER__PORT) flow.
    """

    return bytes(
        Ip4Assembler(
            ip4__src=STACK__IP4,
            ip4__dst=PEER__IP4,
            ip4__payload=TcpAssembler(
                tcp__sport=STACK__PORT,
                tcp__dport=PEER__PORT,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )


def _embedded_tcp6(*, embedded_seq: int) -> bytes:
    """
    Build the IPv6+TCP SYN segment quoted inside an ICMPv6 error
    targeting the (STACK → PEER : STACK__PORT → PEER__PORT) flow.
    """

    return bytes(
        Ip6Assembler(
            ip6__src=STACK__IP6,
            ip6__dst=PEER__IP6,
            ip6__payload=TcpAssembler(
                tcp__sport=STACK__PORT,
                tcp__dport=PEER__PORT,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )


def _icmp4_dest_unreach_frame(
    *,
    code: Icmp4DestinationUnreachableCode,
    embedded_seq: int = LOCAL__ISS,
    mtu: int = 0,
) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Destination Unreachable frame
    whose embedded data is an IPv4+TCP SYN. 'mtu' applies only to
    Code 4 (FRAGMENTATION_NEEDED).
    """

    icmp_kwargs: dict[str, object] = {
        "code": code,
        "data": _embedded_tcp4(embedded_seq=embedded_seq),
    }
    if mtu:
        icmp_kwargs["mtu"] = mtu

    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageDestinationUnreachable(**icmp_kwargs),  # type: ignore[arg-type]
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP4,
            ip4__dst=STACK__IP4,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


def _icmp4_time_exceeded_frame(*, embedded_seq: int = LOCAL__ISS) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Time Exceeded frame whose
    embedded data is an IPv4+TCP SYN.
    """

    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageTimeExceeded(
            code=Icmp4TimeExceededCode.TTL_EXCEEDED_IN_TRANSIT,
            data=_embedded_tcp4(embedded_seq=embedded_seq),
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP4,
            ip4__dst=STACK__IP4,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


def _icmp4_parameter_problem_frame(*, embedded_seq: int = LOCAL__ISS) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Parameter Problem frame whose
    embedded data is an IPv4+TCP SYN.
    """

    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageParameterProblem(
            code=Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
            pointer=0,
            data=_embedded_tcp4(embedded_seq=embedded_seq),
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP4,
            ip4__dst=STACK__IP4,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


def _icmp6_dest_unreach_frame(
    *,
    code: Icmp6DestinationUnreachableCode,
    embedded_seq: int = LOCAL__ISS,
) -> bytes:
    """
    Build an Ethernet/IPv6/ICMPv6 Destination Unreachable frame
    whose embedded data is an IPv6+TCP SYN.
    """

    icmp = Icmp6Assembler(
        icmp6__message=Icmp6MessageDestinationUnreachable(
            code=code,
            data=_embedded_tcp6(embedded_seq=embedded_seq),
        ),
    )
    ip6 = bytes(
        Ip6Assembler(
            ip6__src=PEER__IP6,
            ip6__dst=STACK__IP6,
            ip6__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd" + ip6


def _icmp6_packet_too_big_frame(*, mtu: int, embedded_seq: int = LOCAL__ISS) -> bytes:
    """
    Build an Ethernet/IPv6/ICMPv6 Packet Too Big frame whose
    embedded data is an IPv6+TCP SYN.
    """

    icmp = Icmp6Assembler(
        icmp6__message=Icmp6MessagePacketTooBig(
            mtu=mtu,
            data=_embedded_tcp6(embedded_seq=embedded_seq),
        ),
    )
    ip6 = bytes(
        Ip6Assembler(
            ip6__src=PEER__IP6,
            ip6__dst=STACK__IP6,
            ip6__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd" + ip6


# ---------------------------------------------------------------------------
# Session fixture helpers.
# ---------------------------------------------------------------------------


def _make_syn_sent_session(
    test: TcpTestCase,
    *,
    family: AddressFamily = AddressFamily.INET4,
) -> tuple[TcpSocket, TcpSession]:
    """
    Build a SYN_SENT-state TcpSocket/TcpSession pair on the
    canonical 4-tuple. Mirrors '_make_syn_sent_session' helpers in
    the existing ICMP-TCP test files.
    """

    test._force_iss(LOCAL__ISS)
    local_ip: Ip4Address | Ip6Address
    remote_ip: Ip4Address | Ip6Address
    if family is AddressFamily.INET4:
        local_ip = STACK__IP4
        remote_ip = PEER__IP4
    else:
        local_ip = STACK__IP6
        remote_ip = PEER__IP6
    sock = TcpSocket(family=family)
    sock._local_ip_address = local_ip
    sock._local_port = STACK__PORT
    sock._remote_ip_address = remote_ip
    sock._remote_port = PEER__PORT
    session = TcpSession(
        local_ip_address=local_ip,
        local_port=STACK__PORT,
        remote_ip_address=remote_ip,
        remote_port=PEER__PORT,
        socket=sock,
    )
    sock._tcp_session = session
    stack.sockets[sock.socket_id] = sock
    session.tcp_fsm(syscall=SysCall.CONNECT)
    test._advance(ms=1)
    assert session.state is FsmState.SYN_SENT
    return sock, session


# ---------------------------------------------------------------------------
# IP_RECVERR / IPV6_RECVERR round-trip.
# ---------------------------------------------------------------------------


class TestTcpIpRecverrRoundTrip(TcpTestCase):
    """
    The TcpSocket IP_RECVERR / IPV6_RECVERR setsockopt/getsockopt
    round-trip tests.
    """

    def test__tcp__ip_recverr__default_is_zero(self) -> None:
        """
        Ensure a freshly-constructed TcpSocket reports IP_RECVERR=0
        until the application opts in via setsockopt; this is the
        Linux default behaviour and matches the UDP parallel.

        Reference: Linux 'ip(7)' (IP_RECVERR default off).
        """

        sock = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IP, IP_RECVERR),
            0,
            msg="IP_RECVERR default must be 0 (off) on a fresh socket.",
        )

    def test__tcp__ip_recverr__setsockopt_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_IP, IP_RECVERR, 1)' flips the
        flag and 'getsockopt' returns 1, then setting 0 turns it
        back off — symmetric Linux 'ip(7)' surface.

        Reference: Linux 'ip(7)' (IP_RECVERR get/set symmetry).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IP, IP_RECVERR),
            1,
            msg="After setsockopt(IP_RECVERR=1) getsockopt must return 1.",
        )

        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 0)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IP, IP_RECVERR),
            0,
            msg="After setsockopt(IP_RECVERR=0) getsockopt must return 0.",
        )

    def test__tcp__ipv6_recverr__setsockopt_round_trip(self) -> None:
        """
        Ensure the IPv6 parallel 'IPV6_RECVERR' get/set round-trip
        on an INET6 TcpSocket. IPV6_RECVERR is the gate for the
        ICMPv6 error queue surface.

        Reference: Linux 'ipv6(7)' (IPV6_RECVERR get/set symmetry).
        """

        sock = TcpSocket(family=AddressFamily.INET6)
        sock.setsockopt(IPPROTO_IPV6, IPV6_RECVERR, 1)

        self.assertEqual(
            sock.getsockopt(IPPROTO_IPV6, IPV6_RECVERR),
            1,
            msg="After setsockopt(IPV6_RECVERR=1) getsockopt must return 1.",
        )


# ---------------------------------------------------------------------------
# ICMPv4 error-queue end-to-end.
# ---------------------------------------------------------------------------


class TestTcpIpRecverrIcmp4DestUnreachable(TcpTestCase):
    """
    The TCP IP_RECVERR ICMPv4 Destination Unreachable end-to-end
    queue + recvmsg tests.
    """

    def test__tcp__ip_recverr__icmp4_port_unreach__enqueues(self) -> None:
        """
        Ensure an ICMPv4 Port Unreachable matching a TcpSocket with
        IP_RECVERR=1 appears on the per-socket error queue and
        dequeues via recvmsg(MSG_ERRQUEUE) with errno=ECONNREFUSED,
        origin=SoEeOrigin.ICMP, type=3, code=3, offender=PEER, and
        the embedded data equal to the ICMP error 'data' field.

        Reference: RFC 1122 §4.2.3.9 (TCP MUST report ICMP errors).
        Reference: Linux 'ip(7)' (IP_RECVERR cmsg wire shape).
        """

        sock, _ = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        frame = _icmp4_dest_unreach_frame(
            code=Icmp4DestinationUnreachableCode.PORT,
        )
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        data, ancdata, flags, address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        self.assertEqual(
            flags,
            int(MSG_ERRQUEUE),
            msg="msg_flags must include MSG_ERRQUEUE.",
        )
        self.assertEqual(
            address,
            (str(PEER__IP4), 0),
            msg="recvmsg address must be the ICMP offender (port=0).",
        )
        # The embedded datagram is the ICMP message 'data' field,
        # which is the IPv4+TCP SYN built in '_embedded_tcp4'.
        self.assertEqual(
            data,
            _embedded_tcp4(embedded_seq=LOCAL__ISS),
            msg="recvmsg(MSG_ERRQUEUE) data must equal the embedded triggering segment.",
        )

        self.assertEqual(len(ancdata), 1, msg="One cmsg per dequeued error.")
        level, type_, value = ancdata[0]
        self.assertEqual(level, int(IPPROTO_IP))
        self.assertEqual(type_, int(IP_RECVERR))
        self.assertEqual(
            len(value),
            32,
            msg="sock_extended_err (16) + sockaddr_in (16) = 32 bytes.",
        )

        ee_errno, ee_origin, ee_type, ee_code = struct.unpack("=IBBB", value[:7])
        self.assertEqual(
            ee_errno,
            errno_mod.ECONNREFUSED,
            msg="ICMPv4 type=3 code=3 must map to ECONNREFUSED.",
        )
        self.assertEqual(ee_origin, int(SoEeOrigin.ICMP))
        self.assertEqual(ee_type, 3)
        self.assertEqual(ee_code, 3)

    def test__tcp__ip_recverr__icmp4_host_unreach__maps_to_ehostunreach(self) -> None:
        """
        Ensure an ICMPv4 Host Unreachable (Type=3 Code=1) maps to
        EHOSTUNREACH in the queued ErrorQueueEntry, matching the
        Linux 'icmp_err_convert' table.

        Reference: Linux net/ipv4/icmp.c::icmp_err_convert.
        """

        sock, _ = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        frame = _icmp4_dest_unreach_frame(
            code=Icmp4DestinationUnreachableCode.HOST,
        )
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        _data, ancdata, _flags, _address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        ee_errno = struct.unpack("=I", ancdata[0][2][:4])[0]
        self.assertEqual(
            ee_errno,
            errno_mod.EHOSTUNREACH,
            msg="ICMPv4 type=3 code=1 must map to EHOSTUNREACH.",
        )


class TestTcpIpRecverrIcmp4FragNeeded(TcpTestCase):
    """
    The TCP IP_RECVERR ICMPv4 Fragmentation Needed (RFC 1191 PMTUD)
    queue tests.
    """

    def test__tcp__ip_recverr__icmp4_frag_needed__emsgsize_with_mtu(self) -> None:
        """
        Ensure an ICMPv4 Fragmentation Needed with next-hop MTU
        targeting a TcpSocket with IP_RECVERR=1 queues an
        ErrorQueueEntry with errno=EMSGSIZE and ee_info=MTU per
        Linux semantics, in parallel with the existing PMTU FSM
        event.

        Reference: RFC 1191 §3 (PMTUD next-hop MTU in ICMP).
        Reference: Linux 'ip(7)' (EMSGSIZE + ee_info=MTU on PMTU).
        """

        sock, _ = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        frame = _icmp4_dest_unreach_frame(
            code=Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
            mtu=NEXT_HOP_MTU,
        )
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        _data, ancdata, _flags, _address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        ee_errno, ee_origin, ee_type, ee_code, _pad, ee_info = struct.unpack("=IBBBBI", ancdata[0][2][:12])
        self.assertEqual(
            ee_errno,
            errno_mod.EMSGSIZE,
            msg="Frag-Needed must map to EMSGSIZE.",
        )
        self.assertEqual(ee_origin, int(SoEeOrigin.ICMP))
        self.assertEqual(ee_type, 3)
        self.assertEqual(ee_code, 4)
        self.assertEqual(
            ee_info,
            NEXT_HOP_MTU,
            msg="ee_info must carry the next-hop MTU from the ICMP message.",
        )


class TestTcpIpRecverrIcmp4TimeExceeded(TcpTestCase):
    """
    The TCP IP_RECVERR ICMPv4 Time Exceeded queue tests.
    """

    def test__tcp__ip_recverr__icmp4_time_exceeded__enqueues(self) -> None:
        """
        Ensure an ICMPv4 Time Exceeded targeting a TcpSocket with
        IP_RECVERR=1 queues an ErrorQueueEntry with type=11 and
        errno=EHOSTUNREACH per Linux's icmp_err_convert.

        Reference: RFC 1122 §3.2.2.4 (Time Exceeded pass to transport).
        """

        sock, _ = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        self._packet_handler._phrx_ethernet(_packet_rx(_icmp4_time_exceeded_frame()))

        _data, ancdata, _flags, _address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        ee_errno, _ee_origin, ee_type, _ee_code = struct.unpack("=IBBB", ancdata[0][2][:7])
        self.assertEqual(
            ee_errno,
            errno_mod.EHOSTUNREACH,
            msg="ICMPv4 Time Exceeded must map to EHOSTUNREACH.",
        )
        self.assertEqual(
            ee_type,
            11,
            msg="ee_type must be ICMPv4 Time Exceeded (11).",
        )


class TestTcpIpRecverrIcmp4ParameterProblem(TcpTestCase):
    """
    The TCP IP_RECVERR ICMPv4 Parameter Problem queue tests.
    """

    def test__tcp__ip_recverr__icmp4_parameter_problem__enqueues(self) -> None:
        """
        Ensure an ICMPv4 Parameter Problem targeting a TcpSocket
        with IP_RECVERR=1 queues an ErrorQueueEntry with type=12
        and errno=EPROTO per Linux's icmp_err_convert.

        Reference: RFC 1122 §3.2.2.5 (Parameter Problem pass to transport).
        """

        sock, _ = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        self._packet_handler._phrx_ethernet(_packet_rx(_icmp4_parameter_problem_frame()))

        _data, ancdata, _flags, _address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        ee_errno, _ee_origin, ee_type, _ee_code = struct.unpack("=IBBB", ancdata[0][2][:7])
        self.assertEqual(
            ee_errno,
            errno_mod.EPROTO,
            msg="ICMPv4 Parameter Problem must map to EPROTO.",
        )
        self.assertEqual(
            ee_type,
            12,
            msg="ee_type must be ICMPv4 Parameter Problem (12).",
        )


# ---------------------------------------------------------------------------
# ICMPv6 error-queue end-to-end.
# ---------------------------------------------------------------------------


class TestTcpIpRecverrIcmp6DestUnreachable(TcpTestCase):
    """
    The TCP IPV6_RECVERR ICMPv6 Destination Unreachable end-to-end
    queue + recvmsg tests.
    """

    def test__tcp__ipv6_recverr__icmp6_port_unreach__enqueues(self) -> None:
        """
        Ensure an ICMPv6 Destination Unreachable Code=4 (Port
        Unreachable) targeting a TcpSocket with IPV6_RECVERR=1
        queues an ErrorQueueEntry with errno=ECONNREFUSED,
        origin=SoEeOrigin.ICMP6, type=1, code=4, and a
        sockaddr_in6 28-byte offender block.

        Reference: RFC 4443 §3.1 (ICMPv6 Destination Unreachable).
        Reference: Linux 'ipv6(7)' (IPV6_RECVERR cmsg wire shape).
        """

        sock, _ = _make_syn_sent_session(self, family=AddressFamily.INET6)
        sock.setsockopt(IPPROTO_IPV6, IPV6_RECVERR, 1)

        frame = _icmp6_dest_unreach_frame(
            code=Icmp6DestinationUnreachableCode.PORT,
        )
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        data, ancdata, flags, address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        self.assertEqual(flags, int(MSG_ERRQUEUE))
        # IPv6 4-tuple address shape: (host, port, flowinfo, scope_id).
        self.assertEqual(
            address,
            (str(PEER__IP6), 0, 0, 0),
            msg="IPv6 recvmsg address must be the ICMPv6 offender (port=0, flowinfo=0, scope=0).",
        )
        self.assertEqual(
            data,
            _embedded_tcp6(embedded_seq=LOCAL__ISS),
            msg="recvmsg(MSG_ERRQUEUE) data must equal the embedded triggering segment.",
        )

        level, type_, value = ancdata[0]
        self.assertEqual(level, int(IPPROTO_IPV6))
        self.assertEqual(type_, int(IPV6_RECVERR))
        self.assertEqual(
            len(value),
            44,
            msg="sock_extended_err (16) + sockaddr_in6 (28) = 44 bytes.",
        )

        ee_errno, ee_origin, ee_type, ee_code = struct.unpack("=IBBB", value[:7])
        self.assertEqual(
            ee_errno,
            errno_mod.ECONNREFUSED,
            msg="ICMPv6 type=1 code=4 must map to ECONNREFUSED.",
        )
        self.assertEqual(ee_origin, int(SoEeOrigin.ICMP6))
        self.assertEqual(ee_type, 1)
        self.assertEqual(ee_code, 4)


class TestTcpIpRecverrIcmp6PacketTooBig(TcpTestCase):
    """
    The TCP IPV6_RECVERR ICMPv6 Packet Too Big (RFC 8201 PMTUD)
    queue tests.
    """

    def test__tcp__ipv6_recverr__icmp6_packet_too_big__emsgsize_with_mtu(self) -> None:
        """
        Ensure an ICMPv6 Packet Too Big targeting a TcpSocket with
        IPV6_RECVERR=1 queues an ErrorQueueEntry with
        errno=EMSGSIZE and ee_info=MTU per Linux semantics, in
        parallel with the existing PMTU FSM event.

        Reference: RFC 8201 §4 (IPv6 PMTUD next-hop MTU surface).
        """

        sock, _ = _make_syn_sent_session(self, family=AddressFamily.INET6)
        sock.setsockopt(IPPROTO_IPV6, IPV6_RECVERR, 1)

        frame = _icmp6_packet_too_big_frame(mtu=NEXT_HOP_MTU)
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        _data, ancdata, _flags, _address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        ee_errno, ee_origin, ee_type, ee_code, _pad, ee_info = struct.unpack("=IBBBBI", ancdata[0][2][:12])
        self.assertEqual(
            ee_errno,
            errno_mod.EMSGSIZE,
            msg="ICMPv6 Packet Too Big must map to EMSGSIZE.",
        )
        self.assertEqual(ee_origin, int(SoEeOrigin.ICMP6))
        self.assertEqual(ee_type, 2)
        self.assertEqual(ee_code, 0)
        self.assertEqual(
            ee_info,
            NEXT_HOP_MTU,
            msg="ee_info must carry the next-hop MTU from the ICMPv6 PTB message.",
        )


# ---------------------------------------------------------------------------
# Gating + bounded + FSM-independence.
# ---------------------------------------------------------------------------


class TestTcpIpRecverrGating(TcpTestCase):
    """
    The TCP IP_RECVERR gating tests — opt-in only.
    """

    def test__tcp__ip_recverr__disabled__no_queue_population(self) -> None:
        """
        Ensure a TcpSocket with IP_RECVERR=0 (default) does NOT
        accumulate ICMP errors on its error queue — the legacy
        FSM-event path still fires, but the
        'recvmsg(flags=MSG_ERRQUEUE)' call observes an empty queue
        and times out.

        Reference: Linux 'ip(7)' (IP_RECVERR opt-in gate).
        """

        sock, _ = _make_syn_sent_session(self)
        # IP_RECVERR intentionally not set.

        frame = _icmp4_dest_unreach_frame(
            code=Icmp4DestinationUnreachableCode.PORT,
        )
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        with self.assertRaises(TimeoutError):
            sock.recvmsg(ancbufsize=256, flags=MSG_ERRQUEUE, timeout=0.01)


class TestTcpIpRecverrFifoBound(TcpTestCase):
    """
    The TCP IP_RECVERR bounded-queue (deque maxlen) tests.
    """

    def test__tcp__ip_recverr__fifo_bound__overflow_drops_oldest(self) -> None:
        """
        Ensure that once 'ERROR_QUEUE__MAX_LEN' (=32) entries are
        queued, the next ICMP error drops the oldest entry from
        the head of the deque — FIFO bound matching the
        'deque(maxlen=...)' semantics documented on
        'ErrorQueueEntry'. Drives 'notify_unreachable' directly
        because the higher-level demux path collapses on the
        first ICMP error (the sequence-in-window guard rejects
        subsequent probes once the session has transitioned to
        CLOSED).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock, _ = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        # Drive enough notify_unreachable calls to exceed the bound
        # by exactly one. Each carries a distinct embedded_datagram
        # so the dropped-oldest semantics is observable.
        for i in range(ERROR_QUEUE__MAX_LEN + 1):
            sock.notify_unreachable(
                icmp_origin=SoEeOrigin.ICMP,
                icmp_type=3,
                icmp_code=3,
                offender_ip=PEER__IP4,
                embedded_datagram=bytes([i & 0xFF]),
            )

        # After overflow the queue should still hold exactly MAX_LEN
        # entries; the oldest (i=0) should be dropped, leaving
        # entries i=1..MAX_LEN.
        self.assertEqual(
            len(sock._error_queue),
            ERROR_QUEUE__MAX_LEN,
            msg="Error queue length must equal ERROR_QUEUE__MAX_LEN after overflow.",
        )
        self.assertEqual(
            sock._error_queue[0].embedded_datagram,
            bytes([1]),
            msg="Head of queue must be the entry that followed the dropped oldest.",
        )


class TestTcpIpRecverrFsmIndependence(TcpTestCase):
    """
    The TCP IP_RECVERR FSM-independence tests — entries queued
    during one FSM state remain readable after the session
    transitions.
    """

    def test__tcp__ip_recverr__entry_survives_syn_sent_to_closed(self) -> None:
        """
        Ensure an ErrorQueueEntry queued during SYN_SENT remains
        readable after the session transitions to CLOSED (driven
        by the ICMPv4 Port Unreachable itself). Linux's IP_RECVERR
        contract is "queue regardless of FSM state"; this test
        pins that PyTCP preserves the entry across the transition.

        Reference: Linux 'ip(7)' (IP_RECVERR FSM-independent
        queueing).
        """

        sock, session = _make_syn_sent_session(self)
        sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        frame = _icmp4_dest_unreach_frame(
            code=Icmp4DestinationUnreachableCode.PORT,
        )
        self._packet_handler._phrx_ethernet(_packet_rx(frame))

        # The Port Unreachable on SYN_SENT triggers the existing
        # FSM-event path: ConnError.REFUSED + transition to CLOSED.
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="Port Unreachable on SYN_SENT must drive FSM to CLOSED.",
        )

        # Despite the transition, the queue still has the entry.
        data, ancdata, _flags, _address = sock.recvmsg(
            ancbufsize=256,
            flags=MSG_ERRQUEUE,
            timeout=0.5,
        )

        self.assertEqual(
            data,
            _embedded_tcp4(embedded_seq=LOCAL__ISS),
            msg="ICMP error queued during SYN_SENT must remain readable post-CLOSED.",
        )
        self.assertEqual(len(ancdata), 1)


# ---------------------------------------------------------------------------
# Shared helper.
# ---------------------------------------------------------------------------


def _packet_rx(frame: bytes) -> PacketRx:
    """
    Construct a 'PacketRx' from a raw Ethernet frame. Wrapped in a
    helper so test bodies stay tight.
    """

    return PacketRx(frame)
