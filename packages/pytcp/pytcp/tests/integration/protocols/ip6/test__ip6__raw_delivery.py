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
Integration tests for IPv6 raw-socket delivery semantics (Linux 'SOCK_RAW').

Pins the Linux model for IPv6: an unbound raw socket receives its
protocol's packets without 'bind', and raw delivery is a clone that does
NOT consume -- the normal transport handler still runs, and the
unrecognized-next-header Parameter Problem is suppressed only when a raw
socket received the datagram (the Linux 'raw' flag).

pytcp/tests/integration/protocols/ip6/test__ip6__raw_delivery.py

ver 3.0.9
"""

from net_proto import (
    EthernetAssembler,
    Icmp6Assembler,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6Type,
    Ip6Assembler,
    IpProto,
)
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)

# Silence the SOCKET log channel for the whole module: RAW sockets log
# 'Closed socket' from 'addCleanup(close)' callbacks that fire AFTER the
# harness tearDown restores LOG__CHANNEL, leaking into the runner output.
# Module-level silencing spans every per-test cleanup (unit_testing.md
# §10a.4 / §11).
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence stack log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the production log-channel configuration.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


# An IP next-header with no transport handler, so an inbound datagram is a
# candidate for the raw-socket path rather than a transport demux.
_NO_HANDLER_PROTO: IpProto = IpProto.IP4
_ECHO_ID: int = 0x1234
_ECHO_SEQ: int = 0x0007


def _echo_request_frame() -> bytes:
    """
    Build an Ethernet/IPv6/ICMPv6 Echo Request frame from HOST_A to the
    stack.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=Ip6Assembler(
                ip6__src=HOST_A__IP6_ADDRESS,
                ip6__dst=STACK__IP6_HOST.address,
                ip6__payload=Icmp6Assembler(
                    icmp6__message=Icmp6MessageEchoRequest(id=_ECHO_ID, seq=_ECHO_SEQ, data=b"raw-ping"),
                ),
            ),
        )
    )


def _echo_reply_frame() -> bytes:
    """
    Build an Ethernet/IPv6/ICMPv6 Echo Reply frame from HOST_A to the
    stack (the packet a 'ping' tool receives back).
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=Ip6Assembler(
                ip6__src=HOST_A__IP6_ADDRESS,
                ip6__dst=STACK__IP6_HOST.address,
                ip6__payload=Icmp6Assembler(
                    icmp6__message=Icmp6MessageEchoReply(id=_ECHO_ID, seq=_ECHO_SEQ, data=b"raw-ping"),
                ),
            ),
        )
    )


def _no_handler_frame() -> bytes:
    """
    Build an Ethernet/IPv6 datagram whose next-header has no transport
    handler, from HOST_A to the stack.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=Ip6Assembler(
                ip6__src=HOST_A__IP6_ADDRESS,
                ip6__dst=STACK__IP6_HOST.address,
                ip6__payload=RawAssembler(raw__payload=b"rawdata", ip_proto=_NO_HANDLER_PROTO),
            ),
        )
    )


class TestIp6RawDelivery(IcmpTestCase):
    """
    The IPv6 raw-socket delivery-semantics tests (Linux 'SOCK_RAW').
    """

    def _raw_socket(self, *, protocol: IpProto, bind: bool) -> RawSocket:
        """
        Open a raw IPv6 socket on 'protocol', optionally bound to the
        stack address, and register its cleanup.
        """

        sock = RawSocket(family=AddressFamily.INET6, type=SocketType.RAW, protocol=protocol)
        self.addCleanup(sock.close)
        if bind:
            sock.bind((str(STACK__IP6_HOST.address), 0))
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__ip6_raw__unbound_socket_receives(self) -> None:
        """
        Ensure an unbound IPv6 raw socket receives a matching inbound
        datagram without any 'bind', mirroring Linux where a raw socket
        receives its protocol's packets from the moment it is created.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._raw_socket(protocol=_NO_HANDLER_PROTO, bind=False)

        self._drive_rx(frame=_no_handler_frame())

        self.assertEqual(
            len(sock._packet_rx_md),
            1,
            msg="An unbound IPv6 raw socket must receive a matching inbound datagram (no bind needed).",
        )

    def test__ip6_raw__delivery_does_not_suppress_transport(self) -> None:
        """
        Ensure raw delivery is a copy that does not consume: an inbound
        ICMPv6 Echo Request reaches an open raw ICMPv6 socket AND the
        stack still processes it and emits an Echo Reply.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._raw_socket(protocol=IpProto.ICMP6, bind=True)

        tx_frames = self._drive_rx(frame=_echo_request_frame())

        self.assertEqual(
            len(sock._packet_rx_md),
            1,
            msg="The raw ICMPv6 socket must receive a copy of the inbound Echo Request.",
        )
        self.assertEqual(
            len(tx_frames),
            1,
            msg="Raw delivery must not consume the packet -- the stack must still emit an Echo Reply.",
        )
        self._assert_icmp6_message(
            self._parse_tx_icmp6(tx_frames[0]),
            type=int(Icmp6Type.ECHO_REPLY),
            id=_ECHO_ID,
            seq=_ECHO_SEQ,
        )

    def test__ip6_raw__echo_reply_delivered_exactly_once(self) -> None:
        """
        Ensure an inbound ICMPv6 Echo Reply reaches a matching raw socket
        exactly once -- the IPv6 RX path is the single raw-delivery point,
        with no redundant second delivery from the ICMP Echo Reply handler.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._raw_socket(protocol=IpProto.ICMP6, bind=True)

        self._drive_rx(frame=_echo_reply_frame())

        self.assertEqual(
            len(sock._packet_rx_md),
            1,
            msg="An inbound Echo Reply must be delivered to the raw socket exactly once.",
        )

    def test__ip6_raw__match_suppresses_parameter_problem(self) -> None:
        """
        Ensure a matched raw socket on a next-header with no transport
        handler receives the datagram and suppresses the ICMPv6
        Parameter Problem (unrecognized next header), emitting nothing on
        the wire.

        Reference: RFC 8200 §4 (unrecognized next header, suppressed when a raw socket matched).
        """

        sock = self._raw_socket(protocol=_NO_HANDLER_PROTO, bind=True)

        tx_frames = self._drive_rx(frame=_no_handler_frame())

        self.assertEqual(
            len(sock._packet_rx_md),
            1,
            msg="The raw socket must receive the inbound no-handler datagram.",
        )
        self.assertEqual(
            tx_frames,
            [],
            msg="A matched raw socket must suppress the Parameter Problem (nothing on the wire).",
        )
