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
End-to-end UDP echo integration test for the kernel/userspace boundary.

An out-of-process client opens a UDP socket on the daemon, binds it, and
exchanges datagrams with a peer simulated on the TAP wire over its real
SOCK_DGRAM descriptor — exercising the datagram data plane (control RPC +
SCM_RIGHTS data channel + datagram bridge + per-datagram address framing,
plus the recvmsg ancillary cmsg path) against the live stack. UDP has no
handshake, so both directions run inline on the main thread.

pytcp/tests/integration/ipc/test__ipc__udp_echo.py

ver 3.0.8
"""

import os
import tempfile
import time
from typing import cast, override

from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp import stack
from pytcp.client import ClientStack, ClientUdpSocket, connect
from pytcp.ipc.ipc__server import IpcServer
from pytcp.runtime.socket import IP_RECVTOS, IP_TOS, IPPROTO_IP, AddressFamily, SocketType
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.udp_testcase import UdpTestCase

_LOCAL_PORT: int = 4444
_REMOTE_PORT: int = 5555
_DEADLINE__SEC: float = 5.0


class TestIpcUdpEcho(UdpTestCase):
    """
    The out-of-process UDP echo integration test.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging for the
        whole class so the server's cleanup-time stop line stays quiet.
        """

        super().setUpClass()
        cls._log_channel_prior = stack.LOG__CHANNEL
        stack.LOG__CHANNEL = set()

    @classmethod
    @override
    def tearDownClass(cls) -> None:
        """
        Restore the original logger channel set.
        """

        stack.LOG__CHANNEL = cls._log_channel_prior
        super().tearDownClass()

    @override
    def setUp(self) -> None:
        """
        Build the mocked UDP runtime (via 'UdpTestCase') then stand up an
        'IpcServer' on a temp AF_UNIX path against it.
        """

        super().setUp()

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def _connect(self) -> ClientStack:
        """
        Open a client stack against the server and register its close.
        """

        client = connect(socket_path=self._socket_path)
        self.addCleanup(client.close)
        return client

    def _bound_socket(self) -> ClientUdpSocket:
        """
        Open and bind a client UDP socket onto the stack address /
        local port, with a receive timeout set.
        """

        sock = cast(ClientUdpSocket, self._connect().socket(AddressFamily.INET4, SocketType.DGRAM))
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.bind((str(STACK__IP4_HOST.address), _LOCAL_PORT))
        return sock

    def _peer_datagram(self, *, payload: bytes, dscp: int = 0) -> bytes:
        """
        Build an Ethernet/IPv4/UDP datagram from the peer to the bound
        stack socket, optionally marked with a DSCP (the high 6 bits of
        the TOS byte).
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__dscp=dscp,
                    ip4__payload=UdpAssembler(
                        udp__sport=_REMOTE_PORT,
                        udp__dport=_LOCAL_PORT,
                        udp__payload=payload,
                    ),
                ),
            )
        )

    def test__udp_echo__client_receives_peer_datagram(self) -> None:
        """
        Ensure a datagram a peer sends on the wire is delivered to the
        out-of-process client over its real fd, paired with the sender's
        address.

        Reference: RFC 768 (UDP — datagram delivery with source address).
        """

        sock = self._bound_socket()
        self._drive_udp_rx(frame=self._peer_datagram(payload=b"ping"))

        self.assertEqual(
            sock.recvfrom(),
            (b"ping", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)),
            msg="The client must receive the peer datagram and its sender address over its fd.",
        )

    def test__udp_echo__recvmsg_carries_ip_tos_cmsg(self) -> None:
        """
        Ensure that with IP_RECVTOS enabled, an inbound datagram's TOS is
        delivered to the out-of-process client as an IP_TOS ancillary
        control message on recvmsg.

        Reference: RFC 1122 §4.1.4 (IP_TOS reported to the application).
        """

        sock = self._bound_socket()
        sock.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)
        # DSCP occupies the high 6 bits of the TOS byte: dscp 8 -> TOS 0x20.
        self._drive_udp_rx(frame=self._peer_datagram(payload=b"marked", dscp=8))

        data, ancdata, _flags, address = sock.recvmsg()

        self.assertEqual(
            (data, ancdata, address),
            (b"marked", [(int(IPPROTO_IP), int(IP_TOS), b"\x20")], (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)),
            msg="recvmsg must deliver the inbound TOS as an IP_TOS cmsg when IP_RECVTOS is set.",
        )

    def test__udp_echo__client_datagram_reaches_the_wire(self) -> None:
        """
        Ensure a datagram the out-of-process client writes via 'sendto'
        is carried by the stack onto the wire as a UDP datagram to that
        address.

        Reference: RFC 768 (UDP — sendto datagram emission).
        """

        sock = self._bound_socket()
        sock.sendto(b"pong", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        deadline = time.monotonic() + _DEADLINE__SEC
        probe = None
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                candidate = self._parse_tx(frame)
                if candidate.sport == _LOCAL_PORT and candidate.payload:
                    probe = candidate
                    break
            if probe is not None:
                break
            time.sleep(0.01)

        assert probe is not None, "The client datagram never reached the wire."
        self.assertEqual(
            (probe.payload, probe.dport, str(probe.ip_dst)),
            (b"pong", _REMOTE_PORT, str(HOST_A__IP4_ADDRESS)),
            msg="A datagram the client sent must reach the wire addressed to the peer.",
        )

    def test__udp_echo__sendmsg_ip_tos_marks_the_wire_dscp(self) -> None:
        """
        Ensure a datagram the out-of-process client sends via 'sendmsg'
        with an IPv4 IP_TOS ancillary control message carries that DSCP in
        the outbound IPv4 header — the send-direction mirror of the
        IP_RECVTOS recvmsg path, carried through the datagram bridge.

        Reference: RFC 1122 §4.1.4 (application control of the TOS byte).
        Reference: RFC 2474 §3 (DSCP is the high 6 bits of the TOS byte).
        """

        sock = self._bound_socket()
        # TOS 0x28 -> DSCP 0x0a (40 >> 2 = 10).
        sock.sendmsg(
            [b"marked"],
            [(int(IPPROTO_IP), int(IP_TOS), b"\x28")],
            0,
            (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT),
        )

        deadline = time.monotonic() + _DEADLINE__SEC
        probe = None
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                candidate = self._parse_tx(frame)
                if candidate.sport == _LOCAL_PORT and candidate.payload == b"marked":
                    probe = candidate
                    break
            if probe is not None:
                break
            time.sleep(0.01)

        assert probe is not None, "The sendmsg datagram never reached the wire."
        self.assertEqual(
            probe.ip_dscp,
            0x0A,
            msg="A sendmsg IP_TOS cmsg must mark the outbound datagram's DSCP.",
        )
