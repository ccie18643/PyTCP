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
End-to-end raw-IP echo integration test for the kernel/userspace boundary.

An out-of-process client opens a raw IPv4 socket on the daemon, binds it,
and exchanges raw IP datagrams with a peer simulated on the TAP wire over
its real SOCK_DGRAM descriptor — exercising the raw-socket leg of the
datagram data plane (a raw socket reuses the datagram bridge). The chosen
next-header has no transport handler, so inbound datagrams are delivered
via the IPv4 raw-socket path.

pytcp/tests/integration/ipc/test__ipc__raw_echo.py

ver 3.0.8
"""

import os
import tempfile
import time
from typing import cast, override

from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.client import ClientRawSocket, ClientStack, connect
from pytcp.ipc.ipc__server import IpcServer
from pytcp.runtime.socket import AddressFamily, SocketType
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.udp_testcase import UdpTestCase

# A next-header with no transport demux, so an inbound datagram is
# delivered via the IPv4 raw-socket path rather than a transport handler.
_PROTO: IpProto = IpProto.IP4
_DEADLINE__SEC: float = 5.0


class TestIpcRawEcho(UdpTestCase):
    """
    The out-of-process raw-IP echo integration test.
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

    def _bound_raw_socket(self) -> ClientRawSocket:
        """
        Open and bind a client raw IPv4 socket onto the stack address,
        with a receive timeout set.
        """

        sock = cast(
            ClientRawSocket,
            self._connect().socket(AddressFamily.INET4, SocketType.RAW, _PROTO),
        )
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        return sock

    def test__raw_echo__client_receives_peer_datagram(self) -> None:
        """
        Ensure an inbound IPv4 raw datagram is delivered to the
        out-of-process client over its real fd as the full IPv4 packet
        (header + payload), mirroring Linux 'SOCK_RAW' semantics, paired
        with the sender's address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._bound_raw_socket()
        ip4_packet = Ip4Assembler(
            ip4__src=HOST_A__IP4_ADDRESS,
            ip4__dst=STACK__IP4_HOST.address,
            ip4__payload=RawAssembler(raw__payload=b"rawin", ip_proto=_PROTO),
        )
        self._drive_udp_rx(
            frame=bytes(
                EthernetAssembler(
                    ethernet__src=HOST_A__MAC_ADDRESS,
                    ethernet__dst=STACK__MAC_ADDRESS,
                    ethernet__payload=ip4_packet,
                )
            )
        )

        data, address = sock.recvfrom()

        self.assertEqual(
            data,
            bytes(ip4_packet),
            msg="An IPv4 raw socket must deliver the full IP packet (header + payload), Linux 'SOCK_RAW' style.",
        )
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), 0),
            msg="recvfrom must pair the datagram with the sender's address.",
        )

    def test__raw_echo__client_datagram_reaches_the_wire(self) -> None:
        """
        Ensure a raw IP datagram the out-of-process client writes via
        'sendto' is carried by the stack onto the wire as an IPv4 packet
        with the socket's next-header.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._bound_raw_socket()
        sock.sendto(b"rawout", (str(HOST_A__IP4_ADDRESS), 0))

        deadline = time.monotonic() + _DEADLINE__SEC
        proto = None
        payload = b""
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                packet_rx = PacketRx(frame)
                EthernetParser(packet_rx)
                if packet_rx.ethernet.type is not EtherType.IP4:
                    continue
                Ip4Parser(packet_rx)
                if packet_rx.ip4.proto is _PROTO and bytes(packet_rx.ip4.payload):
                    proto = packet_rx.ip4.proto
                    payload = bytes(packet_rx.ip4.payload)
                    break
            if payload:
                break
            time.sleep(0.01)

        self.assertEqual(
            (proto, payload),
            (_PROTO, b"rawout"),
            msg="A raw datagram the client sent must reach the wire as an IPv4 packet with its next-header.",
        )
