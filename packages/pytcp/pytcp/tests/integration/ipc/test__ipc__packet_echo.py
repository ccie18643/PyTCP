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
End-to-end AF_PACKET echo integration test for the kernel/userspace
boundary.

An out-of-process client opens an AF_PACKET socket on the daemon and
exchanges complete link-layer frames with the TAP wire over its real
SOCK_DGRAM descriptor — exercising the link-layer leg of the data plane
(control RPC + SCM_RIGHTS data channel + packet bridge + sockaddr_ll
framing) against the live stack.

pytcp/tests/integration/ipc/test__ipc__packet_echo.py

ver 3.0.8
"""

import os
import tempfile
import time
from typing import Any, cast, override
from unittest.mock import call

from net_proto import ArpAssembler, ArpOperation, EthernetAssembler, EtherType
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.client import ClientPacketSocket, ClientStack, connect
from pytcp.ipc.ipc__server import IpcServer
from pytcp.runtime.socket import ETH_P_ALL, AddressFamily, SocketType
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

_DEADLINE__SEC: float = 5.0


def _arp_request_frame() -> bytes:
    """
    Build an ARP request from the peer asking for the stack's IPv4
    address — a complete link-layer frame for the AF_PACKET path.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REQUEST,
                arp__sha=HOST_A__MAC_ADDRESS,
                arp__spa=HOST_A__IP4_ADDRESS,
                arp__tpa=STACK__IP4_HOST.address,
            ),
        )
    )


class TestIpcPacketEcho(NetworkTestCase):
    """
    The out-of-process AF_PACKET echo integration test.
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
        Build the mock network (via 'NetworkTestCase') then stand up an
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

    def _packet_socket(self) -> ClientPacketSocket:
        """
        Open a capture-all client AF_PACKET socket with a receive timeout
        set.
        """

        sock = cast(
            ClientPacketSocket,
            self._connect().socket(AddressFamily.PACKET, SocketType.RAW, ETH_P_ALL),
        )
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        return sock

    def test__packet_echo__client_captures_wire_frame(self) -> None:
        """
        Ensure a complete link-layer frame arriving on the wire is
        delivered verbatim to the out-of-process client over its real fd,
        with a sockaddr_ll carrying the arrival ethertype and source MAC.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()
        frame = _arp_request_frame()

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        data, sockaddr_ll = sock.recvfrom()

        self.assertEqual(
            (data, sockaddr_ll.ethertype, sockaddr_ll.mac),
            (frame, EtherType.ARP, HOST_A__MAC_ADDRESS),
            msg="The client must capture the verbatim frame with its sockaddr_ll over its fd.",
        )

    def test__packet_echo__client_frame_reaches_the_wire(self) -> None:
        """
        Ensure a complete link-layer frame the out-of-process client
        sends is emitted verbatim onto the wire by the stack.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()
        frame = _arp_request_frame()
        tx_ring = cast(Any, self._packet_handler._tx_ring)

        # AF_PACKET egress is a verbatim link-frame enqueue
        # ('enqueue_raw_frame'), distinct from the IP TX path the
        # NetworkTestCase '_frames_tx' slot captures.
        sock.sendto(frame, SockAddrLl(ifindex=self._packet_handler._ifindex))

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            if tx_ring.enqueue_raw_frame.call_args_list:
                break
            time.sleep(0.01)

        self.assertEqual(
            tx_ring.enqueue_raw_frame.call_args_list,
            [call(frame)],
            msg="A link-layer frame the client sent must be emitted verbatim onto the wire.",
        )
