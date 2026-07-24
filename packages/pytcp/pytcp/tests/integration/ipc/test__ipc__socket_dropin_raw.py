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
End-to-end raw-IPv4 proof point for the daemon-backed stdlib-socket drop-in.

A raw datagram round trip driven entirely through 'pytcp.socket' — the
stdlib-shaped 'socket()' factory (SOCK_RAW / IPPROTO_ICMP), resolved
against the daemon via the '$PYTCP_DAEMON_SOCKET' singleton, with
datagrams exchanged over the wrapper's 'recvfrom' / 'sendto'. Proves the
drop-in exposes raw sockets (the path a 'ping' tool takes) and that an
inbound IPv4 raw datagram is delivered as the full IPv4 packet (header +
payload), Linux 'SOCK_RAW' style, using only stdlib-shaped calls and
constants.

pytcp/tests/integration/ipc/test__ipc__socket_dropin_raw.py

ver 3.0.9
"""

import os
import tempfile
import time
from typing import override

import pytcp.socket as pytcp_socket
from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import _reset_default_stack
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pytcp.tests.lib.udp_testcase import UdpTestCase

_PROTO: IpProto = IpProto.ICMP4
_DEADLINE__SEC: float = 5.0


class TestSocketDropinRaw(UdpTestCase):
    """
    The daemon-backed socket-drop-in raw-IPv4 round-trip test.
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
        Build the mocked runtime, stand up an 'IpcServer', and point the
        drop-in's daemon singleton at it via '$PYTCP_DAEMON_SOCKET'.
        """

        super().setUp()

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

        self._env_prior = os.environ.get("PYTCP_DAEMON_SOCKET")
        os.environ["PYTCP_DAEMON_SOCKET"] = self._socket_path
        _reset_default_stack()
        self.addCleanup(self._restore_env)
        self.addCleanup(_reset_default_stack)

    def _restore_env(self) -> None:
        """
        Restore the PYTCP_DAEMON_SOCKET environment variable.
        """

        if self._env_prior is None:
            os.environ.pop("PYTCP_DAEMON_SOCKET", None)
        else:
            os.environ["PYTCP_DAEMON_SOCKET"] = self._env_prior

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def _bound_raw_socket(self) -> pytcp_socket.Socket:
        """
        Open and bind a drop-in raw IPv4 / ICMP socket onto the stack
        address, with a receive timeout set.
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_RAW, pytcp_socket.IPPROTO_ICMP)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.bind((str(STACK__IP4_HOST.address), 0))
        return sock

    def test__socket_dropin_raw__recvfrom_delivers_full_ipv4_packet(self) -> None:
        """
        Ensure an inbound IPv4 raw datagram is delivered to a drop-in raw
        socket via its stdlib-shaped 'recvfrom' as the full IPv4 packet
        (header + payload), Linux 'SOCK_RAW' style, paired with the
        sender's address.

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

        data, address = sock.recvfrom(2048)

        self.assertEqual(
            data,
            bytes(ip4_packet),
            msg="A drop-in raw socket must deliver the full IPv4 packet (header + payload), Linux 'SOCK_RAW' style.",
        )
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), 0),
            msg="The drop-in recvfrom() must pair the datagram with the sender's address.",
        )

    def test__socket_dropin_raw__sendto_reaches_the_wire(self) -> None:
        """
        Ensure a raw datagram written through the drop-in's stdlib-shaped
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
            msg="A raw datagram sent via the drop-in sendto() must reach the wire as an IPv4 packet.",
        )
