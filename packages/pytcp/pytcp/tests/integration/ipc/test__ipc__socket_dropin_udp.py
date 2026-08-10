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
End-to-end UDP proof point for the daemon-backed stdlib-socket drop-in.

A datagram round trip driven entirely through 'pytcp.socket' — the
stdlib-shaped 'socket()' factory (SOCK_DGRAM), resolved against the
daemon via the '$PYTCP_DAEMON_SOCKET' singleton, with datagrams exchanged
over the wrapper's 'recvfrom' / 'sendto'. Proves the drop-in delegates
the datagram data plane correctly to the underlying client shim over the
live control RPC + SCM_RIGHTS data channel + datagram bridge, using only
stdlib-shaped calls and constants. UDP has no handshake, so both
directions run inline on the main thread.

pytcp/tests/integration/ipc/test__ipc__socket_dropin_udp.py

ver 3.0.9
"""

import errno
import os
import socket as stdlib_socket
import tempfile
import time
from typing import override

import pytcp.socket as pytcp_socket
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.runtime.socket import IP_TOS, IPPROTO_IP
from pytcp.socket.socket__dropin import _reset_default_stack
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


class TestSocketDropinUdp(UdpTestCase):
    """
    The daemon-backed socket-drop-in UDP datagram round-trip test.
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
        Build the mocked UDP runtime, stand up an 'IpcServer', and point
        the drop-in's daemon singleton at it via '$PYTCP_DAEMON_SOCKET'.
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

    def _bound_socket(self) -> pytcp_socket.Socket:
        """
        Open and bind a drop-in UDP socket onto the stack address / local
        port, with a receive timeout set.
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.bind((str(STACK__IP4_HOST.address), _LOCAL_PORT))
        return sock

    def _peer_datagram(self, *, payload: bytes) -> bytes:
        """
        Build an Ethernet/IPv4/UDP datagram from the peer to the bound
        stack socket.
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
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

    def test__socket_dropin_udp__recvfrom_delivers_peer_datagram(self) -> None:
        """
        Ensure a datagram a peer sends on the wire is delivered to a
        drop-in datagram socket via its stdlib-shaped 'recvfrom', paired
        with the sender's address.

        Reference: RFC 768 (UDP — datagram delivery with source address).
        """

        sock = self._bound_socket()
        self._drive_udp_rx(frame=self._peer_datagram(payload=b"ping"))

        self.assertEqual(
            sock.recvfrom(64),
            (b"ping", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)),
            msg="The drop-in recvfrom() must return the peer datagram and its sender address.",
        )

    def test__socket_dropin_udp__sendto_reaches_the_wire(self) -> None:
        """
        Ensure a datagram written through the drop-in's stdlib-shaped
        'sendto' is carried by the stack onto the wire addressed to the
        peer.

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

        assert probe is not None, "The drop-in datagram never reached the wire."
        self.assertEqual(
            (probe.payload, probe.dport, str(probe.ip_dst)),
            (b"pong", _REMOTE_PORT, str(HOST_A__IP4_ADDRESS)),
            msg="A datagram sent via the drop-in sendto() must reach the wire addressed to the peer.",
        )

    def test__socket_dropin_udp__send_unconnected_raises_edestaddrreq(self) -> None:
        """
        Ensure 'send' (no destination) on an unconnected datagram socket
        raises OSError(EDESTADDRREQ) — matching stdlib — rather than
        silently accepting the datagram the fire-and-forget bridge would
        otherwise drop for having no destination.

        Reference: RFC 768 (UDP — a send needs a destination).
        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)

        with self.assertRaises(OSError) as ctx:
            sock.send(b"nowhere")

        self.assertEqual(
            ctx.exception.errno,
            errno.EDESTADDRREQ,
            msg="send() on an unconnected datagram socket must raise OSError(EDESTADDRREQ).",
        )

    def test__socket_dropin_udp__so_rcvbuf_sizes_a_real_buffer(self) -> None:
        """
        Ensure setsockopt(SO_RCVBUF) sizes a real kernel receive buffer
        (the client's socketpair end — the effective client-side datagram
        buffer) rather than being merely stored on the daemon: getsockopt
        reports the same kernel-adjusted value a plain datagram socket
        gives, not the verbatim requested size.

        Reference: socket(7) SO_RCVBUF (the kernel doubles and clamps the
        requested buffer size).
        """

        control = stdlib_socket.socket(stdlib_socket.AF_UNIX, stdlib_socket.SOCK_DGRAM)
        self.addCleanup(control.close)
        control.setsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_RCVBUF, 8192)
        expected = control.getsockopt(stdlib_socket.SOL_SOCKET, stdlib_socket.SO_RCVBUF)

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.setsockopt(pytcp_socket.SOL_SOCKET, pytcp_socket.SO_RCVBUF, 8192)

        self.assertEqual(
            sock.getsockopt(pytcp_socket.SOL_SOCKET, pytcp_socket.SO_RCVBUF),
            expected,
            msg="SO_RCVBUF must size a real kernel buffer (kernel-adjusted value), not echo the request.",
        )

    def test__socket_dropin_udp__connected_send_reaches_the_wire(self) -> None:
        """
        Ensure 'send' on a CONNECTED datagram socket (after connect())
        still reaches the wire — the connected-send path stays functional
        alongside the unconnected-send EDESTADDRREQ guard.

        Reference: RFC 768 (UDP — send to the connected peer).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.connect((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        sock.send(b"connected")

        deadline = time.monotonic() + _DEADLINE__SEC
        probe = None
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                candidate = self._parse_tx(frame)
                if candidate.payload == b"connected":
                    probe = candidate
                    break
            if probe is not None:
                break
            time.sleep(0.01)

        assert probe is not None, "The connected send() datagram never reached the wire."
        self.assertEqual(
            (probe.dport, str(probe.ip_dst)),
            (_REMOTE_PORT, str(HOST_A__IP4_ADDRESS)),
            msg="A connected send() must reach the wire addressed to the connected peer.",
        )

    def test__socket_dropin_udp__sendmsg_ip_tos_marks_the_wire_dscp(self) -> None:
        """
        Ensure a datagram written through the drop-in's stdlib-shaped
        'sendmsg' with an IPv4 IP_TOS ancillary control message carries
        that DSCP in the outbound IPv4 header — the send-direction mirror
        of the IP_RECVTOS recvmsg path.

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

        assert probe is not None, "The drop-in sendmsg datagram never reached the wire."
        self.assertEqual(
            probe.ip_dscp,
            0x0A,
            msg="A drop-in sendmsg IP_TOS cmsg must mark the outbound datagram's DSCP.",
        )
