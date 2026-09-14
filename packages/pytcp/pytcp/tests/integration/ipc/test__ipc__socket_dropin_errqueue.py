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
End-to-end ICMP-error proof point for the daemon-backed drop-in: an
inbound ICMPv4 Destination Unreachable matched to a daemon-side UDP
socket with IP_RECVERR set is dequeued by the client through
'recvmsg(MSG_ERRQUEUE)', carrying the embedded triggering datagram and
the Linux-shape IP_RECVERR control message across the AF_UNIX boundary.

pytcp/tests/integration/ipc/test__ipc__socket_dropin_errqueue.py

ver 3.0.10
"""

import errno
import os
import struct
import tempfile
import time
from typing import override

import pytcp.socket as pytcp_socket
from net_proto import Icmp4DestinationUnreachableCode, Icmp4MessageDestinationUnreachable
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.runtime.socket import IP_RECVERR, IPPROTO_IP, MSG_ERRQUEUE
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
# 'sock_extended_err' (16) + offender 'sockaddr_in' (16).
_CMSG_LEN: int = 32


def _build_icmp4_unreachable(*, embedded: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Port Unreachable from the peer to the
    stack, quoting 'embedded' — the IPv4 + UDP header of the datagram
    the stack just sent — so the ICMP demux matches it to the socket.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=Ip4Assembler(
                ip4__src=HOST_A__IP4_ADDRESS,
                ip4__dst=STACK__IP4_HOST.address,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageDestinationUnreachable(
                        code=Icmp4DestinationUnreachableCode.PORT,
                        data=embedded,
                    ),
                ),
            ),
        )
    )


class TestSocketDropinErrQueue(UdpTestCase):
    """
    The daemon-backed drop-in ICMP error-queue tests.
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

    def _connected_socket(self, *, recverr: bool) -> pytcp_socket.Socket:
        """
        Open a drop-in UDP socket bound to the stack address and
        connected to the peer, optionally with IP_RECVERR enabled.
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.bind((str(STACK__IP4_HOST.address), _LOCAL_PORT))
        sock.connect((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        if recverr:
            sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)
        return sock

    def _drive_icmp_error(self, sock: pytcp_socket.Socket) -> bytes:
        """
        Send a probe datagram through the drop-in, then drive the ICMPv4
        Port Unreachable that quotes it. Returns the embedded IPv4 + UDP
        bytes the error queue should surface as its data portion.
        """

        sock.send(b"probe")

        # The drop-in hands the datagram to the daemon over the bridge, so
        # the frame reaches the wire on the daemon's thread — wait for it
        # rather than assuming it has already been emitted.
        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline and not self._frames_tx:
            time.sleep(0.01)
        assert self._frames_tx, "The drop-in probe datagram never reached the wire."

        embedded = self._frames_tx[-1][14:]
        self._drive_udp_rx(frame=_build_icmp4_unreachable(embedded=embedded))
        return embedded

    def test__ipc__dropin__errqueue_delivers_embedded_datagram(self) -> None:
        """
        Ensure a client reading 'recvmsg(MSG_ERRQUEUE)' over the daemon
        boundary receives the datagram that triggered the ICMP error as
        the data portion, with the offender's address.

        Reference: RFC 1122 §4.1.3.3 (pass ICMP errors up to the application).
        Reference: Linux 'ip(7)' (IP_RECVERR / MSG_ERRQUEUE API shape).
        """

        sock = self._connected_socket(recverr=True)
        embedded = self._drive_icmp_error(sock)

        data, _ancdata, flags, address = sock.recvmsg(2048, 256, MSG_ERRQUEUE)

        self.assertEqual(
            data,
            embedded,
            msg="The error-queue data portion must be the embedded triggering datagram.",
        )
        self.assertEqual(
            flags,
            int(MSG_ERRQUEUE),
            msg="msg_flags must carry the MSG_ERRQUEUE bit across the daemon boundary.",
        )
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), 0),
            msg="The error-queue address must be the ICMP offender's IP with port 0.",
        )

    def test__ipc__dropin__errqueue_delivers_recverr_cmsg(self) -> None:
        """
        Ensure the Linux-shape IP_RECVERR control message survives the
        daemon boundary intact, so a client can read the originating
        ICMP type, code and mapped errno.

        Reference: Linux 'ip(7)' (IP_RECVERR cmsg wire shape).
        """

        sock = self._connected_socket(recverr=True)
        self._drive_icmp_error(sock)

        _data, ancdata, _flags, _address = sock.recvmsg(2048, 256, MSG_ERRQUEUE)

        self.assertEqual(len(ancdata), 1, msg="Exactly one IP_RECVERR control message is expected.")
        level, type_, value = ancdata[0]
        self.assertEqual((level, type_), (int(IPPROTO_IP), int(IP_RECVERR)))
        self.assertEqual(
            len(value),
            _CMSG_LEN,
            msg="sock_extended_err (16) + sockaddr_in (16) = 32 bytes.",
        )

        ee_errno, ee_origin, ee_type, ee_code = struct.unpack("=IBBB", value[:7])
        self.assertEqual(
            (ee_errno, ee_origin, ee_type, ee_code),
            (errno.ECONNREFUSED, 2, 3, 3),
            msg=(
                "The cmsg must carry errno=ECONNREFUSED, origin=ICMP(2) and " "the originating ICMPv4 type 3 / code 3."
            ),
        )

    def test__ipc__dropin__errqueue_empty_raises_eagain(self) -> None:
        """
        Ensure reading an empty error queue over the daemon boundary
        fails with EAGAIN rather than blocking the daemon's RPC worker,
        matching the non-blocking contract of MSG_ERRQUEUE.

        Reference: Linux 'ip(7)' (MSG_ERRQUEUE never blocks).
        """

        sock = self._connected_socket(recverr=True)

        with self.assertRaises(OSError) as error:
            sock.recvmsg(2048, 256, MSG_ERRQUEUE)

        self.assertEqual(
            error.exception.errno,
            errno.EAGAIN,
            msg="An empty error queue must surface EAGAIN to the client.",
        )

    def test__ipc__dropin__errqueue_stays_empty_without_recverr(self) -> None:
        """
        Ensure the error queue is not populated when IP_RECVERR is unset,
        so the opt-in gate holds across the daemon boundary exactly as it
        does in-process.

        Reference: RFC 1122 §4.1.3.3 (per-socket opt-in to the error queue).
        """

        sock = self._connected_socket(recverr=False)
        self._drive_icmp_error(sock)

        with self.assertRaises(OSError) as error:
            sock.recvmsg(2048, 256, MSG_ERRQUEUE)

        self.assertEqual(
            error.exception.errno,
            errno.EAGAIN,
            msg="Without IP_RECVERR the ICMP error must not reach the error queue.",
        )
