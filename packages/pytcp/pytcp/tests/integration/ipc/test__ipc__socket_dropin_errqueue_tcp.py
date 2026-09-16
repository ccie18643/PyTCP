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
ICMP-error proof point for a daemon-backed STREAM socket: the error
queue that R8 opened for datagram / raw sockets must be reachable from a
TCP client too, so 'recvmsg(MSG_ERRQUEUE)' over the drop-in is not
silently datagram-only.

pytcp/tests/integration/ipc/test__ipc__socket_dropin_errqueue_tcp.py

ver 3.0.10
"""

import errno
import os
import struct
import tempfile
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
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL_PORT: int = 12345
_REMOTE_PORT: int = 80
# Virtual-clock steps used to release the daemon's async SYN.
_ADVANCE_STEP__MS: int = 50
_ADVANCE_TRIES: int = 10
# 'sock_extended_err' (16) + offender 'sockaddr_in' (16).
_CMSG_LEN: int = 32


def _build_icmp4_unreachable(*, embedded: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Port Unreachable from the peer to the
    stack, quoting 'embedded' — the IPv4 + TCP bytes of the SYN the stack
    just emitted — so the ICMP demux matches it to the session.
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


class TestSocketDropinErrQueueTcp(TcpTestCase):
    """
    The daemon-backed drop-in stream-socket ICMP error-queue tests.
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
        Build the mocked TCP runtime, stand up an 'IpcServer', and point
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

    def _syn_sent_socket(self, *, recverr: bool) -> tuple[pytcp_socket.Socket, bytes]:
        """
        Open a drop-in stream socket, enable IP_RECVERR if asked, and
        leave it in SYN-SENT via a non-blocking connect. Returns the
        socket and the IPv4 + TCP bytes of the SYN it put on the wire —
        what an ICMP error would quote back.
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind((str(STACK__IP4_HOST.address), _LOCAL_PORT))
        if recverr:
            sock.setsockopt(IPPROTO_IP, IP_RECVERR, 1)

        # A non-blocking connect kicks off the handshake and returns, so
        # the session sits in SYN-SENT with its SYN already emitted — no
        # peer needed to complete anything.
        sock.setblocking(False)
        try:
            sock.connect((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))
        except BlockingIOError:
            pass

        # The handshake runs on the daemon's async connect worker against
        # the harness's virtual clock, so the SYN is released by advancing
        # the FakeTimer — wall-clock waiting would never produce it.
        for _ in range(_ADVANCE_TRIES):
            self._advance(ms=_ADVANCE_STEP__MS)
            if self._frames_tx:
                break
        assert self._frames_tx, "The drop-in connect never put a SYN on the wire."

        return sock, self._frames_tx[-1][14:]

    def test__ipc__dropin__tcp_errqueue_delivers_recverr_cmsg(self) -> None:
        """
        Ensure a stream client can read an ICMP error over the daemon
        boundary, with the Linux-shape IP_RECVERR control message intact.

        Reference: RFC 1122 §4.2.3.9 (TCP MUST report ICMP errors).
        Reference: Linux 'ip(7)' (IP_RECVERR / MSG_ERRQUEUE API shape).
        """

        sock, embedded = self._syn_sent_socket(recverr=True)
        self._drive_rx(frame=_build_icmp4_unreachable(embedded=embedded))

        data, ancdata, flags, address = sock.recvmsg(2048, 256, MSG_ERRQUEUE)

        self.assertEqual(
            data,
            embedded,
            msg="The error-queue data portion must be the embedded triggering segment.",
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

        self.assertEqual(len(ancdata), 1, msg="Exactly one IP_RECVERR control message is expected.")
        level, type_, value = ancdata[0]
        self.assertEqual((level, type_), (int(IPPROTO_IP), int(IP_RECVERR)))
        self.assertEqual(len(value), _CMSG_LEN, msg="sock_extended_err (16) + sockaddr_in (16) = 32 bytes.")

        ee_errno, ee_origin, ee_type, ee_code = struct.unpack("=IBBB", value[:7])
        self.assertEqual(
            (ee_errno, ee_origin, ee_type, ee_code),
            (errno.ECONNREFUSED, 2, 3, 3),
            msg=(
                "The cmsg must carry errno=ECONNREFUSED, origin=ICMP(2) and " "the originating ICMPv4 type 3 / code 3."
            ),
        )

    def test__ipc__dropin__tcp_errqueue_empty_raises_eagain(self) -> None:
        """
        Ensure reading an empty error queue on a stream socket over the
        daemon boundary fails with EAGAIN rather than the EOPNOTSUPP a
        datagram-only gate would produce.

        Reference: Linux 'ip(7)' (MSG_ERRQUEUE never blocks).
        """

        sock, _embedded = self._syn_sent_socket(recverr=True)

        with self.assertRaises(OSError) as error:
            sock.recvmsg(2048, 256, MSG_ERRQUEUE)

        self.assertEqual(
            error.exception.errno,
            errno.EAGAIN,
            msg="An empty stream-socket error queue must surface EAGAIN to the client.",
        )

    def test__ipc__dropin__tcp_recvmsg_without_errqueue_stays_unsupported(self) -> None:
        """
        Ensure an ordinary 'recvmsg' on a stream socket still reports
        EOPNOTSUPP, so opening the error-queue path does not imply a
        data-path recvmsg the drop-in does not provide for streams.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock, _embedded = self._syn_sent_socket(recverr=False)

        with self.assertRaises(OSError) as error:
            sock.recvmsg(2048, 256)

        self.assertEqual(
            error.exception.errno,
            errno.EOPNOTSUPP,
            msg="A stream-socket data-path recvmsg must stay unsupported.",
        )
