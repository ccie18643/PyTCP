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
End-to-end ICMP Echo ('ping') proof point for the daemon-backed drop-in.

A full Echo Request / Echo Reply round trip driven entirely through
'pytcp.socket' — the stdlib-shaped 'socket(AF_INET, SOCK_DGRAM,
IPPROTO_ICMP)' factory (the Linux unprivileged ping socket), resolved
against the daemon via the '$PYTCP_DAEMON_SOCKET' singleton. Proves the
drop-in routes the ping socket to the daemon, that 'sendto' emits an Echo
Request on the wire with the daemon-owned id, and that an inbound Echo
Reply is demuxed back and surfaced through the wrapper's 'recvmsg' with
the reply's TTL as an 'IP_TTL' cmsg — using only stdlib-shaped calls and
constants.

pytcp/tests/integration/ipc/test__ipc__socket_dropin_ping.py

ver 3.0.10
"""

import os
import tempfile
import time
from typing import override

import pytcp.socket as pytcp_socket
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from net_proto.protocols.icmp4.message.icmp4__message import Icmp4Type
from net_proto.protocols.icmp4.message.icmp4__message__echo_reply import Icmp4MessageEchoReply
from net_proto.protocols.icmp4.message.icmp4__message__echo_request import Icmp4MessageEchoRequest
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import _reset_default_stack
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)

_SEQ: int = 0x0007
_REPLY_TTL: int = 57
_DEADLINE__SEC: float = 5.0


class TestSocketDropinPing(IcmpTestCase):
    """
    The daemon-backed socket-drop-in ICMP Echo round-trip test.
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
        Build the mocked ICMP runtime, stand up an 'IpcServer', and point
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

    def _ping_socket(self) -> pytcp_socket.Socket:
        """
        Open a drop-in IPv4 ICMP Echo ('ping') socket with a receive
        timeout and the TTL cmsg enabled.
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM, pytcp_socket.IPPROTO_ICMP)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.setsockopt(pytcp_socket.IPPROTO_IP, pytcp_socket.IP_RECVTTL, 1)
        return sock

    def _wait_for_echo_request(self) -> int:
        """
        Poll the wire for the Echo Request the daemon emitted and return
        the daemon-owned id it carries.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx_icmp4(frame)
                if probe.icmp_type == int(Icmp4Type.ECHO_REQUEST) and probe.icmp_id is not None:
                    return probe.icmp_id
            time.sleep(0.01)
        raise AssertionError("The drop-in Echo Request never reached the wire.")

    def _echo_reply_frame(self, *, echo_id: int) -> bytes:
        """
        Build an Ethernet/IPv4/ICMPv4 Echo Reply frame carrying 'echo_id'
        from HOST_A to the stack, with a known IP TTL.
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__ttl=_REPLY_TTL,
                    ip4__payload=Icmp4Assembler(
                        icmp4__message=Icmp4MessageEchoReply(id=echo_id, seq=_SEQ, data=b"ping-data"),
                    ),
                ),
            )
        )

    def test__socket_dropin_ping__round_trip_delivers_reply_with_ttl(self) -> None:
        """
        Ensure a 'sendto' through the drop-in ping socket emits an Echo
        Request on the wire and an inbound Echo Reply is delivered back
        through 'recvmsg' as the ICMP message bytes plus the reply's TTL
        as an 'IP_TTL' cmsg.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._ping_socket()
        request = bytes(Icmp4MessageEchoRequest(id=0x1234, seq=_SEQ, data=b"ping-data"))

        sock.sendto(request, (str(HOST_A__IP4_ADDRESS), 0))
        echo_id = self._wait_for_echo_request()

        self._drive_rx(frame=self._echo_reply_frame(echo_id=echo_id))

        data, ancdata, _flags, address = sock.recvmsg(64, 256)

        self.assertEqual(
            data,
            bytes(Icmp4MessageEchoReply(id=echo_id, seq=_SEQ, data=b"ping-data")),
            msg="The drop-in recvmsg() must return the Echo Reply's ICMP message bytes (no IP header).",
        )
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), 0),
            msg="The drop-in recvmsg() must pair the reply with the sender's address.",
        )
        self.assertEqual(
            ancdata,
            [(int(pytcp_socket.IPPROTO_IP), int(pytcp_socket.IP_TTL), _REPLY_TTL.to_bytes(4, "little"))],
            msg="The drop-in recvmsg() must surface the reply's TTL as an IP_TTL cmsg.",
        )
