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
End-to-end test for the out-of-process TCP echo example client.

Runs 'examples/client__tcp_echo_ipc.py' (which uses 'pytcp.client' and
never boots the stack) against a live daemon, driving the connect
handshake and the echo round trip on the TAP wire — the Phase-5
user-visible payoff: a socket example that is a separate-process client
of the stack.

The example's CLI blocks (connect, then recv) on a background thread
while the main thread drives the wire.

examples/tests/integration/ipc/test__client_tcp_echo_ipc.py

ver 3.0.8
"""

import os
import tempfile
import threading
import time
from typing import override

from click.testing import CliRunner, Result

from examples.client__tcp_echo_ipc import cli
from examples.lib.payload import payload
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

_REMOTE_PORT: int = 7
_LOCAL_ISS: int = 3000
_PEER_ISS: int = 9000
_PEER_WIN: int = 64240
_MESSAGE_SIZE: int = 16
_DEADLINE__SEC: float = 5.0


class TestExampleTcpEchoIpc(TcpTestCase):
    """
    The out-of-process TCP echo example-client end-to-end test.
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
        Build the mocked TCP runtime (via 'TcpTestCase') then stand up an
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

    def _wait_for_tx(self, *, want_payload: bool) -> int:
        """
        Block (nudging the virtual clock) until the stack emits a segment
        to the peer port — a SYN ('want_payload' False) or a data segment
        ('want_payload' True) — and return its source (ephemeral) port.
        """

        deadline = time.monotonic() + _DEADLINE__SEC
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.dport == _REMOTE_PORT and bool(probe.payload) == want_payload:
                    return probe.sport
            self._advance(ms=1)
            time.sleep(0.005)
        raise AssertionError("Expected outbound segment never appeared.")

    def test__example_tcp_echo_ipc__out_of_process_round_trip(self) -> None:
        """
        Ensure the example client — a separate-process consumer using
        'pytcp.client' with no stack boot — connects through the daemon
        and completes an echo round trip with a peer on the wire,
        returning a clean exit.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self._force_iss(_LOCAL_ISS)
        message = payload(length=_MESSAGE_SIZE)
        result: list[Result] = []

        def _run_client() -> None:
            result.append(
                CliRunner().invoke(
                    cli,
                    [
                        "--ipc-socket",
                        self._socket_path,
                        "--count",
                        "1",
                        "--delay",
                        "0",
                        "--size",
                        str(_MESSAGE_SIZE),
                        str(HOST_A__IP4_ADDRESS),
                        str(_REMOTE_PORT),
                    ],
                )
            )

        client_thread = threading.Thread(target=_run_client, name="example-client")
        client_thread.start()
        self.addCleanup(client_thread.join)

        # Connect handshake: the client's blocking connect emits a SYN
        # from an ephemeral port; complete it with a synthetic SYN-ACK.
        local_port = self._wait_for_tx(want_payload=False)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=local_port,
                seq=_PEER_ISS,
                ack=_LOCAL_ISS + 1,
                flags=("SYN", "ACK"),
                win=_PEER_WIN,
            )
        )

        # The client now send()s the message; observe it on the wire and
        # echo it straight back so the client's recv() unblocks.
        self._wait_for_tx(want_payload=True)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=local_port,
                seq=_PEER_ISS + 1,
                ack=_LOCAL_ISS + 1 + len(message),
                flags=("ACK",),
                win=_PEER_WIN,
                payload=message,
            )
        )

        client_thread.join(timeout=_DEADLINE__SEC)
        self.assertFalse(client_thread.is_alive(), msg="The example client must finish after the echo round trip.")

        self.assertEqual(
            result[0].exit_code,
            0,
            msg=f"The example client must exit cleanly; output:\n{result[0].output}",
        )
        self.assertIn(
            f"Received {_MESSAGE_SIZE} bytes back.",
            result[0].output,
            msg=f"The example client must report the echoed bytes; output:\n{result[0].output}",
        )
