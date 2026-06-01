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
Tests for the IPC SCM_RIGHTS file-descriptor-passing primitive.

pytcp/tests/unit/ipc/test__ipc__fdpass.py

ver 3.0.8
"""

import os
import socket
from typing import override
from unittest import TestCase

from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__fdpass import recv_frame_with_fd, send_frame_with_fd
from pytcp.ipc.ipc__frame import IPC__FRAME__MAX_PAYLOAD_LEN, send_frame


class TestIpcFdPass(TestCase):
    """
    The IPC SCM_RIGHTS fd-passing round-trip tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create a connected AF_UNIX stream socketpair as the control
        channel and a pipe whose read end is the descriptor to pass.
        """

        self._sock_a, self._sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self._sock_a.close)
        self.addCleanup(self._sock_b.close)

        self._pipe_r, self._pipe_w = os.pipe()
        self.addCleanup(lambda: os.close(self._pipe_r))
        self.addCleanup(lambda: os.close(self._pipe_w))

    def test__ipc__fdpass__payload_round_trip(self) -> None:
        """
        Ensure the framed payload accompanying a passed descriptor is
        recovered intact on the peer end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        send_frame_with_fd(self._sock_a, b"with-fd", self._pipe_r)
        payload, received_fd = recv_frame_with_fd(self._sock_b)
        assert received_fd is not None
        self.addCleanup(lambda: os.close(received_fd))

        self.assertEqual(
            payload,
            b"with-fd",
            msg="recv_frame_with_fd must recover the framed payload intact.",
        )

    def test__ipc__fdpass__no_fd_returns_none(self) -> None:
        """
        Ensure a frame sent with no attached descriptor (a plain
        'send_frame') is received with a None fd rather than raising, so
        the fd-bearing receive path tolerates an fd-less error response.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        send_frame(self._sock_a, b"no-fd")
        payload, received_fd = recv_frame_with_fd(self._sock_b)

        self.assertEqual(
            (payload, received_fd),
            (b"no-fd", None),
            msg="A frame with no attached descriptor must yield a None fd, not raise.",
        )

    def test__ipc__fdpass__descriptor_is_working_duplicate(self) -> None:
        """
        Ensure the received descriptor is a real working duplicate of
        the sent one — a distinct fd number that reads the same open
        file — so the peer can use it as its own.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        send_frame_with_fd(self._sock_a, b"", self._pipe_r)
        _, received_fd = recv_frame_with_fd(self._sock_b)
        assert received_fd is not None
        self.addCleanup(lambda: os.close(received_fd))

        os.write(self._pipe_w, b"through-the-fd")

        self.assertEqual(
            (received_fd != self._pipe_r, os.read(received_fd, 64)),
            (True, b"through-the-fd"),
            msg="The received fd must be a distinct, working duplicate of the sent fd.",
        )

    def test__ipc__fdpass__sequential_passes(self) -> None:
        """
        Ensure multiple descriptors passed back-to-back are each
        received as their own working duplicate.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        results: list[bytes] = []
        for index in range(3):
            send_frame_with_fd(self._sock_a, f"msg{index}".encode(), self._pipe_r)
            payload, received_fd = recv_frame_with_fd(self._sock_b)
            assert received_fd is not None
            os.write(self._pipe_w, b"x")
            results.append(payload + os.read(received_fd, 1))
            os.close(received_fd)

        self.assertEqual(
            results,
            [b"msg0x", b"msg1x", b"msg2x"],
            msg="Each sequential fd-pass must deliver its payload and a working fd.",
        )

    def test__ipc__fdpass__truncated_prefix_raises(self) -> None:
        """
        Ensure a control stream closed before the full length prefix
        raises 'IpcFrameError' rather than yielding a partial frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._sock_a.close()

        with self.assertRaises(IpcFrameError):
            recv_frame_with_fd(self._sock_b)

    def test__ipc__fdpass__oversize_payload_rejected(self) -> None:
        """
        Ensure 'send_frame_with_fd' refuses a payload larger than the
        maximum frame size, mirroring the plain framing guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcFrameError):
            send_frame_with_fd(self._sock_a, bytes(IPC__FRAME__MAX_PAYLOAD_LEN + 1), self._pipe_r)
