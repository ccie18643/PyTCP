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

ver 3.0.10
"""

import array
import os
import socket
import struct
from typing import override
from unittest import TestCase

from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__fdpass import recv_frame_with_fd, send_frame_with_fd
from pytcp.ipc.ipc__frame import (
    IPC__FRAME__LENGTH_PREFIX_STRUCT,
    IPC__FRAME__MAX_PAYLOAD_LEN,
    pack_frame,
    send_frame,
)


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


class TestIpcFdPass__MutationGoldens(TestCase):
    """
    SCM_RIGHTS fd-passing branch goldens: the received descriptor is a
    live, distinct fd (not an off-by-one index), an fd-less frame
    yields None, and more than one passed descriptor is rejected.
    """

    @override
    def setUp(self) -> None:
        """
        Create the AF_UNIX control-channel socketpair shared by the
        fd-passing tests.
        """

        self._sock_a, self._sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self._sock_a.close)
        self.addCleanup(self._sock_b.close)

    def _pipe(self) -> tuple[int, int]:
        """Return a fresh pipe (read, write) registered for cleanup."""

        read_fd, write_fd = os.pipe()
        self.addCleanup(lambda: os.close(read_fd))
        self.addCleanup(lambda: os.close(write_fd))
        return read_fd, write_fd

    def test__fdpass__received_fd_is_live_and_distinct(self) -> None:
        """
        Ensure the descriptor recovered from a passed frame is a new,
        distinct fd that refers to the same underlying pipe — pinning
        the 'fds[0]' return index (an off-by-one would IndexError) and
        the single-fd acceptance (a '> 0' edit would reject it).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        read_fd, write_fd = self._pipe()
        send_frame_with_fd(self._sock_a, b"with-fd", read_fd)

        payload, got_fd = recv_frame_with_fd(self._sock_b)
        self.addCleanup(lambda: os.close(got_fd) if got_fd is not None else None)

        self.assertEqual(payload, b"with-fd", msg="payload must accompany the passed fd.")
        self.assertIsInstance(got_fd, int, msg="a single passed fd must be returned.")
        assert got_fd is not None
        self.assertNotEqual(got_fd, read_fd, msg="the received fd must be a new descriptor.")
        os.write(write_fd, b"PING")
        self.assertEqual(
            os.read(got_fd, 4),
            b"PING",
            msg="the received fd must read bytes written through the original pipe.",
        )

    def test__fdpass__frame_without_fd_yields_none(self) -> None:
        """
        Ensure a plain (fd-less) frame recovered via recv_frame_with_fd
        yields a None descriptor, pinning the no-fd branch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._sock_a.sendall(pack_frame(b"plain"))

        payload, got_fd = recv_frame_with_fd(self._sock_b)

        self.assertEqual(payload, b"plain", msg="the fd-less payload must be recovered.")
        self.assertIsNone(got_fd, msg="a frame with no SCM_RIGHTS fd must yield None.")

    def test__fdpass__more_than_one_fd_rejected(self) -> None:
        """
        Ensure a frame carrying two passed descriptors is rejected,
        pinning the 'len(fds) > 1' guard against an off-by-one that
        would accept two.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        read_a, _ = self._pipe()
        read_b, _ = self._pipe()
        prefix = struct.pack(IPC__FRAME__LENGTH_PREFIX_STRUCT, 3)
        self._sock_a.sendmsg(
            [prefix],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [read_a, read_b]))],
        )
        self._sock_a.sendall(b"xyz")

        with self.assertRaises(IpcFrameError):
            recv_frame_with_fd(self._sock_b)
