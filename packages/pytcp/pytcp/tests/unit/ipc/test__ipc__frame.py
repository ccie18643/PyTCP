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
Tests for the IPC length-prefixed stream framing codec.

pytcp/tests/unit/ipc/test__ipc__frame.py

ver 3.0.8
"""

import socket
import struct
import threading
from typing import override
from unittest import TestCase

from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__frame import (
    IPC__FRAME__LENGTH_PREFIX_LEN,
    IPC__FRAME__MAX_PAYLOAD_LEN,
    pack_frame,
    recv_frame,
    send_frame,
)


class TestIpcFramePack(TestCase):
    """
    The IPC frame length-prefix packing tests.
    """

    def test__ipc__frame__pack__prepends_length_prefix(self) -> None:
        """
        Ensure 'pack_frame' prepends a 4-byte big-endian unsigned
        length prefix to the payload so the stream peer can recover
        the message boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # IPC frame for payload b"PING" (8 bytes total):
        #   Bytes 0-3 : 0x00000004 -> length prefix = 4
        #   Bytes 4-7 : 0x50494e47 -> payload b"PING"
        frame = pack_frame(b"PING")

        self.assertEqual(
            frame,
            b"\x00\x00\x00\x04PING",
            msg="pack_frame must prepend a 4-byte big-endian length prefix.",
        )

    def test__ipc__frame__pack__empty_payload(self) -> None:
        """
        Ensure 'pack_frame' encodes a zero-length payload as a bare
        length prefix of zero, so empty messages have a valid frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # IPC frame for an empty payload (4 bytes total):
        #   Bytes 0-3 : 0x00000000 -> length prefix = 0 (no payload)
        frame = pack_frame(b"")

        self.assertEqual(
            frame,
            b"\x00\x00\x00\x00",
            msg="pack_frame of an empty payload must be the zero length prefix only.",
        )

    def test__ipc__frame__pack__length_prefix_len_constant(self) -> None:
        """
        Ensure the length-prefix width constant matches the actual
        prefix the codec emits, so readers can size their initial
        read against it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            IPC__FRAME__LENGTH_PREFIX_LEN,
            len(struct.pack("!I", 0)),
            msg="IPC__FRAME__LENGTH_PREFIX_LEN must equal the packed prefix width.",
        )

    def test__ipc__frame__pack__oversize_payload_rejected(self) -> None:
        """
        Ensure 'pack_frame' refuses a payload larger than the maximum
        frame size so an absurd length cannot be put on the wire (the
        send-side mirror of the recv-side oversize guard).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        oversize = bytes(IPC__FRAME__MAX_PAYLOAD_LEN + 1)

        with self.assertRaises(IpcFrameError) as error:
            pack_frame(oversize)

        self.assertEqual(
            str(error.exception),
            f"[IPC] Frame payload length {len(oversize)} exceeds the maximum "
            f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
            msg="Oversize pack_frame must raise IpcFrameError with the canonical message.",
        )


class TestIpcFrameStream(TestCase):
    """
    The IPC frame send/recv round-trip tests over a real stream
    socketpair.
    """

    @override
    def setUp(self) -> None:
        """
        Create a connected AF_UNIX stream socketpair as the transport
        under test.
        """

        self._sock_a, self._sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self._sock_a.close)
        self.addCleanup(self._sock_b.close)

    def test__ipc__frame__roundtrip(self) -> None:
        """
        Ensure a payload written with 'send_frame' is recovered intact
        by 'recv_frame' on the peer end of the stream.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        send_frame(self._sock_a, b"hello world")

        self.assertEqual(
            recv_frame(self._sock_b),
            b"hello world",
            msg="recv_frame must recover the exact payload written by send_frame.",
        )

    def test__ipc__frame__roundtrip__empty_payload(self) -> None:
        """
        Ensure an empty payload round-trips as an empty bytes value,
        distinct from the clean-EOF 'None' sentinel.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        send_frame(self._sock_a, b"")

        self.assertEqual(
            recv_frame(self._sock_b),
            b"",
            msg="An empty payload must round-trip as b'' (not None).",
        )

    def test__ipc__frame__preserves_message_boundaries(self) -> None:
        """
        Ensure multiple frames written back-to-back on one stream are
        read back as separate messages, so the length prefix restores
        the boundaries the byte stream itself does not preserve.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        send_frame(self._sock_a, b"first")
        send_frame(self._sock_a, b"second")
        send_frame(self._sock_a, b"third")

        self.assertEqual(
            [recv_frame(self._sock_b) for _ in range(3)],
            [b"first", b"second", b"third"],
            msg="recv_frame must restore per-message boundaries from the byte stream.",
        )

    def test__ipc__frame__large_payload_reassembled(self) -> None:
        """
        Ensure a payload larger than a single kernel stream segment is
        reassembled across partial reads, so the recv loop does not
        assume one read yields the whole payload.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = bytes(range(256)) * 4096  # 1 MiB, will span many reads

        # A 1 MiB payload exceeds the socketpair's kernel send buffer,
        # so 'send_frame' (a blocking sendall) cannot complete until the
        # peer drains it. Run the send on a worker thread so 'recv_frame'
        # in the test thread drains concurrently — without this the two
        # blocking calls would deadlock.
        sender = threading.Thread(target=send_frame, args=(self._sock_a, payload))
        sender.start()
        self.addCleanup(sender.join)

        self.assertEqual(
            recv_frame(self._sock_b),
            payload,
            msg="recv_frame must reassemble a multi-segment payload exactly.",
        )

    def test__ipc__frame__clean_eof_returns_none(self) -> None:
        """
        Ensure 'recv_frame' returns None when the peer closes the
        stream at a frame boundary, signalling end-of-stream rather
        than a truncated frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._sock_a.close()

        self.assertIsNone(
            recv_frame(self._sock_b),
            msg="recv_frame must return None on a clean EOF at a frame boundary.",
        )

    def test__ipc__frame__truncated_prefix_raises(self) -> None:
        """
        Ensure 'recv_frame' raises 'IpcFrameError' when the peer closes
        after sending only part of the length prefix, so a half-written
        header is reported rather than silently treated as EOF.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._sock_a.sendall(b"\x00\x00")  # 2 of 4 prefix bytes, then close
        self._sock_a.close()

        with self.assertRaises(IpcFrameError) as error:
            recv_frame(self._sock_b)

        self.assertEqual(
            str(error.exception),
            "[IPC] Stream closed mid-frame while reading the 4-byte length prefix.",
            msg="A truncated length prefix must raise IpcFrameError.",
        )

    def test__ipc__frame__truncated_payload_raises(self) -> None:
        """
        Ensure 'recv_frame' raises 'IpcFrameError' when the peer closes
        after a complete length prefix but before the full payload, so
        a truncated message is reported rather than returned short.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Length prefix announces 10 bytes; only 3 follow before close.
        self._sock_a.sendall(struct.pack("!I", 10) + b"abc")
        self._sock_a.close()

        with self.assertRaises(IpcFrameError) as error:
            recv_frame(self._sock_b)

        self.assertEqual(
            str(error.exception),
            "[IPC] Stream closed mid-frame: expected 10 payload bytes, got 3.",
            msg="A truncated payload must raise IpcFrameError.",
        )

    def test__ipc__frame__oversize_prefix_raises(self) -> None:
        """
        Ensure 'recv_frame' rejects a length prefix that announces a
        payload larger than the maximum, so a hostile or corrupt peer
        cannot drive an unbounded allocation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._sock_a.sendall(struct.pack("!I", IPC__FRAME__MAX_PAYLOAD_LEN + 1))

        with self.assertRaises(IpcFrameError) as error:
            recv_frame(self._sock_b)

        self.assertEqual(
            str(error.exception),
            f"[IPC] Frame length prefix {IPC__FRAME__MAX_PAYLOAD_LEN + 1} exceeds "
            f"the maximum of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
            msg="An oversize length prefix must raise IpcFrameError.",
        )


class TestIpcFrame__WireGoldens(TestCase):
    """
    Exact wire-byte goldens and boundary cases that pin the frame
    length-prefix format and the max-payload constant.
    """

    def test__frame__max_payload_constant_is_16_mib(self) -> None:
        """
        Ensure the maximum payload length is exactly 16 MiB, pinning the
        '16 * 1024 * 1024' constant arithmetic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            IPC__FRAME__MAX_PAYLOAD_LEN,
            16777216,
            msg="IPC__FRAME__MAX_PAYLOAD_LEN must be 16 MiB (16777216).",
        )

    def test__frame__pack_exact_wire_bytes(self) -> None:
        """
        Ensure pack_frame emits a 4-byte big-endian length prefix
        followed by the payload, byte-for-byte.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            pack_frame(b"abc"),
            bytes.fromhex("00000003616263"),
            msg="pack_frame(b'abc') must be 0x00000003 + 'abc'.",
        )
        self.assertEqual(
            pack_frame(b""),
            bytes.fromhex("00000000"),
            msg="pack_frame(b'') must be a 4-byte zero length prefix only.",
        )

    def test__frame__recv_clean_eof_returns_none(self) -> None:
        """
        Ensure recv_frame returns None on a clean EOF (peer closed with
        no bytes), pinning the empty-prefix check against a relational
        edit.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(receiver.close)
        sender.close()

        self.assertIsNone(
            recv_frame(receiver),
            msg="a clean EOF before any byte must yield None.",
        )

    def test__frame__recv_partial_prefix_rejected(self) -> None:
        """
        Ensure a connection that delivers fewer than the 4 prefix bytes
        before closing is rejected, pinning the partial-prefix length
        check.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(receiver.close)
        sender.sendall(b"\x00\x00")
        sender.close()

        with self.assertRaises(IpcFrameError):
            recv_frame(receiver)

    def test__frame__recv_roundtrips_packed_frame(self) -> None:
        """
        Ensure a packed frame sent over the transport is recovered
        exactly by recv_frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(receiver.close)
        self.addCleanup(sender.close)
        sender.sendall(pack_frame(b"hello"))

        self.assertEqual(
            recv_frame(receiver),
            b"hello",
            msg="a packed frame must round-trip through recv_frame.",
        )
