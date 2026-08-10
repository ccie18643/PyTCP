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
Tests for the IPC control-channel message envelope codec.

pytcp/tests/unit/ipc/test__ipc__message.py

ver 3.0.10
"""

import struct
from enum import IntEnum
from unittest import TestCase

from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__errors import IpcMessageError
from pytcp.ipc.ipc__message import (
    IPC__MESSAGE__HEADER_LEN,
    IpcMessage,
)


class TestIpcMessageEnums(TestCase):
    """
    The IPC message kind / op enum tests.
    """

    def test__ipc__message__kind_is_int_enum(self) -> None:
        """
        Ensure 'IpcMessageKind' is an 'IntEnum' so its members pack
        directly into the single-byte 'kind' header field.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(IpcMessageKind, IntEnum),
            msg="IpcMessageKind must be an IntEnum (it packs as a byte).",
        )

    def test__ipc__message__op_is_int_enum(self) -> None:
        """
        Ensure 'IpcOp' is an 'IntEnum' so its members pack directly
        into the two-byte 'op' header field.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(IpcOp, IntEnum),
            msg="IpcOp must be an IntEnum (it packs as a 16-bit word).",
        )


class TestIpcMessageCodec(TestCase):
    """
    The IPC message envelope encode / decode tests.
    """

    def test__ipc__message__header_layout(self) -> None:
        """
        Ensure a message encodes as a fixed 7-byte header
        (kind:u8, op:u16, req_id:u32) followed by the opaque body, so
        the on-wire envelope shape is pinned.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        message = IpcMessage(
            kind=IpcMessageKind.REQUEST,
            op=IpcOp.PING,
            req_id=7,
            body=b"",
        )

        # IPC message header for REQUEST/PING, req_id=7, empty body:
        #   Byte 0    : 0x00       -> kind = REQUEST (0)
        #   Bytes 1-2 : 0x0000     -> op = PING (0)
        #   Bytes 3-6 : 0x00000007 -> req_id = 7
        self.assertEqual(
            message.to_bytes(),
            b"\x00\x00\x00\x00\x00\x00\x07",
            msg="IpcMessage must encode as a 7-byte header then the body.",
        )

    def test__ipc__message__header_len_constant(self) -> None:
        """
        Ensure the header-length constant matches the packed header
        width so a decoder can split header from body against it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            IPC__MESSAGE__HEADER_LEN,
            len(struct.pack("! B H I", 0, 0, 0)),
            msg="IPC__MESSAGE__HEADER_LEN must equal the packed header width.",
        )

    def test__ipc__message__roundtrip_with_body(self) -> None:
        """
        Ensure a message with a non-empty body round-trips through
        encode then decode to an equal message, preserving every
        envelope field.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        message = IpcMessage(
            kind=IpcMessageKind.RESPONSE_OK,
            op=IpcOp.PING,
            req_id=0xDEADBEEF,
            body=b"PONG-payload",
        )

        self.assertEqual(
            IpcMessage.from_bytes(message.to_bytes()),
            message,
            msg="IpcMessage must survive an encode/decode round-trip intact.",
        )

    def test__ipc__message__roundtrip_empty_body(self) -> None:
        """
        Ensure a message with an empty body round-trips and decodes
        with 'body' equal to b'', not None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        message = IpcMessage(
            kind=IpcMessageKind.RESPONSE_ERROR,
            op=IpcOp.PING,
            req_id=1,
            body=b"",
        )

        decoded = IpcMessage.from_bytes(message.to_bytes())

        self.assertEqual(
            decoded.body,
            b"",
            msg="An empty body must decode to b'' (not None).",
        )

    def test__ipc__message__decode_preserves_fields(self) -> None:
        """
        Ensure decode recovers the exact kind, op, and req_id a message
        was built with, so the envelope routing fields are trustworthy.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        decoded = IpcMessage.from_bytes(
            IpcMessage(
                kind=IpcMessageKind.RESPONSE_OK,
                op=IpcOp.PING,
                req_id=42,
                body=b"x",
            ).to_bytes()
        )

        self.assertEqual(
            (decoded.kind, decoded.op, decoded.req_id),
            (IpcMessageKind.RESPONSE_OK, IpcOp.PING, 42),
            msg="Decoded kind / op / req_id must match the encoded message.",
        )

    def test__ipc__message__truncated_header_raises(self) -> None:
        """
        Ensure decoding a buffer shorter than the fixed header raises
        'IpcMessageError' rather than unpacking past the end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcMessageError) as error:
            IpcMessage.from_bytes(b"\x00\x00\x00")  # 3 of 7 header bytes

        self.assertEqual(
            str(error.exception),
            "[IPC] Message buffer of 3 bytes is shorter than the 7-byte header.",
            msg="A truncated message header must raise IpcMessageError.",
        )

    def test__ipc__message__unknown_kind_raises(self) -> None:
        """
        Ensure decoding a message whose 'kind' byte is not a known
        'IpcMessageKind' raises 'IpcMessageError', surfacing a protocol
        mismatch rather than crashing on the enum lookup.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # kind=0xFF (unknown), op=PING, req_id=0, no body.
        buffer = struct.pack("! B H I", 0xFF, 0, 0)

        with self.assertRaises(IpcMessageError) as error:
            IpcMessage.from_bytes(buffer)

        self.assertEqual(
            str(error.exception),
            "[IPC] Unknown message kind 255.",
            msg="An unknown message kind must raise IpcMessageError.",
        )

    def test__ipc__message__unknown_op_decodes_as_raw_int(self) -> None:
        """
        Ensure decoding a message whose 'op' word is not a known
        'IpcOp' member succeeds with 'op' as the raw integer, so an
        unsupported op survives decode and can be answered with a
        RESPONSE_ERROR at dispatch rather than failing here.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # kind=REQUEST, op=0xFFFF (not a defined IpcOp), req_id=0.
        buffer = struct.pack("! B H I", 0, 0xFFFF, 0)

        self.assertEqual(
            IpcMessage.from_bytes(buffer).op,
            0xFFFF,
            msg="An unknown op word must decode to the raw integer, not raise.",
        )
