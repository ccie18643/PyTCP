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
Module contains tests for the ICMPv6 Packet Too Big message.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__packet_too_big__assembler.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import (
    IP6__PAYLOAD__MAX_LEN,
    UINT_32__MAX,
    UINT_32__MIN,
    Icmp6Assembler,
    Icmp6MessagePacketTooBig,
    Icmp6PacketTooBigCode,
    Icmp6Type,
)
from net_proto.tests.lib.parameterized import parameterized_class

# RFC 4443 §3.2 — the embedded packet is truncated so the whole ICMPv6
# message fits the IPv6 minimum MTU: 1280 - 40 (IPv6 header) - 8 (PTB
# header) = 1232 octets.
_TRUNCATION_CAP = 1232


class TestIcmp6MessagePacketTooBigAsserts(TestCase):
    """
    The ICMPv6 Packet Too Big message constructor assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the Packet Too Big
        message constructor so each test can override one field.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6PacketTooBigCode.DEFAULT,
            "mtu": 1280,
            "data": b"",
        }

    def test__icmp6__message__packet_too_big__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions.

        Reference: RFC 4443 §3.2 (Packet Too Big wire format).
        """

        message = Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            len(message),
            8,
            msg="Default-constructed Packet Too Big (no data) must be 8 bytes.",
        )

    def test__icmp6__message__packet_too_big__code__not_Icmp6PacketTooBigCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' that is not an
        Icmp6PacketTooBigCode.

        Reference: RFC 4443 §3.2 (Packet Too Big code is 0).
        """

        self._kwargs["code"] = value = "not a code"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6PacketTooBigCode. Got: {type(value)!r}",
            msg="Unexpected assertion message for a non-Icmp6PacketTooBigCode 'code'.",
        )

    def test__icmp6__message__packet_too_big__mtu__under_min(self) -> None:
        """
        Ensure the constructor rejects an 'mtu' below UINT_32__MIN.

        Reference: RFC 4443 §3.2 (MTU is a 32-bit field).
        """

        self._kwargs["mtu"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'mtu' under UINT_32__MIN.",
        )

    def test__icmp6__message__packet_too_big__mtu__over_max(self) -> None:
        """
        Ensure the constructor rejects an 'mtu' above UINT_32__MAX.

        Reference: RFC 4443 §3.2 (MTU is a 32-bit field).
        """

        self._kwargs["mtu"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'mtu' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'mtu' over UINT_32__MAX.",
        )

    def test__icmp6__message__packet_too_big__data__not_bytes(self) -> None:
        """
        Ensure the constructor rejects a 'data' field that is not a
        bytes-like object.

        Reference: RFC 4443 §3.2 (embedded packet is an octet string).
        """

        self._kwargs["data"] = value = "not bytes"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be bytes, bytearray or memoryview. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-bytes 'data'.",
        )

    def test__icmp6__message__packet_too_big__data__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' field longer than the
        16-bit payload ceiling minus the 8-byte message header.

        Reference: RFC 4443 §3.2 (embedded packet bounded by the payload length field).
        """

        self._kwargs["data"] = b"X" * (IP6__PAYLOAD__MAX_LEN - 8 + 1)

        with self.assertRaises(AssertionError) as error:
            Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                f"The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP6__PAYLOAD__MAX_LEN - 8}. "
                f"Got: {IP6__PAYLOAD__MAX_LEN - 8 + 1!r}"
            ),
            msg="Unexpected assertion message for 'data' over the payload ceiling.",
        )

    def test__icmp6__message__packet_too_big__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure embedded data longer than the minimum-MTU limit is
        truncated so the whole message fits the IPv6 minimum MTU (1232
        octets of embedded data).

        Reference: RFC 4443 §3.2 (truncate so the message fits the minimum MTU).
        """

        self._kwargs["data"] = b"X" * (_TRUNCATION_CAP + 100)

        message = Icmp6MessagePacketTooBig(**self._kwargs)

        self.assertEqual(
            len(message.data),
            _TRUNCATION_CAP,
            msg=f"Embedded data must be truncated to {_TRUNCATION_CAP} octets.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Packet Too Big, mtu=1280, no data.",
            "_kwargs": {"code": Icmp6PacketTooBigCode.DEFAULT, "mtu": 1280, "data": b""},
            "_results": {
                "__len__": 8,
                "mtu": 1280,
                # PTB wire frame (8 bytes, message cksum left 0 — the
                # assembler injects the real checksum):
                #   Byte 0    : 0x02       -> type=PACKET_TOO_BIG (2)
                #   Byte 1    : 0x00       -> code=DEFAULT (0)
                #   Bytes 2-3 : 0x0000     -> cksum placeholder
                #   Bytes 4-7 : 0x00000500 -> mtu=1280
                "__bytes__": b"\x02\x00\x00\x00\x00\x00\x05\x00",
            },
        },
        {
            "_description": "ICMPv6 Packet Too Big, mtu=1500, 8-byte embedded data.",
            "_kwargs": {
                "code": Icmp6PacketTooBigCode.DEFAULT,
                "mtu": 1500,
                "data": b"\x00\x01\x02\x03\x04\x05\x06\x07",
            },
            "_results": {
                "__len__": 16,
                "mtu": 1500,
                # PTB wire frame (16 bytes):
                #   Byte 0     : 0x02       -> type=PACKET_TOO_BIG (2)
                #   Byte 1     : 0x00       -> code=DEFAULT (0)
                #   Bytes 2-3  : 0x0000     -> cksum placeholder
                #   Bytes 4-7  : 0x000005dc -> mtu=1500
                #   Bytes 8-15 : 0x0001..07 -> embedded data
                "__bytes__": b"\x02\x00\x00\x00\x00\x00\x05\xdc\x00\x01\x02\x03\x04\x05\x06\x07",
            },
        },
    ]
)
class TestIcmp6MessagePacketTooBigAssembler(TestCase):
    """
    The ICMPv6 Packet Too Big message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the Packet Too Big message from the parametrized kwargs.
        """

        self._message = Icmp6MessagePacketTooBig(**self._kwargs)

    def test__icmp6__message__packet_too_big__len(self) -> None:
        """
        Ensure 'len()' equals ICMP6__PACKET_TOO_BIG__LEN plus len(data).

        Reference: RFC 4443 §3.2 (Packet Too Big length = 8 + embedded data).
        """

        self.assertEqual(
            len(self._message),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__message__packet_too_big__type(self) -> None:
        """
        Ensure the 'type' field is Icmp6Type.PACKET_TOO_BIG.

        Reference: RFC 4443 §3.2 (Packet Too Big type is 2).
        """

        self.assertEqual(
            self._message.type,
            Icmp6Type.PACKET_TOO_BIG,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__message__packet_too_big__mtu(self) -> None:
        """
        Ensure the 'mtu' field exposes the provided value.

        Reference: RFC 4443 §3.2 (MTU of the next-hop link).
        """

        self.assertEqual(
            self._message.mtu,
            self._results["mtu"],
            msg=f"Unexpected 'mtu' for case: {self._description}",
        )

    def test__icmp6__message__packet_too_big__bytes(self) -> None:
        """
        Ensure 'bytes()' on the message yields the expected wire frame
        (type, code, cksum placeholder, mtu, embedded data).

        Reference: RFC 4443 §3.2 (Packet Too Big wire layout).
        """

        self.assertEqual(
            bytes(self._message),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__message__packet_too_big__assemble_wire_type(self) -> None:
        """
        Ensure 'assemble()' yields wire bytes whose first octet is
        type=2 (PACKET_TOO_BIG) and whose total length matches the
        message length.

        Reference: RFC 4443 §3.2 (Packet Too Big type byte is 2).
        """

        buffers: list[Buffer] = []
        Icmp6Assembler(icmp6__message=self._message).assemble(buffers)
        wire = b"".join(bytes(b) for b in buffers)

        self.assertEqual(wire[0], 2, msg="First wire byte must be type=2 (PACKET_TOO_BIG).")
        self.assertEqual(
            len(wire),
            self._results["__len__"],
            msg=f"Assembled wire length must equal the message length for case: {self._description}",
        )
