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
Module contains tests for the DHCPv4 Client Identifier option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__client_id.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionClientId,
    Dhcp4OptionType,
)


class TestDhcp4OptionClientIdAsserts(TestCase):
    """
    The DHCPv4 Client Identifier option constructor argument assert tests.
    """

    def test__dhcp4__option__client_id__client_id__not_bytes(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option constructor raises an
        exception when the provided 'client_id' argument is not bytes.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        value = "not bytes"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClientId(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'client_id' field must be bytes. Got: {type(value)!r}",
            msg="Unexpected 'client_id' type assert message.",
        )

    def test__dhcp4__option__client_id__accepts_bytearray(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option accepts bytearray input.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        option = Dhcp4OptionClientId(bytearray(b"\xaa\xbb\xcc"))

        self.assertEqual(
            option.client_id,
            bytearray(b"\xaa\xbb\xcc"),
            msg="bytearray 'client_id' must be stored as-is.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Client Identifier option (2-byte boundary, RFC 2132 §9.14 minimum).",
            "_args": [b"\x01\xff"],
            "_results": {
                "__len__": 4,
                "__str__": "client_id 01:ff",
                "__repr__": "Dhcp4OptionClientId(client_id=b'\\x01\\xff')",
                "__bytes__": (
                    # DHCPv4 Client Identifier option [RFC 2132 §9.14]
                    #   Code : 0x3d (61, Client Identifier)
                    #   Len  : 0x02 (2 bytes — the RFC-mandated minimum)
                    #   Data : 01  (htype = Ethernet)
                    #          ff  (1-byte identifier)
                    b"\x3d\x02\x01\xff"
                ),
                "client_id": b"\x01\xff",
                "type": Dhcp4OptionType.CLIENT_ID,
                "len": 4,
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (6-byte ID).",
            "_args": [b"\xaa\xbb\xcc\xdd\xee\xff"],
            "_results": {
                "__len__": 8,
                "__str__": "client_id aa:bb:cc:dd:ee:ff",
                "__repr__": "Dhcp4OptionClientId(client_id=b'\\xaa\\xbb\\xcc\\xdd\\xee\\xff')",
                "__bytes__": (
                    # DHCPv4 Client Identifier option [RFC 2132]
                    #   Code : 0x3d (61, Client Identifier)
                    #   Len  : 0x06 (6 bytes)
                    #   Data : aa bb cc dd ee ff (raw 6-byte identifier)
                    b"\x3d\x06\xaa\xbb\xcc\xdd\xee\xff"
                ),
                "client_id": b"\xaa\xbb\xcc\xdd\xee\xff",
                "type": Dhcp4OptionType.CLIENT_ID,
                "len": 8,
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (htype + MAC, 7 bytes).",
            "_args": [b"\x01\xde\xad\xbe\xef\x00\x01"],
            "_results": {
                "__len__": 9,
                "__str__": "client_id 01:de:ad:be:ef:00:01",
                "__repr__": "Dhcp4OptionClientId(client_id=b'\\x01\\xde\\xad\\xbe\\xef\\x00\\x01')",
                "__bytes__": (
                    # DHCPv4 Client Identifier option [RFC 2132]
                    #   Code : 0x3d (61, Client Identifier)
                    #   Len  : 0x07 (7 bytes)
                    #   Data : 01  (htype = Ethernet)
                    #          de ad be ef 00 01  (MAC identifier)
                    b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01"
                ),
                "client_id": b"\x01\xde\xad\xbe\xef\x00\x01",
                "type": Dhcp4OptionType.CLIENT_ID,
                "len": 9,
            },
        },
    ]
)
class TestDhcp4OptionClientIdAssembler(TestCase):
    """
    The DHCPv4 Client Identifier option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Client Identifier option object with testcase
        arguments.
        """

        self._option = Dhcp4OptionClientId(*self._args)

    def test__dhcp4__option__client_id__len(self) -> None:
        """
        Ensure the option '__len__()' returns code + len + identifier bytes.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__client_id__str(self) -> None:
        """
        Ensure the option '__str__()' method renders the canonical log line.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__client_id__repr(self) -> None:
        """
        Ensure the option '__repr__()' method renders the dataclass form.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__client_id__bytes(self) -> None:
        """
        Ensure 'bytes()' on the option yields the expected wire image.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__client_id__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol and reproduces the
        same bytes as 'bytes(option)'.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__client_id__field(self) -> None:
        """
        Ensure the 'client_id' field reflects the constructor argument.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            self._option.client_id,
            self._results["client_id"],
            msg=f"Unexpected 'client_id' for case: {self._description}",
        )

    def test__dhcp4__option__client_id__type(self) -> None:
        """
        Ensure the option 'type' field is always CLIENT_ID.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__client_id__len_field(self) -> None:
        """
        Ensure the option 'len' field matches __len__().

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__client_id__roundtrip(self) -> None:
        """
        Ensure bytes(option) can be parsed back into an equal option.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            Dhcp4OptionClientId.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Client Identifier option (2-byte boundary, RFC §9.14 minimum).",
            "_args": [b"\x3d\x02\x01\xff" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionClientId(client_id=b"\x01\xff"),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (6-byte ID).",
            "_args": [b"\x3d\x06\xaa\xbb\xcc\xdd\xee\xff" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionClientId(client_id=b"\xaa\xbb\xcc\xdd\xee\xff"),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (htype + MAC, 7 bytes).",
            "_args": [b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionClientId(client_id=b"\x01\xde\xad\xbe\xef\x00\x01"),
            },
        },
    ]
)
class TestDhcp4OptionClientIdParser(TestCase):
    """
    The DHCPv4 Client Identifier option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__client_id__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        option = Dhcp4OptionClientId.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionClientIdParserErrors(TestCase):
    """
    The DHCPv4 Client Identifier option parser error tests.
    """

    def test__dhcp4__option__client_id__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClientId.from_buffer(b"\x3d")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Client Identifier option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__client_id__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 61.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClientId.from_buffer(b"\xfe\x01\x00")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Client Identifier option type must be {Dhcp4OptionType.CLIENT_ID!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__client_id__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionClientId.from_buffer(b"\x3d\x02")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Client Identifier option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 4",
            msg="Unexpected integrity-error message.",
        )

    def test__dhcp4__option__client_id__wire_len_below_minimum(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the wire
        length byte is less than the RFC-mandated minimum of 2. A
        valid Client Identifier carries a 1-byte type code plus at
        least 1 identifier byte.

        Reference: RFC 2132 §9.14 ("The code for this option is 61,
        and its minimum length is 2.").
        """

        # Wire frame: code=0x3d (61), length=0x01 (one byte of data
        # — below the §9.14 minimum of 2), plus a stray byte.
        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionClientId.from_buffer(b"\x3d\x01\x00")

        self.assertIn(
            "minimum length is 2",
            str(error.exception),
            msg="Integrity-error message must cite the RFC 2132 §9.14 minimum.",
        )


class TestDhcp4OptionClientIdBounds(TestCase):
    """
    The DHCPv4 Client Identifier option construction-time bounds
    tests. RFC 2132 §9.14 mandates a minimum data length of 2
    (1-byte type code + ≥ 1 identifier byte). The wire-format
    length byte is a single octet so the maximum data length is
    255.
    """

    def test__dhcp4__option__client_id__below_min_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4OptionClientId with fewer than
        2 bytes raises AssertionError at construction time, citing
        the spec-mandated minimum length.

        Reference: RFC 2132 §9.14 (minimum length is 2).
        """

        for value in (b"", b"\x01"):
            with self.subTest(value=value):
                with self.assertRaises(AssertionError) as error:
                    Dhcp4OptionClientId(value)
                self.assertIn(
                    "minimum length is 2",
                    str(error.exception),
                    msg=f"AssertionError must cite RFC 2132 §9.14 min for {value!r}.",
                )

    def test__dhcp4__option__client_id__over_uint8_rejected(self) -> None:
        """
        Ensure constructing a Dhcp4OptionClientId with more than 255
        bytes raises AssertionError at construction time, rather
        than failing deep inside __buffer__ with a struct.error
        when the length byte overflows uint8.

        Reference: RFC 2132 §9.14 (length is a single octet).
        """

        too_long = b"\x01" + b"x" * 255  # 256 bytes total

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClientId(too_long)

        self.assertIn(
            "must fit in a uint8",
            str(error.exception),
            msg="AssertionError must cite the uint8 length-byte ceiling.",
        )

    def test__dhcp4__option__client_id__boundary_2_bytes_accepted(self) -> None:
        """
        Ensure exactly 2 bytes (the spec-minimum boundary) is
        accepted at construction.

        Reference: RFC 2132 §9.14 (minimum length is 2).
        """

        # Should not raise.
        option = Dhcp4OptionClientId(b"\x01\xff")
        self.assertEqual(
            len(option.client_id),
            2,
            msg="Boundary 2-byte client_id must be accepted.",
        )

    def test__dhcp4__option__client_id__boundary_255_bytes_accepted(self) -> None:
        """
        Ensure exactly 255 bytes (the uint8 length-byte ceiling)
        is accepted at construction.

        Reference: RFC 2132 §9.14 (length field is a single octet).
        """

        # Should not raise.
        option = Dhcp4OptionClientId(b"\x01" + b"x" * 254)
        self.assertEqual(
            len(option.client_id),
            255,
            msg="Boundary 255-byte client_id must be accepted.",
        )


class TestDhcp4OptionClientIdBehavior(TestCase):
    """
    The DHCPv4 Client Identifier option behavioral tests.
    """

    def test__dhcp4__option__client_id__equality(self) -> None:
        """
        Ensure two options with equal 'client_id' compare equal.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertEqual(
            Dhcp4OptionClientId(b"\x01\x02\x03"),
            Dhcp4OptionClientId(b"\x01\x02\x03"),
            msg="Options with identical client_id must compare equal.",
        )

    def test__dhcp4__option__client_id__inequality(self) -> None:
        """
        Ensure two options with different 'client_id' compare unequal.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        self.assertNotEqual(
            Dhcp4OptionClientId(b"\x01\x02\x03"),
            Dhcp4OptionClientId(b"\x01\x02\x04"),
            msg="Options with different client_id must not compare equal.",
        )

    def test__dhcp4__option__client_id__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        option = Dhcp4OptionClientId(b"\x01\x02\x03")

        with self.assertRaises(FrozenInstanceError):
            option.client_id = b"\x04\x05\x06"  # type: ignore[misc]

    def test__dhcp4__option__client_id__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §9.14 (Client-identifier option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionClientId(  # type: ignore[call-arg]
                type=Dhcp4OptionType.CLIENT_ID,
                client_id=b"\x01\x02\x03",
            )
