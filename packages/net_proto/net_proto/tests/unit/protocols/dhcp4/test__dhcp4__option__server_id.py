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
Module contains tests for the DHCPv4 Server Identifier option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__server_id.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionServerId,
    Dhcp4OptionType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    DHCP4__OPTION__SERVER_ID__LEN,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionServerIdAsserts(TestCase):
    """
    The DHCPv4 Server Identifier option constructor argument assert tests.
    """

    def test__dhcp4__option__server_id__not_Ip4Address(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'server_id' argument is not an Ip4Address.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionServerId(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'server_id' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'server_id' type assert message.",
        )

    def test__dhcp4__option__server_id__rejects_str_ip(self) -> None:
        """
        Ensure the constructor rejects a dotted-decimal string address —
        Ip4Address instances are required.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        value = "192.0.2.1"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionServerId(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'server_id' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'server_id' type assert message for str.",
        )

    def test__dhcp4__option__server_id__rejects_int(self) -> None:
        """
        Ensure the constructor rejects a bare int — Ip4Address instances are
        required.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        value = 0xC0000201

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionServerId(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'server_id' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'server_id' type assert message for int.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-1).",
            "_args": [Ip4Address("192.0.2.1")],
            "_results": {
                "__len__": 6,
                "__str__": "server_id 192.0.2.1",
                "__repr__": "Dhcp4OptionServerId(server_id=Ip4Address('192.0.2.1'))",
                "__bytes__": (
                    # DHCPv4 Server Identifier option [RFC 2132]
                    #   Code : 0x36 (54, Server Identifier)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : c0 00 02 01   (192.0.2.1)
                    b"\x36\x04\xc0\x00\x02\x01"
                ),
                "server_id": Ip4Address("192.0.2.1"),
                "type": Dhcp4OptionType.SERVER_ID,
                "len": DHCP4__OPTION__SERVER_ID__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (low address).",
            "_args": [Ip4Address("1.2.3.4")],
            "_results": {
                "__len__": 6,
                "__str__": "server_id 1.2.3.4",
                "__repr__": "Dhcp4OptionServerId(server_id=Ip4Address('1.2.3.4'))",
                "__bytes__": (
                    # DHCPv4 Server Identifier option [RFC 2132]
                    #   Code : 0x36 (54, Server Identifier)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 01 02 03 04   (1.2.3.4)
                    b"\x36\x04\x01\x02\x03\x04"
                ),
                "server_id": Ip4Address("1.2.3.4"),
                "type": Dhcp4OptionType.SERVER_ID,
                "len": DHCP4__OPTION__SERVER_ID__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-3).",
            "_args": [Ip4Address("203.0.113.10")],
            "_results": {
                "__len__": 6,
                "__str__": "server_id 203.0.113.10",
                "__repr__": "Dhcp4OptionServerId(server_id=Ip4Address('203.0.113.10'))",
                "__bytes__": (
                    # DHCPv4 Server Identifier option [RFC 2132]
                    #   Code : 0x36 (54, Server Identifier)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : cb 00 71 0a   (203.0.113.10)
                    b"\x36\x04\xcb\x00\x71\x0a"
                ),
                "server_id": Ip4Address("203.0.113.10"),
                "type": Dhcp4OptionType.SERVER_ID,
                "len": DHCP4__OPTION__SERVER_ID__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (zero address).",
            "_args": [Ip4Address("0.0.0.0")],
            "_results": {
                "__len__": 6,
                "__str__": "server_id 0.0.0.0",
                "__repr__": "Dhcp4OptionServerId(server_id=Ip4Address('0.0.0.0'))",
                "__bytes__": (
                    # DHCPv4 Server Identifier option [RFC 2132]
                    #   Code : 0x36 (54, Server Identifier)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 00 00 00 00   (0.0.0.0)
                    b"\x36\x04\x00\x00\x00\x00"
                ),
                "server_id": Ip4Address("0.0.0.0"),
                "type": Dhcp4OptionType.SERVER_ID,
                "len": DHCP4__OPTION__SERVER_ID__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (broadcast address).",
            "_args": [Ip4Address("255.255.255.255")],
            "_results": {
                "__len__": 6,
                "__str__": "server_id 255.255.255.255",
                "__repr__": "Dhcp4OptionServerId(server_id=Ip4Address('255.255.255.255'))",
                "__bytes__": (
                    # DHCPv4 Server Identifier option [RFC 2132]
                    #   Code : 0x36 (54, Server Identifier)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff ff ff ff   (255.255.255.255)
                    b"\x36\x04\xff\xff\xff\xff"
                ),
                "server_id": Ip4Address("255.255.255.255"),
                "type": Dhcp4OptionType.SERVER_ID,
                "len": DHCP4__OPTION__SERVER_ID__LEN,
            },
        },
    ]
)
class TestDhcp4OptionServerIdAssembler(TestCase):
    """
    The DHCPv4 Server Identifier option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Server Identifier option object with testcase
        arguments.
        """

        self._option = Dhcp4OptionServerId(*self._args)

    def test__dhcp4__option__server_id__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 6-byte option length.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__server_id__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__server_id__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__server_id__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__server_id__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__server_id__field(self) -> None:
        """
        Ensure the 'server_id' field reflects the constructor argument.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            self._option.server_id,
            self._results["server_id"],
            msg=f"Unexpected 'server_id' for case: {self._description}",
        )

    def test__dhcp4__option__server_id__type(self) -> None:
        """
        Ensure the 'type' field is always SERVER_ID (54).

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__server_id__len_field(self) -> None:
        """
        Ensure the 'len' field equals DHCP4__OPTION__SERVER_ID__LEN.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__server_id__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            Dhcp4OptionServerId.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-1).",
            "_args": [b"\x36\x04\xc0\x00\x02\x01" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (low address).",
            "_args": [b"\x36\x04\x01\x02\x03\x04" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionServerId(Ip4Address("1.2.3.4")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-3).",
            "_args": [b"\x36\x04\xcb\x00\x71\x0a" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionServerId(Ip4Address("203.0.113.10")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (zero address).",
            "_args": [b"\x36\x04\x00\x00\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionServerId(Ip4Address("0.0.0.0")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (broadcast address).",
            "_args": [b"\x36\x04\xff\xff\xff\xff" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionServerId(Ip4Address("255.255.255.255")),
            },
        },
    ]
)
class TestDhcp4OptionServerIdParser(TestCase):
    """
    The DHCPv4 Server Identifier option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__server_id__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        option = Dhcp4OptionServerId.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionServerIdParserErrors(TestCase):
    """
    The DHCPv4 Server Identifier option parser error tests.
    """

    def test__dhcp4__option__server_id__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionServerId.from_buffer(b"\x36")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Server Identifier option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__server_id__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 54.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionServerId.from_buffer(b"\xfe\x04\xc0\x00\x02\x01")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Server Identifier option type must be {Dhcp4OptionType.SERVER_ID!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__server_id__bad_length_field(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length is not exactly 4 bytes.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionServerId.from_buffer(b"\x36\x03\xc0\x00\x02")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Server Identifier option length value must be 6 bytes. Got: 5",
            msg="Unexpected bad-length-field integrity error message.",
        )

    def test__dhcp4__option__server_id__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionServerId.from_buffer(b"\x36\x04")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Server Identifier option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 6",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp4OptionServerIdBehavior(TestCase):
    """
    The DHCPv4 Server Identifier option behavioral tests.
    """

    def test__dhcp4__option__server_id__equality(self) -> None:
        """
        Ensure two options with equal 'server_id' compare equal.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertEqual(
            Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
            Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
            msg="Options with identical server_id must compare equal.",
        )

    def test__dhcp4__option__server_id__inequality(self) -> None:
        """
        Ensure two options with different 'server_id' compare unequal.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        self.assertNotEqual(
            Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
            Dhcp4OptionServerId(Ip4Address("192.0.2.2")),
            msg="Options with different server_id must not compare equal.",
        )

    def test__dhcp4__option__server_id__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        option = Dhcp4OptionServerId(Ip4Address("192.0.2.1"))

        with self.assertRaises(FrozenInstanceError):
            option.server_id = Ip4Address("198.51.100.1")  # type: ignore[misc]

    def test__dhcp4__option__server_id__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §9.7 (Server Identifier option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionServerId(  # type: ignore[call-arg]
                Ip4Address("192.0.2.1"),
                type=Dhcp4OptionType.SERVER_ID,
            )


class TestDhcp4OptionServerIdWrongType(TestCase):
    """
    The DHCPv4 Server Identifier option wrong-code-byte parser tests.
    """

    def test__dhcp4__option__server_id__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code byte equals
        Dhcp4OptionType.SERVER_ID and rejects a code byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: RFC 2132 §9.7 (Server Identifier option code 54).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionServerId.from_buffer(b"\x00\x04\x0a\x00\x00\x01")

    def test__dhcp4__option__server_id__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code byte above
        Dhcp4OptionType.SERVER_ID, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 2132 §9.7 (Server Identifier option code 54).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionServerId.from_buffer(b"\xff\x04\x0a\x00\x00\x01")
