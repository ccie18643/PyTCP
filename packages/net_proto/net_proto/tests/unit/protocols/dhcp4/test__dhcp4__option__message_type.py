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
Module contains tests for the DHCPv4 Message Type option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__message_type.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4MessageType,
    Dhcp4OptionMessageType,
    Dhcp4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionMessageTypeAsserts(TestCase):
    """
    The DHCPv4 Message Type option constructor argument assert tests.
    """

    def test__dhcp4__option__message_type__not_Dhcp4MessageType(self) -> None:
        """
        Ensure the DHCPv4 Message Type option constructor raises an exception
        when the provided 'message_type' argument is not a Dhcp4MessageType.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        value = "not a Dhcp4MessageType"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMessageType(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'message_type' field must be a Dhcp4MessageType. Got: {type(value)!r}",
            msg="Unexpected 'message_type' type assert message.",
        )

    def test__dhcp4__option__message_type__rejects_raw_int(self) -> None:
        """
        Ensure the DHCPv4 Message Type option constructor rejects a raw int.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMessageType(1)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'message_type' field must be a Dhcp4MessageType. Got: {type(1)!r}",
            msg="Unexpected 'message_type' type assert message for int.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Message Type option (DISCOVER).",
            "_message_type": Dhcp4MessageType.DISCOVER,
            "_str": "message_type Discover",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.DISCOVER: 1>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 01   (DHCPDISCOVER)
            "_bytes": b"\x35\x01\x01",
        },
        {
            "_description": "The DHCPv4 Message Type option (OFFER).",
            "_message_type": Dhcp4MessageType.OFFER,
            "_str": "message_type Offer",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.OFFER: 2>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 02   (DHCPOFFER)
            "_bytes": b"\x35\x01\x02",
        },
        {
            "_description": "The DHCPv4 Message Type option (REQUEST).",
            "_message_type": Dhcp4MessageType.REQUEST,
            "_str": "message_type Request",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.REQUEST: 3>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 03   (DHCPREQUEST)
            "_bytes": b"\x35\x01\x03",
        },
        {
            "_description": "The DHCPv4 Message Type option (DECLINE).",
            "_message_type": Dhcp4MessageType.DECLINE,
            "_str": "message_type Decline",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.DECLINE: 4>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 04   (DHCPDECLINE)
            "_bytes": b"\x35\x01\x04",
        },
        {
            "_description": "The DHCPv4 Message Type option (ACK).",
            "_message_type": Dhcp4MessageType.ACK,
            "_str": "message_type ACK",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.ACK: 5>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 05   (DHCPACK)
            "_bytes": b"\x35\x01\x05",
        },
        {
            "_description": "The DHCPv4 Message Type option (NAK).",
            "_message_type": Dhcp4MessageType.NAK,
            "_str": "message_type NAK",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.NAK: 6>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 06   (DHCPNAK)
            "_bytes": b"\x35\x01\x06",
        },
        {
            "_description": "The DHCPv4 Message Type option (RELEASE).",
            "_message_type": Dhcp4MessageType.RELEASE,
            "_str": "message_type Release",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.RELEASE: 7>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 07   (DHCPRELEASE)
            "_bytes": b"\x35\x01\x07",
        },
        {
            "_description": "The DHCPv4 Message Type option (INFORM).",
            "_message_type": Dhcp4MessageType.INFORM,
            "_str": "message_type Inform",
            "_repr": "Dhcp4OptionMessageType(message_type=<Dhcp4MessageType.INFORM: 8>)",
            # DHCPv4 Message Type option [RFC 2132]
            #   Code : 0x35 (53, Message Type)
            #   Len  : 0x01 (1 byte)
            #   Data : 08   (DHCPINFORM)
            "_bytes": b"\x35\x01\x08",
        },
    ]
)
class TestDhcp4OptionMessageTypeAssembler(TestCase):
    """
    The DHCPv4 Message Type option assembler tests.
    """

    _description: str
    _message_type: Dhcp4MessageType
    _str: str
    _repr: str
    _bytes: bytes

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Message Type option object.
        """

        self._option = Dhcp4OptionMessageType(self._message_type)

    def test__dhcp4__option__message_type__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 3 bytes (code + len + value).

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            len(self._option),
            3,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__message_type__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            str(self._option),
            self._str,
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__message_type__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            repr(self._option),
            self._repr,
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__message_type__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            bytes(self._option),
            self._bytes,
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__message_type__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._bytes,
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__message_type__field(self) -> None:
        """
        Ensure the 'message_type' field reflects the constructor argument.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            self._option.message_type,
            self._message_type,
            msg=f"Unexpected 'message_type' for case: {self._description}",
        )

    def test__dhcp4__option__message_type__type(self) -> None:
        """
        Ensure the 'type' field is always MESSAGE_TYPE (53).

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            self._option.type,
            Dhcp4OptionType.MESSAGE_TYPE,
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__message_type__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            Dhcp4OptionMessageType.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Message Type option (DISCOVER).",
            "_buffer": b"\x35\x01\x01" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
        },
        {
            "_description": "The DHCPv4 Message Type option (OFFER).",
            "_buffer": b"\x35\x01\x02" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.OFFER),
        },
        {
            "_description": "The DHCPv4 Message Type option (REQUEST).",
            "_buffer": b"\x35\x01\x03" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.REQUEST),
        },
        {
            "_description": "The DHCPv4 Message Type option (DECLINE).",
            "_buffer": b"\x35\x01\x04" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DECLINE),
        },
        {
            "_description": "The DHCPv4 Message Type option (ACK).",
            "_buffer": b"\x35\x01\x05" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.ACK),
        },
        {
            "_description": "The DHCPv4 Message Type option (NAK).",
            "_buffer": b"\x35\x01\x06" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.NAK),
        },
        {
            "_description": "The DHCPv4 Message Type option (RELEASE).",
            "_buffer": b"\x35\x01\x07" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.RELEASE),
        },
        {
            "_description": "The DHCPv4 Message Type option (INFORM).",
            "_buffer": b"\x35\x01\x08" + b"ZH0PA",
            "_expected": Dhcp4OptionMessageType(message_type=Dhcp4MessageType.INFORM),
        },
    ]
)
class TestDhcp4OptionMessageTypeParser(TestCase):
    """
    The DHCPv4 Message Type option parser (success) tests.
    """

    _description: str
    _buffer: bytes
    _expected: Dhcp4OptionMessageType

    def test__dhcp4__option__message_type__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            Dhcp4OptionMessageType.from_buffer(self._buffer),
            self._expected,
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionMessageTypeParserErrors(TestCase):
    """
    The DHCPv4 Message Type option parser error tests.
    """

    def test__dhcp4__option__message_type__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMessageType.from_buffer(b"\x35")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Message Type option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__message_type__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 53.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMessageType.from_buffer(b"\xfe\x01\x01")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Message Type option type must be {Dhcp4OptionType.MESSAGE_TYPE!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__message_type__bad_length_field(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        option length is not 1.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionMessageType.from_buffer(b"\x35\x00\x01")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Message Type option length value must be 3 bytes. Got: 2",
            msg="Unexpected bad-length-field integrity message.",
        )

    def test__dhcp4__option__message_type__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionMessageType.from_buffer(b"\x35\x01")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Message Type option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 3",
            msg="Unexpected truncated-buffer integrity message.",
        )


class TestDhcp4OptionMessageTypeBehavior(TestCase):
    """
    The DHCPv4 Message Type option behavioral tests.
    """

    def test__dhcp4__option__message_type__equality(self) -> None:
        """
        Ensure two options with equal 'message_type' compare equal.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertEqual(
            Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
            Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
            msg="Options with identical message_type must compare equal.",
        )

    def test__dhcp4__option__message_type__inequality(self) -> None:
        """
        Ensure two options with different 'message_type' compare unequal.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        self.assertNotEqual(
            Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
            Dhcp4OptionMessageType(Dhcp4MessageType.ACK),
            msg="Options with different message_type must not compare equal.",
        )

    def test__dhcp4__option__message_type__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        option = Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER)

        with self.assertRaises(FrozenInstanceError):
            option.message_type = Dhcp4MessageType.ACK  # type: ignore[misc]

    def test__dhcp4__option__message_type__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §9.6 (DHCP Message Type option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionMessageType(  # type: ignore[call-arg]
                type=Dhcp4OptionType.MESSAGE_TYPE,
                message_type=Dhcp4MessageType.DISCOVER,
            )


class TestDhcp4OptionMessageTypeWrongType(TestCase):
    """
    The DHCPv4 Message Type option wrong-code-byte parser tests.
    """

    def test__dhcp4__option__message_type__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code byte equals
        Dhcp4OptionType.MESSAGE_TYPE and rejects a code byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: RFC 2132 §9.6 (DHCP Message Type option code 53).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionMessageType.from_buffer(b"\x00\x01\x01")

    def test__dhcp4__option__message_type__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code byte above
        Dhcp4OptionType.MESSAGE_TYPE, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 2132 §9.6 (DHCP Message Type option code 53).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionMessageType.from_buffer(b"\xff\x01\x01")
