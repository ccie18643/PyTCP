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
Module contains tests for the DHCPv4 Maximum DHCP Message Size
option (RFC 2132 §9.10) wire-format codec.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__max_msg_size.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    UINT_16__MAX,
    Dhcp4IntegrityError,
    Dhcp4OptionMaxMsgSize,
    Dhcp4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionMaxMsgSizeAsserts(TestCase):
    """
    The DHCPv4 Maximum DHCP Message Size option constructor argument
    assert tests.
    """

    def test__dhcp4__option__max_msg_size__under_min(self) -> None:
        """
        Ensure the constructor raises when 'max_msg_size' is below
        the option's minimum value of 576 bytes.

        Reference: RFC 2132 §9.10 (min DHCP message size = 576).
        Reference: RFC 2131 §2 (baseline 576-byte message floor).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMaxMsgSize(575)

        self.assertEqual(
            str(error.exception),
            "The 'max_msg_size' field must be at least 576 bytes per RFC 2132 §9.10. Got: 575",
            msg="Unexpected 'max_msg_size' under-min assert message.",
        )

    def test__dhcp4__option__max_msg_size__over_max(self) -> None:
        """
        Ensure the constructor raises when 'max_msg_size' exceeds
        UINT_16__MAX. The wire-format encodes the size as a uint16.

        Reference: RFC 2132 §9.10 (16-bit field).
        """

        value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMaxMsgSize(value)

        self.assertEqual(
            str(error.exception),
            f"The 'max_msg_size' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'max_msg_size' over-max assert message.",
        )


@parameterized_class(
    [
        {
            "_description": "Minimum legal Max DHCP Message Size (576).",
            "_args": [576],
            "_results": {
                "__len__": 4,
                "__str__": "max_msg_size 576",
                "__repr__": "Dhcp4OptionMaxMsgSize(max_msg_size=576)",
                "__bytes__": (
                    # DHCPv4 Maximum DHCP Message Size option [RFC 2132 §9.10]
                    #   Code : 0x39 (57, Maximum DHCP Message Size)
                    #   Len  : 0x02 (2 bytes)
                    #   Data : 02 40    (576 bytes)
                    b"\x39\x02\x02\x40"
                ),
                "max_msg_size": 576,
            },
        },
        {
            "_description": "Standard Ethernet MTU (1500).",
            "_args": [1500],
            "_results": {
                "__len__": 4,
                "__str__": "max_msg_size 1500",
                "__repr__": "Dhcp4OptionMaxMsgSize(max_msg_size=1500)",
                "__bytes__": b"\x39\x02\x05\xdc",
                "max_msg_size": 1500,
            },
        },
        {
            "_description": "UINT_16__MAX upper bound.",
            "_args": [0xFFFF],
            "_results": {
                "__len__": 4,
                "__str__": "max_msg_size 65535",
                "__repr__": "Dhcp4OptionMaxMsgSize(max_msg_size=65535)",
                "__bytes__": b"\x39\x02\xff\xff",
                "max_msg_size": 0xFFFF,
            },
        },
    ]
)
class TestDhcp4OptionMaxMsgSizeAssembler(TestCase):
    """
    The DHCPv4 Maximum DHCP Message Size option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the SUT.
        """

        self._option = Dhcp4OptionMaxMsgSize(*self._args)

    def test__dhcp4__option__max_msg_size__len(self) -> None:
        """
        Ensure 'len(option)' equals the documented 4-byte total.

        Reference: RFC 2132 §9.10 (option layout: 1 + 1 + 2 bytes).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected len for case: {self._description}",
        )

    def test__dhcp4__option__max_msg_size__str(self) -> None:
        """
        Ensure '__str__' renders the documented short form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__max_msg_size__bytes(self) -> None:
        """
        Ensure 'bytes(option)' matches the wire-format byte sequence.

        Reference: RFC 2132 §9.10 (wire-format diagram).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__dhcp4__option__max_msg_size__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' round-trips back to the original
        'max_msg_size' value.

        Reference: RFC 2132 §9.10 (wire-format round-trip).
        """

        parsed = Dhcp4OptionMaxMsgSize.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            parsed.max_msg_size,
            self._results["max_msg_size"],
            msg=f"Unexpected round-trip max_msg_size for case: {self._description}",
        )


class TestDhcp4OptionMaxMsgSizeIntegrity(TestCase):
    """
    The DHCPv4 Maximum DHCP Message Size option integrity-check tests.
    """

    def test__dhcp4__option__max_msg_size__bad_length(self) -> None:
        """
        Ensure 'from_buffer' raises Dhcp4IntegrityError when the
        TLV's length byte does not equal the option's documented
        4-byte total.

        Reference: RFC 2132 §9.10 (length = 2).
        """

        # Type=57, Length=3 (wrong; must be 2 for a uint16 value).
        bad_buffer = b"\x39\x03\x05\xdc\x00"

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionMaxMsgSize.from_buffer(bad_buffer)

        self.assertIn(
            "length value must be 4 bytes",
            str(error.exception),
            msg="Bad-length DHCPv4 Max-Msg-Size option must raise Dhcp4IntegrityError.",
        )

    def test__dhcp4__option__max_msg_size__wrong_type(self) -> None:
        """
        Ensure 'from_buffer' refuses a buffer whose first byte is
        not 'Dhcp4OptionType.MAX_MSG_SIZE'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Type=51 (Lease Time, not Max-Msg-Size), Length=2.
        bad_buffer = b"\x33\x02\x05\xdc"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionMaxMsgSize.from_buffer(bad_buffer)

        self.assertIn(
            f"option type must be {Dhcp4OptionType.MAX_MSG_SIZE!r}",
            str(error.exception),
            msg="Wrong-type buffer must trigger the type assertion.",
        )

    def test__dhcp4__option__max_msg_size__wire_below_576_rejected(self) -> None:
        """
        Ensure 'from_buffer' raises Dhcp4IntegrityError when the
        wire value is below the option's 576-octet minimum,
        before the dataclass `__post_init__` would otherwise
        raise a bare AssertionError.

        Reference: RFC 2132 §9.10 (Maximum DHCP Message Size minimum 576).
        Reference: RFC 2131 §2 (baseline 576-byte DHCP message floor).
        """

        # Type=57, Length=2, value=575 (one below the §9.10 floor).
        bad_buffer = b"\x39\x02\x02\x3f"

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionMaxMsgSize.from_buffer(bad_buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Maximum DHCP Message Size option value must be "
            "at least 576 bytes (RFC 2132 §9.10). Got: 575",
            msg="Below-576 wire value must raise typed Dhcp4IntegrityError.",
        )
