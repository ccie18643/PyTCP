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
Module contains tests for the DHCPv4 Requested IP Address option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__req_ip_addr.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionReqIpAddr,
    Dhcp4OptionType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__req_ip_addr import (
    DHCP4__OPTION__REQ_IP_ADDR__LEN,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionReqIpAddrAsserts(TestCase):
    """
    The DHCPv4 Requested IP Address option constructor argument assert tests.
    """

    def test__dhcp4__option__req_ip_addr__not_Ip4Address(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'req_ip_addr' argument is not an Ip4Address.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionReqIpAddr(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'req_ip_addr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'req_ip_addr' type assert message.",
        )

    def test__dhcp4__option__req_ip_addr__rejects_str_ip(self) -> None:
        """
        Ensure the constructor rejects a dotted-decimal string address —
        Ip4Address instances are required.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        value = "192.0.2.1"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionReqIpAddr(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'req_ip_addr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'req_ip_addr' type assert message for str.",
        )

    def test__dhcp4__option__req_ip_addr__rejects_int(self) -> None:
        """
        Ensure the constructor rejects a bare int — Ip4Address instances are
        required.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        value = 0xC0000201

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionReqIpAddr(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'req_ip_addr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'req_ip_addr' type assert message for int.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Requested IP Address option (TEST-NET-1).",
            "_args": [Ip4Address("192.0.2.1")],
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 192.0.2.1",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('192.0.2.1'))",
                "__bytes__": (
                    # DHCPv4 Requested IP Address option [RFC 2132]
                    #   Code : 0x32 (50, Requested IP Address)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : c0 00 02 01   (192.0.2.1)
                    b"\x32\x04\xc0\x00\x02\x01"
                ),
                "req_ip_addr": Ip4Address("192.0.2.1"),
                "type": Dhcp4OptionType.REQ_IP_ADDR,
                "len": DHCP4__OPTION__REQ_IP_ADDR__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (low address).",
            "_args": [Ip4Address("1.2.3.4")],
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 1.2.3.4",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('1.2.3.4'))",
                "__bytes__": (
                    # DHCPv4 Requested IP Address option [RFC 2132]
                    #   Code : 0x32 (50, Requested IP Address)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 01 02 03 04   (1.2.3.4)
                    b"\x32\x04\x01\x02\x03\x04"
                ),
                "req_ip_addr": Ip4Address("1.2.3.4"),
                "type": Dhcp4OptionType.REQ_IP_ADDR,
                "len": DHCP4__OPTION__REQ_IP_ADDR__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (TEST-NET-3).",
            "_args": [Ip4Address("203.0.113.10")],
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 203.0.113.10",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('203.0.113.10'))",
                "__bytes__": (
                    # DHCPv4 Requested IP Address option [RFC 2132]
                    #   Code : 0x32 (50, Requested IP Address)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : cb 00 71 0a   (203.0.113.10)
                    b"\x32\x04\xcb\x00\x71\x0a"
                ),
                "req_ip_addr": Ip4Address("203.0.113.10"),
                "type": Dhcp4OptionType.REQ_IP_ADDR,
                "len": DHCP4__OPTION__REQ_IP_ADDR__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (zero address).",
            "_args": [Ip4Address("0.0.0.0")],
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 0.0.0.0",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('0.0.0.0'))",
                "__bytes__": (
                    # DHCPv4 Requested IP Address option [RFC 2132]
                    #   Code : 0x32 (50, Requested IP Address)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 00 00 00 00   (0.0.0.0)
                    b"\x32\x04\x00\x00\x00\x00"
                ),
                "req_ip_addr": Ip4Address("0.0.0.0"),
                "type": Dhcp4OptionType.REQ_IP_ADDR,
                "len": DHCP4__OPTION__REQ_IP_ADDR__LEN,
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (broadcast address).",
            "_args": [Ip4Address("255.255.255.255")],
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 255.255.255.255",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('255.255.255.255'))",
                "__bytes__": (
                    # DHCPv4 Requested IP Address option [RFC 2132]
                    #   Code : 0x32 (50, Requested IP Address)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : ff ff ff ff   (255.255.255.255)
                    b"\x32\x04\xff\xff\xff\xff"
                ),
                "req_ip_addr": Ip4Address("255.255.255.255"),
                "type": Dhcp4OptionType.REQ_IP_ADDR,
                "len": DHCP4__OPTION__REQ_IP_ADDR__LEN,
            },
        },
    ]
)
class TestDhcp4OptionReqIpAddrAssembler(TestCase):
    """
    The DHCPv4 Requested IP Address option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Requested IP Address option object with
        testcase arguments.
        """

        self._option = Dhcp4OptionReqIpAddr(*self._args)

    def test__dhcp4__option__req_ip_addr__len(self) -> None:
        """
        Ensure '__len__()' returns the fixed 6-byte option length.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__field(self) -> None:
        """
        Ensure the 'req_ip_addr' field reflects the constructor argument.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            self._option.req_ip_addr,
            self._results["req_ip_addr"],
            msg=f"Unexpected 'req_ip_addr' for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__type(self) -> None:
        """
        Ensure the 'type' field is always REQ_IP_ADDR (50).

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__len_field(self) -> None:
        """
        Ensure the 'len' field equals DHCP4__OPTION__REQ_IP_ADDR__LEN.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__req_ip_addr__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            Dhcp4OptionReqIpAddr.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Requested IP Address option (TEST-NET-1).",
            "_args": [b"\x32\x04\xc0\x00\x02\x01" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.1")),
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (low address).",
            "_args": [b"\x32\x04\x01\x02\x03\x04" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionReqIpAddr(Ip4Address("1.2.3.4")),
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (TEST-NET-3).",
            "_args": [b"\x32\x04\xcb\x00\x71\x0a" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionReqIpAddr(Ip4Address("203.0.113.10")),
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (zero address).",
            "_args": [b"\x32\x04\x00\x00\x00\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionReqIpAddr(Ip4Address("0.0.0.0")),
            },
        },
        {
            "_description": "The DHCPv4 Requested IP Address option (broadcast address).",
            "_args": [b"\x32\x04\xff\xff\xff\xff" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionReqIpAddr(Ip4Address("255.255.255.255")),
            },
        },
    ]
)
class TestDhcp4OptionReqIpAddrParser(TestCase):
    """
    The DHCPv4 Requested IP Address option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__req_ip_addr__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        option = Dhcp4OptionReqIpAddr.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionReqIpAddrParserErrors(TestCase):
    """
    The DHCPv4 Requested IP Address option parser error tests.
    """

    def test__dhcp4__option__req_ip_addr__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionReqIpAddr.from_buffer(b"\x32")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Requested IP Address option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__req_ip_addr__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 50.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionReqIpAddr.from_buffer(b"\xfe\x04\xc0\x00\x02\x01")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Requested IP Address option type must be {Dhcp4OptionType.REQ_IP_ADDR!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__req_ip_addr__bad_length_field(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length is not exactly 4 bytes.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionReqIpAddr.from_buffer(b"\x32\x03\xc0\x00\x02")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Requested IP Address option length value must be 6 bytes. Got: 5",
            msg="Unexpected bad-length-field integrity error message.",
        )

    def test__dhcp4__option__req_ip_addr__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionReqIpAddr.from_buffer(b"\x32\x04")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Requested IP Address option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 6",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp4OptionReqIpAddrBehavior(TestCase):
    """
    The DHCPv4 Requested IP Address option behavioral tests.
    """

    def test__dhcp4__option__req_ip_addr__equality(self) -> None:
        """
        Ensure two options with equal 'req_ip_addr' compare equal.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertEqual(
            Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.1")),
            Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.1")),
            msg="Options with identical req_ip_addr must compare equal.",
        )

    def test__dhcp4__option__req_ip_addr__inequality(self) -> None:
        """
        Ensure two options with different 'req_ip_addr' compare unequal.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        self.assertNotEqual(
            Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.1")),
            Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.2")),
            msg="Options with different req_ip_addr must not compare equal.",
        )

    def test__dhcp4__option__req_ip_addr__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        option = Dhcp4OptionReqIpAddr(Ip4Address("192.0.2.1"))

        with self.assertRaises(FrozenInstanceError):
            option.req_ip_addr = Ip4Address("198.51.100.1")  # type: ignore[misc]

    def test__dhcp4__option__req_ip_addr__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §9.1 (Requested IP Address option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionReqIpAddr(  # type: ignore[call-arg]
                Ip4Address("192.0.2.1"),
                type=Dhcp4OptionType.REQ_IP_ADDR,
            )


class TestDhcp4OptionReqIpAddrWrongType(TestCase):
    """
    The DHCPv4 Requested IP Address option wrong-code-byte parser tests.
    """

    def test__dhcp4__option__req_ip_addr__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code byte equals
        Dhcp4OptionType.REQ_IP_ADDR and rejects a code byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: RFC 2132 §9.1 (Requested IP Address option code 50).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionReqIpAddr.from_buffer(b"\x00\x04\x0a\x00\x00\x05")

    def test__dhcp4__option__req_ip_addr__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code byte above
        Dhcp4OptionType.REQ_IP_ADDR, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 2132 §9.1 (Requested IP Address option code 50).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionReqIpAddr.from_buffer(b"\xff\x04\x0a\x00\x00\x05")
