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
This module contains tests for the DHCPv4 Classless Static Route
option (option 121, RFC 3442).

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__classless_static_route.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address, Ip4Network
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionClasslessStaticRoute,
    Dhcp4OptionType,
)
from net_proto.tests.lib.parameterized import parameterized_class


class TestDhcp4OptionClasslessStaticRouteAsserts(TestCase):
    """
    The DHCPv4 Classless Static Route option constructor assert tests.
    """

    def test__dhcp4__option__classless_static_route__not_list(self) -> None:
        """
        Ensure the constructor rejects a non-list 'routes' field.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClasslessStaticRoute(
                (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),  # type: ignore[arg-type]
            )

        self.assertEqual(
            str(error.exception),
            "The 'routes' field must be a list. Got: <class 'tuple'>",
            msg="A non-list 'routes' field must be rejected.",
        )

    def test__dhcp4__option__classless_static_route__bad_element(self) -> None:
        """
        Ensure the constructor rejects a 'routes' element that is not
        an (Ip4Network, Ip4Address) tuple.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClasslessStaticRoute(
                [(Ip4Address("10.0.0.0"), Ip4Address("192.0.2.1"))],  # type: ignore[list-item]
            )

        self.assertIn(
            "must be a list of (Ip4Network, Ip4Address) tuples",
            str(error.exception),
            msg="A 'routes' element with the wrong shape must be rejected.",
        )

    def test__dhcp4__option__classless_static_route__empty(self) -> None:
        """
        Ensure the constructor rejects an empty 'routes' list (the
        option minimum length is 5 octets).

        Reference: RFC 3442 (Classless Route Option Format, minimum length 5).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClasslessStaticRoute([])

        self.assertIn(
            "must carry at least 1 route",
            str(error.exception),
            msg="An empty 'routes' list must be rejected.",
        )


@parameterized_class(
    [
        {
            "_description": "Single default route (0.0.0.0/0 via 192.0.2.1).",
            "_args": [[(Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1"))]],
            "_results": {
                "__len__": 7,
                "__str__": "classless_static_route ['0.0.0.0/0 via 192.0.2.1']",
                "__repr__": (
                    "Dhcp4OptionClasslessStaticRoute(" "routes=[(Ip4Network('0.0.0.0/0'), Ip4Address('192.0.2.1'))])"
                ),
                "__bytes__": (
                    # DHCPv4 Classless Static Route option [RFC 3442]
                    #   Code  : 0x79 (121)
                    #   Len   : 0x05 (5 bytes)
                    #   Route : 00            -> width 0 (default route, 0 significant octets)
                    #           c0 00 02 01   -> router 192.0.2.1
                    b"\x79\x05\x00\xc0\x00\x02\x01"
                ),
                "routes": [(Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1"))],
                "type": Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                "len": 7,
            },
        },
        {
            "_description": "Single /24 route (10.0.0.0/24 via 192.0.2.1).",
            "_args": [[(Ip4Network("10.0.0.0/24"), Ip4Address("192.0.2.1"))]],
            "_results": {
                "__len__": 10,
                "__str__": "classless_static_route ['10.0.0.0/24 via 192.0.2.1']",
                "__repr__": (
                    "Dhcp4OptionClasslessStaticRoute(" "routes=[(Ip4Network('10.0.0.0/24'), Ip4Address('192.0.2.1'))])"
                ),
                "__bytes__": (
                    # DHCPv4 Classless Static Route option [RFC 3442]
                    #   Code  : 0x79 (121)
                    #   Len   : 0x08 (8 bytes)
                    #   Route : 18 0a 00 00   -> width 24, subnet 10.0.0 (3 significant octets)
                    #           c0 00 02 01   -> router 192.0.2.1
                    b"\x79\x08\x18\x0a\x00\x00\xc0\x00\x02\x01"
                ),
                "routes": [(Ip4Network("10.0.0.0/24"), Ip4Address("192.0.2.1"))],
                "type": Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                "len": 10,
            },
        },
        {
            "_description": "Single /8 route (10.0.0.0/8 via 10.0.0.1).",
            "_args": [[(Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1"))]],
            "_results": {
                "__len__": 8,
                "__str__": "classless_static_route ['10.0.0.0/8 via 10.0.0.1']",
                "__repr__": (
                    "Dhcp4OptionClasslessStaticRoute(" "routes=[(Ip4Network('10.0.0.0/8'), Ip4Address('10.0.0.1'))])"
                ),
                "__bytes__": (
                    # DHCPv4 Classless Static Route option [RFC 3442]
                    #   Code  : 0x79 (121)
                    #   Len   : 0x06 (6 bytes)
                    #   Route : 08 0a         -> width 8, subnet 10 (1 significant octet)
                    #           0a 00 00 01   -> router 10.0.0.1
                    b"\x79\x06\x08\x0a\x0a\x00\x00\x01"
                ),
                "routes": [(Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1"))],
                "type": Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                "len": 8,
            },
        },
        {
            "_description": "Two routes (default + classless /8).",
            "_args": [
                [
                    (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),
                    (Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1")),
                ]
            ],
            "_results": {
                "__len__": 13,
                "__str__": "classless_static_route ['0.0.0.0/0 via 192.0.2.1', '10.0.0.0/8 via 10.0.0.1']",
                "__repr__": (
                    "Dhcp4OptionClasslessStaticRoute("
                    "routes=[(Ip4Network('0.0.0.0/0'), Ip4Address('192.0.2.1')), "
                    "(Ip4Network('10.0.0.0/8'), Ip4Address('10.0.0.1'))])"
                ),
                "__bytes__": (
                    # DHCPv4 Classless Static Route option [RFC 3442]
                    #   Code  : 0x79 (121)
                    #   Len   : 0x0b (11 bytes)
                    #   Route1: 00            -> width 0 (default route)
                    #           c0 00 02 01   -> router 192.0.2.1
                    #   Route2: 08 0a         -> width 8, subnet 10
                    #           0a 00 00 01   -> router 10.0.0.1
                    b"\x79\x0b\x00\xc0\x00\x02\x01\x08\x0a\x0a\x00\x00\x01"
                ),
                "routes": [
                    (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),
                    (Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1")),
                ],
                "type": Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                "len": 13,
            },
        },
    ]
)
class TestDhcp4OptionClasslessStaticRouteAssembler(TestCase):
    """
    The DHCPv4 Classless Static Route option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the option object with the testcase arguments.
        """

        self._option = Dhcp4OptionClasslessStaticRoute(*self._args)

    def test__dhcp4__option__classless_static_route__len(self) -> None:
        """
        Ensure '__len__()' returns the full option length.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__str(self) -> None:
        """
        Ensure '__str__()' renders the route list.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__bytes(self) -> None:
        """
        Ensure 'bytes()' renders the compact RFC 3442 wire encoding.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__routes_field(self) -> None:
        """
        Ensure the 'routes' field exposes the route list.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            self._option.routes,
            self._results["routes"],
            msg=f"Unexpected 'routes' for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__type_field(self) -> None:
        """
        Ensure the 'type' field is the option-121 codepoint.

        Reference: RFC 3442 (option code 121).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__len_field(self) -> None:
        """
        Ensure the 'len' field is the full option length.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__classless_static_route__roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(option))' reconstructs an equal option.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            Dhcp4OptionClasslessStaticRoute.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


class TestDhcp4OptionClasslessStaticRouteRfc3442Examples(TestCase):
    """
    The DHCPv4 Classless Static Route descriptor-encoding tests
    against the RFC 3442 examples table.
    """

    def test__dhcp4__option__classless_static_route__descriptor_examples(self) -> None:
        """
        Ensure each (subnet, mask) pair encodes to the destination
        descriptor given in the RFC 3442 examples table.

        Reference: RFC 3442 (Classless Route Option Format examples).
        """

        # (network, expected destination-descriptor bytes) from the
        # RFC 3442 "Subnet number / Subnet mask / Destination
        # descriptor" examples table.
        cases = [
            (Ip4Network("0.0.0.0/0"), b"\x00"),
            (Ip4Network("10.0.0.0/8"), b"\x08\x0a"),
            (Ip4Network("10.0.0.0/24"), b"\x18\x0a\x00\x00"),
            (Ip4Network("10.17.0.0/16"), b"\x10\x0a\x11"),
            (Ip4Network("10.27.129.0/24"), b"\x18\x0a\x1b\x81"),
            (Ip4Network("10.229.0.128/25"), b"\x19\x0a\xe5\x00\x80"),
            (Ip4Network("10.198.122.47/32"), b"\x20\x0a\xc6\x7a\x2f"),
        ]

        for network, descriptor in cases:
            with self.subTest(network=str(network)):
                option = Dhcp4OptionClasslessStaticRoute([(network, Ip4Address("0.0.0.0"))])
                # Wire layout: type, len, <descriptor>, <4-byte router>.
                emitted_descriptor = bytes(option)[2:-4]
                self.assertEqual(
                    emitted_descriptor,
                    descriptor,
                    msg=f"Descriptor encoding for {network} must match RFC 3442 table.",
                )


@parameterized_class(
    [
        {
            "_description": "Single default route.",
            "_buffer": b"\x79\x05\x00\xc0\x00\x02\x01",
            "_routes": [(Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1"))],
        },
        {
            "_description": "Single /8 route.",
            "_buffer": b"\x79\x06\x08\x0a\x0a\x00\x00\x01",
            "_routes": [(Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1"))],
        },
        {
            "_description": "Two routes (default + /8).",
            "_buffer": b"\x79\x0b\x00\xc0\x00\x02\x01\x08\x0a\x0a\x00\x00\x01",
            "_routes": [
                (Ip4Network("0.0.0.0/0"), Ip4Address("192.0.2.1")),
                (Ip4Network("10.0.0.0/8"), Ip4Address("10.0.0.1")),
            ],
        },
    ]
)
class TestDhcp4OptionClasslessStaticRouteParser(TestCase):
    """
    The DHCPv4 Classless Static Route option parser tests.
    """

    _description: str
    _buffer: bytes
    _routes: list[tuple[Ip4Network, Ip4Address]]

    def test__dhcp4__option__classless_static_route__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' decodes the compact wire encoding into
        the expected route list.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        self.assertEqual(
            Dhcp4OptionClasslessStaticRoute.from_buffer(self._buffer).routes,
            self._routes,
            msg=f"Unexpected parsed routes for case: {self._description}",
        )


class TestDhcp4OptionClasslessStaticRouteIntegrity(TestCase):
    """
    The DHCPv4 Classless Static Route option integrity tests.
    """

    def test__dhcp4__option__classless_static_route__masks_host_bits(self) -> None:
        """
        Ensure the parser zeroes the destination host bits (the
        installed subnet number is the logical AND of the supplied
        subnet number and mask).

        Reference: RFC 3442 (subnet number is the logical AND of number and mask).
        """

        # width 25, subnet 129.210.177.132, router 10.0.0.1.
        buffer = b"\x79\x09\x19\x81\xd2\xb1\x84\x0a\x00\x00\x01"

        self.assertEqual(
            Dhcp4OptionClasslessStaticRoute.from_buffer(buffer).routes[0][0],
            Ip4Network("129.210.177.128/25"),
            msg="The host bits of the destination must be zeroed (RFC 3442 AND rule).",
        )

    def test__dhcp4__option__classless_static_route__rejects_width_over_32(self) -> None:
        """
        Ensure a subnet-mask width above 32 is rejected with a typed
        integrity error.

        Reference: RFC 3442 (subnet-mask width 0-32).
        """

        # width 33 (0x21) — invalid.
        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionClasslessStaticRoute.from_buffer(b"\x79\x05\x21\x00\x00\x00\x00")

        self.assertIn(
            "subnet-mask width must be 0-32",
            str(error.exception),
            msg="A width above 32 must raise a typed integrity error.",
        )

    def test__dhcp4__option__classless_static_route__rejects_truncated_descriptor(self) -> None:
        """
        Ensure a descriptor whose significant octets + router run
        past the option data is rejected with a typed integrity error.

        Reference: RFC 3442 (Classless Route Option Format).
        """

        # width 24 needs 3 significant + 4 router = 7 data octets after
        # the width byte, but only 4 remain.
        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionClasslessStaticRoute.from_buffer(b"\x79\x05\x18\x0a\x00\x00\xc0")

        self.assertIn(
            "truncates the option data",
            str(error.exception),
            msg="A truncated descriptor must raise a typed integrity error.",
        )

    def test__dhcp4__option__classless_static_route__rejects_below_min_length(self) -> None:
        """
        Ensure an option whose length byte is below the 5-octet
        minimum is rejected with a typed integrity error.

        Reference: RFC 3442 (minimum length 5 bytes).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionClasslessStaticRoute.from_buffer(b"\x79\x04\x00\xc0\x00\x02")

        self.assertIn(
            "minimum length is 5 octets",
            str(error.exception),
            msg="A below-minimum length byte must raise a typed integrity error.",
        )


class TestDhcp4OptionClasslessStaticRouteWrongType(TestCase):
    """
    The DHCPv4 Classless Static Route option wrong-code-byte parser tests.
    """

    def test__dhcp4__option__classless_static_route__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the option code byte equals
        Dhcp4OptionType.CLASSLESS_STATIC_ROUTE and rejects a code byte below it, pinning
        the equality check against a '<=' relaxation.

        Reference: RFC 3442 (Classless Static Route option code 121).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionClasslessStaticRoute.from_buffer(b"\x00\x08\x18\x0a\x00\x00\xc0\xa8\x01\x01")

    def test__dhcp4__option__classless_static_route__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects an option code byte above
        Dhcp4OptionType.CLASSLESS_STATIC_ROUTE, pinning the equality check against a
        '>=' relaxation.

        Reference: RFC 3442 (Classless Static Route option code 121).
        """

        with self.assertRaises(AssertionError):
            Dhcp4OptionClasslessStaticRoute.from_buffer(b"\xff\x08\x18\x0a\x00\x00\xc0\xa8\x01\x01")


class TestDhcp4OptionClasslessStaticRouteHostRoute(TestCase):
    """
    The DHCPv4 Classless Static Route /32 host-route boundary tests.
    """

    def test__dhcp4__option__classless_static_route__from_buffer_prefixlen_32_accepted(self) -> None:
        """
        Ensure 'from_buffer()' accepts a /32 host route — the inclusive
        maximum prefix length — pinning the 'prefixlen > 32' rejection
        against a '>= 32' over-rejection that would reject valid host
        routes.

        Reference: RFC 3442 (subnet-mask width is 0..32 inclusive).
        """

        # Classless Static Route option, one /32 host route:
        #   Byte 0     : 0x79       -> code=CLASSLESS_STATIC_ROUTE (121)
        #   Byte 1     : 0x09       -> len=9
        #   Byte 2     : 0x20       -> prefixlen=32 (all 4 octets significant)
        #   Bytes 3-6  : 0x0a010203 -> destination 10.1.2.3
        #   Bytes 7-10 : 0xc0a80101 -> router 192.168.1.1
        decoded = Dhcp4OptionClasslessStaticRoute.from_buffer(b"\x79\x09\x20\x0a\x01\x02\x03\xc0\xa8\x01\x01")

        self.assertEqual(
            decoded.routes,
            [(Ip4Network("10.1.2.3/32"), Ip4Address("192.168.1.1"))],
            msg="A /32 host route must decode (prefixlen=32 is the inclusive maximum).",
        )
