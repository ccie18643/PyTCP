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
This module contains the NetAddr error-hierarchy tests.

net_addr/tests/unit/test__errors.py

ver 3.0.9
"""

from unittest import TestCase

from net_addr import (
    IfAddrError,
    IfAddrFormatError,
    IfAddrSanityError,
    Ip4AddressError,
    Ip4AddressFormatError,
    Ip4AddressSanityError,
    Ip4IfAddrError,
    Ip4IfAddrFormatError,
    Ip4IfAddrSanityError,
    Ip4MaskError,
    Ip4MaskFormatError,
    Ip4NetworkError,
    Ip4NetworkFormatError,
    Ip4NetworkSanityError,
    Ip4WildcardError,
    Ip4WildcardFormatError,
    Ip6AddressError,
    Ip6AddressFormatError,
    Ip6AddressSanityError,
    Ip6IfAddrError,
    Ip6IfAddrFormatError,
    Ip6IfAddrSanityError,
    Ip6MaskError,
    Ip6MaskFormatError,
    Ip6NetworkError,
    Ip6NetworkFormatError,
    Ip6NetworkSanityError,
    Ip6WildcardError,
    Ip6WildcardFormatError,
    IpAddressError,
    IpAddressFormatError,
    IpAddressSanityError,
    IpMaskError,
    IpMaskFormatError,
    IpNetworkError,
    IpNetworkFormatError,
    IpNetworkSanityError,
    IpWildcardError,
    IpWildcardFormatError,
    MacAddressError,
    MacAddressFormatError,
    MacAddressSanityError,
    NetAddrError,
)

# (leaf, axis base, per-type umbrella, concept umbrella) for
# every concrete net_addr error. The axis base is the
# version-agnostic Format / Sanity grouping; the per-type
# umbrella is the MAC-parallel "any error of this concrete
# type"; the concept umbrella is "any error of this value-type
# concept, any version, any axis".
_HIERARCHY: list[tuple[type[NetAddrError], type[NetAddrError], type[NetAddrError], type[NetAddrError]]] = [
    (Ip4AddressFormatError, IpAddressFormatError, Ip4AddressError, IpAddressError),
    (Ip4AddressSanityError, IpAddressSanityError, Ip4AddressError, IpAddressError),
    (Ip6AddressFormatError, IpAddressFormatError, Ip6AddressError, IpAddressError),
    (Ip6AddressSanityError, IpAddressSanityError, Ip6AddressError, IpAddressError),
    (Ip4MaskFormatError, IpMaskFormatError, Ip4MaskError, IpMaskError),
    (Ip6MaskFormatError, IpMaskFormatError, Ip6MaskError, IpMaskError),
    (Ip4WildcardFormatError, IpWildcardFormatError, Ip4WildcardError, IpWildcardError),
    (Ip6WildcardFormatError, IpWildcardFormatError, Ip6WildcardError, IpWildcardError),
    (Ip4NetworkFormatError, IpNetworkFormatError, Ip4NetworkError, IpNetworkError),
    (Ip4NetworkSanityError, IpNetworkSanityError, Ip4NetworkError, IpNetworkError),
    (Ip6NetworkFormatError, IpNetworkFormatError, Ip6NetworkError, IpNetworkError),
    (Ip6NetworkSanityError, IpNetworkSanityError, Ip6NetworkError, IpNetworkError),
    (Ip4IfAddrFormatError, IfAddrFormatError, Ip4IfAddrError, IfAddrError),
    (Ip4IfAddrSanityError, IfAddrSanityError, Ip4IfAddrError, IfAddrError),
    (Ip6IfAddrFormatError, IfAddrFormatError, Ip6IfAddrError, IfAddrError),
    (Ip6IfAddrSanityError, IfAddrSanityError, Ip6IfAddrError, IfAddrError),
]


class TestNetAddrErrorHierarchy(TestCase):
    """
    The NetAddr error-hierarchy relationship tests.
    """

    def test__net_addr__errors__leaf_subclass_relations(self) -> None:
        """
        Ensure every concrete error is a subclass of its axis
        base, its per-type umbrella, its concept umbrella, and
        the NetAddrError root, so each grouping level is
        catchable.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for leaf, axis, per_type, concept in _HIERARCHY:
            with self.subTest(leaf=leaf.__name__):
                for ancestor in (axis, per_type, concept, NetAddrError):
                    self.assertTrue(
                        issubclass(leaf, ancestor),
                        msg=f"{leaf.__name__} must be a subclass of {ancestor.__name__}.",
                    )

    def test__net_addr__errors__per_type_umbrella_catches_both_axes(self) -> None:
        """
        Ensure a per-type umbrella catches both the Format and
        the Sanity leaf of that concrete type (the MAC-parallel
        grouping), and does not catch the sibling version's
        errors.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(Ip4AddressError):
            raise Ip4AddressFormatError("bad")
        with self.assertRaises(Ip4AddressError):
            raise Ip4AddressSanityError("bad")

        with self.assertRaises(NetAddrError) as ctx:
            raise Ip6AddressFormatError("bad")
        self.assertNotIsInstance(
            ctx.exception,
            Ip4AddressError,
            msg="An IPv6 address error must not be caught by the IPv4 umbrella.",
        )

    def test__net_addr__errors__axis_base_still_catches_both_versions(self) -> None:
        """
        Ensure the version-agnostic axis base still catches the
        IPv4 and IPv6 leaves of that axis and not the other
        axis (the pre-existing grouping is preserved via
        multiple inheritance).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpAddressFormatError):
            raise Ip4AddressFormatError("bad")
        with self.assertRaises(IpAddressFormatError):
            raise Ip6AddressFormatError("bad")

        with self.assertRaises(NetAddrError) as ctx:
            raise Ip4AddressSanityError("bad")
        self.assertNotIsInstance(
            ctx.exception,
            IpAddressFormatError,
            msg="A Sanity error must not be caught by the Format axis base.",
        )

    def test__net_addr__errors__concept_umbrella_catches_any_version_or_axis(self) -> None:
        """
        Ensure the concept umbrella catches every version and
        axis of that value-type concept and nothing from a
        different concept.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for leaf in (
            Ip4AddressFormatError,
            Ip4AddressSanityError,
            Ip6AddressFormatError,
            Ip6AddressSanityError,
        ):
            with self.subTest(leaf=leaf.__name__):
                with self.assertRaises(IpAddressError):
                    raise leaf("bad")

        with self.assertRaises(NetAddrError) as ctx:
            raise Ip4NetworkFormatError("bad")
        self.assertNotIsInstance(
            ctx.exception,
            IpAddressError,
            msg="A network error must not be caught by the address concept umbrella.",
        )

    def test__net_addr__errors__mac_hierarchy_unchanged(self) -> None:
        """
        Ensure the MAC error family keeps its single per-type
        umbrella joining both axes, unaffected by the IP
        restructuring.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for leaf in (MacAddressFormatError, MacAddressSanityError):
            with self.subTest(leaf=leaf.__name__):
                self.assertTrue(
                    issubclass(leaf, MacAddressError),
                    msg=f"{leaf.__name__} must remain under MacAddressError.",
                )
                with self.assertRaises(MacAddressError):
                    raise leaf("bad")

    def test__net_addr__errors__format_messages_preserved(self) -> None:
        """
        Ensure the restructuring does not change the rendered
        message of any Format error (the multiple-inheritance
        umbrellas are transparent in the MRO).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for error_type, expected in [
            (Ip4AddressFormatError, "The IPv4 address format is invalid: 'x'"),
            (Ip6AddressFormatError, "The IPv6 address format is invalid: 'x'"),
            (Ip4MaskFormatError, "The IPv4 mask format is invalid: 'x'"),
            (Ip6MaskFormatError, "The IPv6 mask format is invalid: 'x'"),
            (Ip4WildcardFormatError, "The IPv4 wildcard format is invalid: 'x'"),
            (Ip6WildcardFormatError, "The IPv6 wildcard format is invalid: 'x'"),
            (Ip4NetworkFormatError, "The IPv4 network format is invalid: 'x'"),
            (Ip6NetworkFormatError, "The IPv6 network format is invalid: 'x'"),
            (Ip4IfAddrFormatError, "The IPv4 interface address format is invalid: 'x'"),
            (Ip6IfAddrFormatError, "The IPv6 interface address format is invalid: 'x'"),
            (MacAddressFormatError, "The MAC address format is invalid: 'x'"),
        ]:
            with self.subTest(error_type=error_type.__name__):
                self.assertEqual(
                    str(error_type("x")),
                    expected,
                    msg=f"{error_type.__name__} message must be unchanged by the umbrella restructuring.",
                )
