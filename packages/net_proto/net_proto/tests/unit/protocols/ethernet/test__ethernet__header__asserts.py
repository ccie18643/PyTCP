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
This module contains tests for the Ethernet II header fields and asserts.

net_proto/tests/unit/protocols/ethernet/test__ethernet__header__asserts.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import EthernetHeader, EtherType
from net_proto.protocols.ethernet.ethernet__header import (
    ETHERNET__HEADER__LEN,
    ETHERNET__HEADER__STRUCT,
    EthernetHeaderProperties,
)


class TestEthernetHeaderAsserts(TestCase):
    """
    The Ethernet header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the Ethernet header constructor.
        """

        self._kwargs: dict[str, Any] = {
            "dst": MacAddress(),
            "src": MacAddress(),
            "type": EtherType.RAW,
        }

    def test__ethernet__header__dst__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet header constructor raises an exception when the
        provided 'dst' argument is not a MacAddress.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self._kwargs["dst"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            EthernetHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'dst' type assert message.",
        )

    def test__ethernet__header__src__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet header constructor raises an exception when the
        provided 'src' argument is not a MacAddress.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self._kwargs["src"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            EthernetHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'src' type assert message.",
        )

    def test__ethernet__header__type__not_EtherType(self) -> None:
        """
        Ensure the Ethernet header constructor raises an exception when the
        provided 'type' argument is not an EtherType.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self._kwargs["type"] = value = "not an EtherType"

        with self.assertRaises(AssertionError) as error:
            EthernetHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an EtherType. Got: {type(value)!r}",
            msg="Unexpected 'type' type assert message.",
        )


class TestEthernetHeaderConstants(TestCase):
    """
    The Ethernet header module-level constants tests.
    """

    def test__ethernet__header__len_constant(self) -> None:
        """
        Ensure the ETHERNET__HEADER__LEN constant equals 14 bytes (the wire
        length of a DIX/Ethernet II header: 6+6+2).

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self.assertEqual(
            ETHERNET__HEADER__LEN,
            14,
            msg="ETHERNET__HEADER__LEN must be 14 bytes (dst + src + type).",
        )

    def test__ethernet__header__struct_constant(self) -> None:
        """
        Ensure the ETHERNET__HEADER__STRUCT format string describes a big-endian
        layout of two 6-byte fields followed by a 16-bit word.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self.assertEqual(
            ETHERNET__HEADER__STRUCT,
            "! 6s 6s H",
            msg="Unexpected ETHERNET__HEADER__STRUCT format string.",
        )


class TestEthernetHeaderOperation(TestCase):
    """
    The Ethernet header construction, equality, and buffer-protocol tests.
    """

    def _valid_kwargs(self) -> dict[str, Any]:
        """
        Return a reference set of valid Ethernet header constructor kwargs.
        """

        return {
            "dst": MacAddress("11:22:33:44:55:66"),
            "src": MacAddress("78:89:9a:ab:bc:cd"),
            "type": EtherType.IP4,
        }

    def test__ethernet__header__construction(self) -> None:
        """
        Ensure a valid Ethernet header instance can be constructed and its
        fields are exposed exactly as provided.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        kwargs = self._valid_kwargs()

        header = EthernetHeader(**kwargs)

        self.assertEqual(header.dst, kwargs["dst"], msg="Unexpected 'dst'.")
        self.assertEqual(header.src, kwargs["src"], msg="Unexpected 'src'.")
        self.assertEqual(header.type, kwargs["type"], msg="Unexpected 'type'.")

    def test__ethernet__header__len(self) -> None:
        """
        Ensure 'len()' on the header returns the canonical 14-byte size.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        header = EthernetHeader(**self._valid_kwargs())

        self.assertEqual(
            len(header),
            ETHERNET__HEADER__LEN,
            msg="Ethernet header length must be 14 bytes.",
        )

    def test__ethernet__header__buffer_protocol(self) -> None:
        """
        Ensure the Ethernet header buffer representation matches the wire
        format [DIX] exactly.

        Expected layout:
          Destination MAC : 11:22:33:44:55:66
          Source MAC      : 78:89:9a:ab:bc:cd
          Ethertype       : 0x0800 (IPv4)

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        header = EthernetHeader(**self._valid_kwargs())

        frame = bytes(memoryview(header))

        self.assertEqual(
            frame,
            # Ethernet II
            #   Destination MAC : 11:22:33:44:55:66
            #   Source MAC      : 78:89:9a:ab:bc:cd
            #   Ethertype       : 0x0800 (IPv4)
            b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x08\x00",
            msg="Unexpected Ethernet header wire bytes.",
        )

    def test__ethernet__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent header.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        original = EthernetHeader(**self._valid_kwargs())

        rebuilt = EthernetHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )

    def test__ethernet__header__from_buffer_consumes_prefix(self) -> None:
        """
        Ensure 'from_buffer()' reads only the first ETHERNET__HEADER__LEN
        bytes and ignores any trailing data.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        original = EthernetHeader(**self._valid_kwargs())
        padded = bytes(memoryview(original)) + b"\xde\xad\xbe\xef"

        rebuilt = EthernetHeader.from_buffer(padded)

        self.assertEqual(
            rebuilt,
            original,
            msg="Trailing bytes must not affect from_buffer output.",
        )

    def test__ethernet__header__from_buffer_accepts_unknown_ethertype(self) -> None:
        """
        Ensure 'from_buffer()' accepts an unknown EtherType value by extending
        the enum via 'EtherType.from_int()' rather than rejecting the frame.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        frame = (
            # Ethernet II
            #   Destination MAC : 11:22:33:44:55:66
            #   Source MAC      : 78:89:9a:ab:bc:cd
            #   Ethertype       : 0x9999 (UNKNOWN)
            b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x99\x99"
        )

        header = EthernetHeader.from_buffer(frame)

        self.assertEqual(int(header.type), 0x9999, msg="Unknown EtherType must round-trip as its integer value.")
        self.assertTrue(header.type.is_unknown, msg="0x9999 must be flagged as an unknown EtherType.")

    def test__ethernet__header__equality(self) -> None:
        """
        Ensure two Ethernet headers with identical field values compare equal.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        kwargs = self._valid_kwargs()

        self.assertEqual(
            EthernetHeader(**kwargs),
            EthernetHeader(**kwargs),
            msg="Equal field sets must compare equal.",
        )

    def test__ethernet__header__inequality_on_type(self) -> None:
        """
        Ensure headers differing only in 'type' compare unequal.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        base = self._valid_kwargs()
        base.pop("type")

        self.assertNotEqual(
            EthernetHeader(type=EtherType.IP4, **base),
            EthernetHeader(type=EtherType.IP6, **base),
            msg="Headers differing in 'type' must not compare equal.",
        )

    def test__ethernet__header__is_hashable(self) -> None:
        """
        Ensure Ethernet headers can be used as keys in a set/dict.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        header = EthernetHeader(**self._valid_kwargs())

        self.assertIn(header, {header}, msg="Ethernet header must be hashable.")

    def test__ethernet__header__is_frozen(self) -> None:
        """
        Ensure Ethernet header fields cannot be mutated after construction.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        header = EthernetHeader(**self._valid_kwargs())

        with self.assertRaises(FrozenInstanceError):
            header.type = EtherType.ARP  # type: ignore[misc]

    def test__ethernet__header__rejects_positional_args(self) -> None:
        """
        Ensure the Ethernet header constructor rejects positional arguments.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        with self.assertRaises(TypeError):
            EthernetHeader(  # type: ignore[call-arg]
                MacAddress(),
                MacAddress(),
                EtherType.RAW,
            )


class _EthernetHeaderPropertiesHost(EthernetHeaderProperties):
    """
    Minimal concrete host exposing EthernetHeaderProperties accessors.
    """

    def __init__(self, *, header: EthernetHeader) -> None:
        """
        Store the provided Ethernet header on the required '_header' slot.
        """

        self._header = header


class TestEthernetHeaderProperties(TestCase):
    """
    The EthernetHeaderProperties mixin accessors and setters tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh host with a known-good Ethernet header per test case.
        """

        self._header = EthernetHeader(
            dst=MacAddress("11:22:33:44:55:66"),
            src=MacAddress("78:89:9a:ab:bc:cd"),
            type=EtherType.IP4,
        )
        self._host = _EthernetHeaderPropertiesHost(header=self._header)

    def test__ethernet__header__properties__dst_getter(self) -> None:
        """
        Ensure the 'dst' property returns the underlying header's 'dst' field.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self.assertEqual(
            self._host.dst,
            MacAddress("11:22:33:44:55:66"),
            msg="'dst' property must reflect the header's 'dst' field.",
        )

    def test__ethernet__header__properties__src_getter(self) -> None:
        """
        Ensure the 'src' property returns the underlying header's 'src' field.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self.assertEqual(
            self._host.src,
            MacAddress("78:89:9a:ab:bc:cd"),
            msg="'src' property must reflect the header's 'src' field.",
        )

    def test__ethernet__header__properties__type_getter(self) -> None:
        """
        Ensure the 'type' property returns the underlying header's 'type'
        field.

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        self.assertEqual(
            self._host.type,
            EtherType.IP4,
            msg="'type' property must reflect the header's 'type' field.",
        )

    def test__ethernet__header__properties__dst_setter_bypasses_frozen(self) -> None:
        """
        Ensure the 'dst' setter mutates the frozen header via the documented
        'object.__setattr__' bypass (used by TX packet handlers when filling in
        the destination MAC after ARP resolution).

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        new_dst = MacAddress("aa:bb:cc:dd:ee:ff")
        self._host.dst = new_dst

        self.assertEqual(
            self._header.dst,
            new_dst,
            msg="'dst' setter must update the underlying header's 'dst' field.",
        )
        self.assertEqual(
            self._host.dst,
            new_dst,
            msg="'dst' property must return the updated value after the setter runs.",
        )

    def test__ethernet__header__properties__src_setter_bypasses_frozen(self) -> None:
        """
        Ensure the 'src' setter mutates the frozen header via the documented
        'object.__setattr__' bypass (used by TX packet handlers when filling in
        the source MAC from the selected egress interface).

        Reference: RFC 894 (Ethernet II header — dst, src, EtherType).
        """

        new_src = MacAddress("de:ad:be:ef:00:01")
        self._host.src = new_src

        self.assertEqual(
            self._header.src,
            new_src,
            msg="'src' setter must update the underlying header's 'src' field.",
        )
        self.assertEqual(
            self._host.src,
            new_src,
            msg="'src' property must return the updated value after the setter runs.",
        )
