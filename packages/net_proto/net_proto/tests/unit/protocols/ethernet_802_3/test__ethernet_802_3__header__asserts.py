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
This module contains tests for the Ethernet 802.3 header fields and asserts.

net_proto/tests/unit/protocols/ethernet_802_3/test__ethernet_802_3__header__asserts.py

ver 3.0.10
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import MacAddress
from net_proto import (
    ETHERNET_802_3__HEADER__LEN,
    ETHERNET_802_3__PACKET__MAX_LEN,
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    UINT_16__MIN,
    Ethernet8023Header,
)
from net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__STRUCT,
    Ethernet8023HeaderProperties,
)


class TestEthernet8023HeaderAsserts(TestCase):
    """
    The Ethernet 802.3 header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the Ethernet 802.3 header constructor.
        """

        self._kwargs: dict[str, Any] = {
            "dst": MacAddress(),
            "src": MacAddress(),
            "dlen": 0,
        }

    def test__ethernet_802_3__header__dst__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when
        the provided 'dst' argument is not a MacAddress.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self._kwargs["dst"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'dst' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'dst' type assert message.",
        )

    def test__ethernet_802_3__header__src__not_MacAddress(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when
        the provided 'src' argument is not a MacAddress.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self._kwargs["src"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'src' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'src' type assert message.",
        )

    def test__ethernet_802_3__header__dlen__under_min(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when
        the provided 'dlen' argument is lower than the minimum supported value.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self._kwargs["dlen"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'dlen' field must be a 16-bit unsigned integer lower than "
            f"or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. Got: {value!r}",
            msg="Unexpected 'dlen' lower-bound assert message.",
        )

    def test__ethernet_802_3__header__dlen__over_max(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor raises an exception when
        the provided 'dlen' argument is higher than the maximum supported
        value (the 802.3 payload ceiling of 1500 bytes).

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self._kwargs["dlen"] = value = ETHERNET_802_3__PAYLOAD__MAX_LEN + 1

        with self.assertRaises(AssertionError) as error:
            Ethernet8023Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'dlen' field must be a 16-bit unsigned integer lower than "
            f"or equal to {ETHERNET_802_3__PAYLOAD__MAX_LEN}. Got: {value!r}",
            msg="Unexpected 'dlen' upper-bound assert message.",
        )


class TestEthernet8023HeaderConstants(TestCase):
    """
    The Ethernet 802.3 header module-level constants tests.
    """

    def test__ethernet_802_3__header__len_constant(self) -> None:
        """
        Ensure the ETHERNET_802_3__HEADER__LEN constant equals 14 bytes (the
        wire length of an IEEE 802.3 MAC header: 6 + 6 + 2).

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            ETHERNET_802_3__HEADER__LEN,
            14,
            msg="ETHERNET_802_3__HEADER__LEN must be 14 bytes (dst + src + dlen).",
        )

    def test__ethernet_802_3__header__struct_constant(self) -> None:
        """
        Ensure the ETHERNET_802_3__HEADER__STRUCT format string describes a
        big-endian layout of two 6-byte fields followed by a 16-bit word.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            ETHERNET_802_3__HEADER__STRUCT,
            "! 6s 6s H",
            msg="Unexpected ETHERNET_802_3__HEADER__STRUCT format string.",
        )

    def test__ethernet_802_3__packet__max_len_constant(self) -> None:
        """
        Ensure the ETHERNET_802_3__PACKET__MAX_LEN constant equals the IEEE
        802.3 MTU of 1514 bytes (header + maximum 1500-byte payload).

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            ETHERNET_802_3__PACKET__MAX_LEN,
            1514,
            msg="ETHERNET_802_3__PACKET__MAX_LEN must be 1514 bytes.",
        )

    def test__ethernet_802_3__payload__max_len_constant(self) -> None:
        """
        Ensure ETHERNET_802_3__PAYLOAD__MAX_LEN equals the packet maximum
        length minus the fixed 14-byte header.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            ETHERNET_802_3__PAYLOAD__MAX_LEN,
            ETHERNET_802_3__PACKET__MAX_LEN - ETHERNET_802_3__HEADER__LEN,
            msg="ETHERNET_802_3__PAYLOAD__MAX_LEN must be packet max minus header length.",
        )


class TestEthernet8023HeaderOperation(TestCase):
    """
    The Ethernet 802.3 header construction, equality, and buffer-protocol tests.
    """

    def _valid_kwargs(self) -> dict[str, Any]:
        """
        Return a reference set of valid Ethernet 802.3 header constructor kwargs.
        """

        return {
            "dst": MacAddress("11:22:33:44:55:66"),
            "src": MacAddress("78:89:9a:ab:bc:cd"),
            "dlen": 16,
        }

    def test__ethernet_802_3__header__construction(self) -> None:
        """
        Ensure a valid Ethernet 802.3 header instance can be constructed and
        its fields are exposed exactly as provided.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        kwargs = self._valid_kwargs()

        header = Ethernet8023Header(**kwargs)

        self.assertEqual(header.dst, kwargs["dst"], msg="Unexpected 'dst'.")
        self.assertEqual(header.src, kwargs["src"], msg="Unexpected 'src'.")
        self.assertEqual(header.dlen, kwargs["dlen"], msg="Unexpected 'dlen'.")

    def test__ethernet_802_3__header__len(self) -> None:
        """
        Ensure 'len()' on the header returns the canonical 14-byte size.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        header = Ethernet8023Header(**self._valid_kwargs())

        self.assertEqual(
            len(header),
            ETHERNET_802_3__HEADER__LEN,
            msg="Ethernet 802.3 header length must be 14 bytes.",
        )

    def test__ethernet_802_3__header__buffer_protocol(self) -> None:
        """
        Ensure the Ethernet 802.3 header buffer representation matches the
        wire format [IEEE] exactly.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        header = Ethernet8023Header(**self._valid_kwargs())

        frame = bytes(memoryview(header))

        self.assertEqual(
            frame,
            # Ethernet 802.3
            #   Destination MAC : 11:22:33:44:55:66
            #   Source MAC      : 78:89:9a:ab:bc:cd
            #   Length          : 0x0010 (16 bytes)
            b"\x11\x22\x33\x44\x55\x66\x78\x89\x9a\xab\xbc\xcd\x00\x10",
            msg="Unexpected Ethernet 802.3 header wire bytes.",
        )

    def test__ethernet_802_3__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent header.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        original = Ethernet8023Header(**self._valid_kwargs())

        rebuilt = Ethernet8023Header.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )

    def test__ethernet_802_3__header__from_buffer_consumes_prefix(self) -> None:
        """
        Ensure 'from_buffer()' reads only the first ETHERNET_802_3__HEADER__LEN
        bytes and ignores any trailing data.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        original = Ethernet8023Header(**self._valid_kwargs())
        padded = bytes(memoryview(original)) + b"\xde\xad\xbe\xef"

        rebuilt = Ethernet8023Header.from_buffer(padded)

        self.assertEqual(
            rebuilt,
            original,
            msg="Trailing bytes must not affect from_buffer output.",
        )

    def test__ethernet_802_3__header__from_buffer_at_max_dlen(self) -> None:
        """
        Ensure 'from_buffer()' accepts the maximum allowed 'dlen' value of
        1500 and exposes it verbatim on the reconstructed header.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        frame = (
            # Ethernet 802.3
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 12:13:14:15:16:17
            #   Length          : 0x05dc (1500 bytes)
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x12\x13\x14\x15\x16\x17\x05\xdc"
        )

        header = Ethernet8023Header.from_buffer(frame)

        self.assertEqual(
            header.dlen,
            ETHERNET_802_3__PAYLOAD__MAX_LEN,
            msg="'dlen' at maximum must round-trip as 1500.",
        )

    def test__ethernet_802_3__header__equality(self) -> None:
        """
        Ensure two Ethernet 802.3 headers with identical field values compare
        equal.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        kwargs = self._valid_kwargs()

        self.assertEqual(
            Ethernet8023Header(**kwargs),
            Ethernet8023Header(**kwargs),
            msg="Equal field sets must compare equal.",
        )

    def test__ethernet_802_3__header__inequality_on_dlen(self) -> None:
        """
        Ensure headers differing only in 'dlen' compare unequal.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        base = self._valid_kwargs()
        base.pop("dlen")

        self.assertNotEqual(
            Ethernet8023Header(dlen=16, **base),
            Ethernet8023Header(dlen=32, **base),
            msg="Headers differing in 'dlen' must not compare equal.",
        )

    def test__ethernet_802_3__header__is_hashable(self) -> None:
        """
        Ensure Ethernet 802.3 headers can be used as keys in a set/dict.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        header = Ethernet8023Header(**self._valid_kwargs())

        self.assertIn(header, {header}, msg="Ethernet 802.3 header must be hashable.")

    def test__ethernet_802_3__header__is_frozen(self) -> None:
        """
        Ensure Ethernet 802.3 header fields cannot be mutated after
        construction.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        header = Ethernet8023Header(**self._valid_kwargs())

        with self.assertRaises(FrozenInstanceError):
            header.dlen = 32  # type: ignore[misc]

    def test__ethernet_802_3__header__rejects_positional_args(self) -> None:
        """
        Ensure the Ethernet 802.3 header constructor rejects positional
        arguments.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        with self.assertRaises(TypeError):
            Ethernet8023Header(  # type: ignore[call-arg]
                MacAddress(),
                MacAddress(),
                0,
            )


class _Ethernet8023HeaderPropertiesHost(Ethernet8023HeaderProperties):
    """
    Minimal concrete host exposing Ethernet8023HeaderProperties accessors.
    """

    def __init__(self, *, header: Ethernet8023Header) -> None:
        """
        Store the provided Ethernet 802.3 header on the required '_header' slot.
        """

        self._header = header


class TestEthernet8023HeaderProperties(TestCase):
    """
    The Ethernet8023HeaderProperties mixin accessors and setters tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh host with a known-good Ethernet 802.3 header per test case.
        """

        self._header = Ethernet8023Header(
            dst=MacAddress("11:22:33:44:55:66"),
            src=MacAddress("78:89:9a:ab:bc:cd"),
            dlen=16,
        )
        self._host = _Ethernet8023HeaderPropertiesHost(header=self._header)

    def test__ethernet_802_3__header__properties__dst_getter(self) -> None:
        """
        Ensure the 'dst' property returns the underlying header's 'dst' field.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            self._host.dst,
            MacAddress("11:22:33:44:55:66"),
            msg="'dst' property must reflect the header's 'dst' field.",
        )

    def test__ethernet_802_3__header__properties__src_getter(self) -> None:
        """
        Ensure the 'src' property returns the underlying header's 'src' field.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            self._host.src,
            MacAddress("78:89:9a:ab:bc:cd"),
            msg="'src' property must reflect the header's 'src' field.",
        )

    def test__ethernet_802_3__header__properties__dlen_getter(self) -> None:
        """
        Ensure the 'dlen' property returns the underlying header's 'dlen'
        field.

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
        """

        self.assertEqual(
            self._host.dlen,
            16,
            msg="'dlen' property must reflect the header's 'dlen' field.",
        )

    def test__ethernet_802_3__header__properties__dst_setter_bypasses_frozen(self) -> None:
        """
        Ensure the 'dst' setter mutates the frozen header via the documented
        'object.__setattr__' bypass (used by TX packet handlers when filling
        in the destination MAC after ARP resolution).

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
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

    def test__ethernet_802_3__header__properties__src_setter_bypasses_frozen(self) -> None:
        """
        Ensure the 'src' setter mutates the frozen header via the documented
        'object.__setattr__' bypass (used by TX packet handlers when filling
        in the source MAC from the selected egress interface).

        Reference: IEEE 802.3 §3 (802.3 MAC header — dst, src, length).
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
