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
This module contains tests for the ARP packet header fields and asserts.

net_proto/tests/unit/protocols/arp/test__arp__header__asserts.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from net_proto import (
    ARP__HEADER__LEN,
    ArpHardwareType,
    ArpHeader,
    ArpOperation,
    EtherType,
)
from net_proto.protocols.arp.arp__enums import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__PROTOCOL_LEN__IP4,
)


class TestArpHeaderAsserts(TestCase):
    """
    The ARP header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the ARP header constructor.
        """

        self._kwargs: dict[str, Any] = {
            "oper": ArpOperation.REQUEST,
            "sha": MacAddress(),
            "spa": Ip4Address(),
            "tha": MacAddress(),
            "tpa": Ip4Address(),
        }

    def test__arp__header__oper__not_ArpOperation(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'oper' argument is not an ArpOperation.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self._kwargs["oper"] = value = "not an ArpOperation"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'oper' field must be an ArpOperation. Got: {type(value)!r}",
            msg="Unexpected 'oper' assert message.",
        )

    def test__arp__header__sha__not_MacAddress(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'sha' argument is not a MacAddress.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self._kwargs["sha"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sha' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'sha' assert message.",
        )

    def test__arp__header__spa__not_Ip4Address(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'spa' argument is not an Ip4Address.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self._kwargs["spa"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'spa' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'spa' assert message.",
        )

    def test__arp__header__tha__not_MacAddress(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'tha' argument is not a MacAddress.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self._kwargs["tha"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tha' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'tha' assert message.",
        )

    def test__arp__header__tpa__not_Ip4Address(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'tpa' argument is not an Ip4Address.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self._kwargs["tpa"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'tpa' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'tpa' assert message.",
        )


class TestArpHeaderDefaults(TestCase):
    """
    The ARP header immutable default-field tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a minimal valid ARP header for inspection.
        """

        self._header = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress("01:02:03:04:05:06"),
            spa=Ip4Address("11.22.33.44"),
            tha=MacAddress("0a:0b:0c:0d:0e:0f"),
            tpa=Ip4Address("101.102.103.104"),
        )

    def test__arp__header__hrtype_default(self) -> None:
        """
        Ensure the 'hrtype' field defaults to ArpHardwareType.ETHERNET.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self.assertEqual(
            self._header.hrtype,
            ArpHardwareType.ETHERNET,
            msg="Default 'hrtype' must be ArpHardwareType.ETHERNET.",
        )

    def test__arp__header__prtype_default(self) -> None:
        """
        Ensure the 'prtype' field defaults to EtherType.IP4.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self.assertEqual(
            self._header.prtype,
            EtherType.IP4,
            msg="Default 'prtype' must be EtherType.IP4.",
        )

    def test__arp__header__hrlen_default(self) -> None:
        """
        Ensure the 'hrlen' field defaults to the Ethernet MAC length (6).

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self.assertEqual(
            self._header.hrlen,
            ARP__HARDWARE_LEN__ETHERNET,
            msg="Default 'hrlen' must match ARP__HARDWARE_LEN__ETHERNET.",
        )

    def test__arp__header__prlen_default(self) -> None:
        """
        Ensure the 'prlen' field defaults to the IPv4 address length (4).

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        self.assertEqual(
            self._header.prlen,
            ARP__PROTOCOL_LEN__IP4,
            msg="Default 'prlen' must match ARP__PROTOCOL_LEN__IP4.",
        )

    def test__arp__header__hrtype_cannot_be_overridden(self) -> None:
        """
        Ensure 'hrtype' cannot be supplied via the constructor (init=False).

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        with self.assertRaises(TypeError):
            ArpHeader(
                hrtype=ArpHardwareType.ETHERNET,  # type: ignore[call-arg]
                oper=ArpOperation.REQUEST,
                sha=MacAddress(),
                spa=Ip4Address(),
                tha=MacAddress(),
                tpa=Ip4Address(),
            )


class TestArpHeaderOperation(TestCase):
    """
    The ARP header construction, equality, and buffer-protocol tests.
    """

    def test__arp__header__request_construction(self) -> None:
        """
        Ensure a valid ARP Request header instance can be constructed and its
        fields are exposed exactly as provided.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        header = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress("01:02:03:04:05:06"),
            spa=Ip4Address("11.22.33.44"),
            tha=MacAddress("0a:0b:0c:0d:0e:0f"),
            tpa=Ip4Address("101.102.103.104"),
        )

        self.assertEqual(header.oper, ArpOperation.REQUEST, msg="Unexpected 'oper'.")
        self.assertEqual(header.sha, MacAddress("01:02:03:04:05:06"), msg="Unexpected 'sha'.")
        self.assertEqual(header.spa, Ip4Address("11.22.33.44"), msg="Unexpected 'spa'.")
        self.assertEqual(header.tha, MacAddress("0a:0b:0c:0d:0e:0f"), msg="Unexpected 'tha'.")
        self.assertEqual(header.tpa, Ip4Address("101.102.103.104"), msg="Unexpected 'tpa'.")

    def test__arp__header__reply_construction(self) -> None:
        """
        Ensure a valid ARP Reply header instance can be constructed and its
        fields are exposed exactly as provided.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        header = ArpHeader(
            oper=ArpOperation.REPLY,
            sha=MacAddress("a1:b2:c3:d4:e5:f6"),
            spa=Ip4Address("5.5.5.5"),
            tha=MacAddress("7a:7b:7c:7d:7e:7f"),
            tpa=Ip4Address("7.7.7.7"),
        )

        self.assertEqual(header.oper, ArpOperation.REPLY, msg="Unexpected 'oper'.")
        self.assertEqual(header.sha, MacAddress("a1:b2:c3:d4:e5:f6"), msg="Unexpected 'sha'.")
        self.assertEqual(header.spa, Ip4Address("5.5.5.5"), msg="Unexpected 'spa'.")
        self.assertEqual(header.tha, MacAddress("7a:7b:7c:7d:7e:7f"), msg="Unexpected 'tha'.")
        self.assertEqual(header.tpa, Ip4Address("7.7.7.7"), msg="Unexpected 'tpa'.")

    def test__arp__header__len(self) -> None:
        """
        Ensure 'len()' on the header returns the canonical 28-byte size.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        header = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress(),
            spa=Ip4Address(),
            tha=MacAddress(),
            tpa=Ip4Address(),
        )

        self.assertEqual(len(header), ARP__HEADER__LEN, msg="ARP header length must be 28 bytes.")

    def test__arp__header__buffer_protocol(self) -> None:
        """
        Ensure the ARP header buffer representation matches the wire format.

        The ARP packet [RFC 826] is laid out as:
          Hardware type : 0x0001 (Ethernet)
          Protocol type : 0x0800 (IPv4)
          HLEN / PLEN   : 6 / 4
          Operation     : 1 (Request)
          Sender MAC    : 01:02:03:04:05:06
          Sender IP     : 11.22.33.44
          Target MAC    : 0a:0b:0c:0d:0e:0f
          Target IP     : 101.102.103.104

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        header = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress("01:02:03:04:05:06"),
            spa=Ip4Address("11.22.33.44"),
            tha=MacAddress("0a:0b:0c:0d:0e:0f"),
            tpa=Ip4Address("101.102.103.104"),
        )

        self.assertEqual(
            bytes(memoryview(header)),
            (
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            msg="ARP Request wire format does not match RFC 826 layout.",
        )

    def test__arp__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent header.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        original = ArpHeader(
            oper=ArpOperation.REPLY,
            sha=MacAddress("a1:b2:c3:d4:e5:f6"),
            spa=Ip4Address("5.5.5.5"),
            tha=MacAddress("7a:7b:7c:7d:7e:7f"),
            tpa=Ip4Address("7.7.7.7"),
        )

        rebuilt = ArpHeader.from_buffer(bytes(memoryview(original)))

        self.assertEqual(rebuilt, original, msg="Roundtrip through from_buffer must preserve equality.")

    def test__arp__header__from_buffer_consumes_prefix(self) -> None:
        """
        Ensure 'from_buffer()' reads only the first ARP__HEADER__LEN bytes and
        ignores any trailing data.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        original = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress("01:02:03:04:05:06"),
            spa=Ip4Address("11.22.33.44"),
            tha=MacAddress("0a:0b:0c:0d:0e:0f"),
            tpa=Ip4Address("101.102.103.104"),
        )
        padded = bytes(memoryview(original)) + b"\xde\xad\xbe\xef"

        rebuilt = ArpHeader.from_buffer(padded)

        self.assertEqual(rebuilt, original, msg="Trailing bytes must not affect from_buffer output.")

    def test__arp__header__equality(self) -> None:
        """
        Ensure two ARP headers with identical field values compare equal.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        kwargs: dict[str, Any] = {
            "oper": ArpOperation.REQUEST,
            "sha": MacAddress("01:02:03:04:05:06"),
            "spa": Ip4Address("11.22.33.44"),
            "tha": MacAddress("0a:0b:0c:0d:0e:0f"),
            "tpa": Ip4Address("101.102.103.104"),
        }

        self.assertEqual(ArpHeader(**kwargs), ArpHeader(**kwargs), msg="Equal field sets must compare equal.")

    def test__arp__header__inequality_on_oper(self) -> None:
        """
        Ensure headers differing only in 'oper' compare unequal.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        base: dict[str, Any] = {
            "sha": MacAddress("01:02:03:04:05:06"),
            "spa": Ip4Address("11.22.33.44"),
            "tha": MacAddress("0a:0b:0c:0d:0e:0f"),
            "tpa": Ip4Address("101.102.103.104"),
        }

        self.assertNotEqual(
            ArpHeader(oper=ArpOperation.REQUEST, **base),
            ArpHeader(oper=ArpOperation.REPLY, **base),
            msg="Headers differing in 'oper' must not compare equal.",
        )

    def test__arp__header__is_hashable(self) -> None:
        """
        Ensure ARP headers can be used as keys in a set/dict.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        header = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress("01:02:03:04:05:06"),
            spa=Ip4Address("11.22.33.44"),
            tha=MacAddress("0a:0b:0c:0d:0e:0f"),
            tpa=Ip4Address("101.102.103.104"),
        )

        self.assertIn(header, {header}, msg="ARP header must be hashable.")

    def test__arp__header__is_frozen(self) -> None:
        """
        Ensure ARP header fields cannot be mutated after construction.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        header = ArpHeader(
            oper=ArpOperation.REQUEST,
            sha=MacAddress(),
            spa=Ip4Address(),
            tha=MacAddress(),
            tpa=Ip4Address(),
        )

        with self.assertRaises(FrozenInstanceError):
            header.oper = ArpOperation.REPLY  # type: ignore[misc]

    def test__arp__header__rejects_positional_args(self) -> None:
        """
        Ensure the ARP header constructor rejects positional arguments.

        Reference: RFC 826 (ARP header fields — hrtype, prtype, hrlen, prlen, oper, sha, spa, tha, tpa).
        """

        with self.assertRaises(TypeError):
            ArpHeader(  # type: ignore[call-arg]
                ArpOperation.REQUEST,
                MacAddress(),
                Ip4Address(),
                MacAddress(),
                Ip4Address(),
            )
