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
Module contains tests for the ICMPv6 MLDv2 Multicast Address Record
constructor argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__multicast_address_record__asserts.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)


class TestIcmp6Mld2MulticastAddressRecordAsserts(TestCase):
    """
    The ICMPv6 MLDv2 Multicast Address Record constructor argument assert
    tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline used as the starting point for every
        negative/positive boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "type": Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
            "multicast_address": Ip6Address("ff02::1"),
            "source_addresses": [],
            "aux_data": b"",
        }

    def test__icmp6__mld2__multicast_address_record__multicast_address__not_multicast(self) -> None:
        """
        Ensure the constructor rejects a 'multicast_address' argument that
        is not a multicast IPv6 address.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self._kwargs["multicast_address"] = value = Ip6Address("2001::1")

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MulticastAddressRecord(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'multicast_address' field must be a multicast address. Got: {value!r}",
            msg="Unexpected 'multicast_address' assert message.",
        )

    def test__icmp6__mld2__multicast_address_record__source_addresses__not_unicast(self) -> None:
        """
        Ensure the constructor rejects a 'source_addresses' list containing
        any non-unicast IPv6 address.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        offender = Ip6Address("ff02::1")
        self._kwargs["source_addresses"] = [
            Ip6Address("2001::1"),
            offender,
            Ip6Address("2001::2"),
        ]

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MulticastAddressRecord(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'source_addresses' field must contain only unicast addresses. Got: {offender!r}",
            msg="Unexpected 'source_addresses' assert message.",
        )

    def test__icmp6__mld2__multicast_address_record__aux_data__not_4_byte_aligned(self) -> None:
        """
        Ensure the constructor rejects an 'aux_data' buffer whose length is
        not a multiple of 4 bytes.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        self._kwargs["aux_data"] = b"X" * 17  # 17 = 16 + 1 → not 4-byte aligned

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MulticastAddressRecord(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'aux_data' field must be 4-byte aligned. Got: 17",
            msg="Unexpected 'aux_data' assert message.",
        )

    def test__icmp6__mld2__multicast_address_record__aux_data__unaligned_lengths_rejected(self) -> None:
        """
        Ensure every non-4-byte-aligned length in 1..19 is rejected by the
        'aux_data' alignment check (negative sweep across all off-by-one
        positions within a 4-byte period).

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        for length in range(1, 20):
            if length % 4 == 0:
                continue
            with self.subTest(length=length):
                kwargs = {**self._kwargs, "aux_data": b"X" * length}
                with self.assertRaises(AssertionError) as error:
                    Icmp6Mld2MulticastAddressRecord(**kwargs)
                self.assertEqual(
                    str(error.exception),
                    f"The 'aux_data' field must be 4-byte aligned. Got: {length}",
                    msg=f"Unexpected 'aux_data' assert for length {length}.",
                )

    def test__icmp6__mld2__multicast_address_record__aux_data__aligned_lengths_accepted(self) -> None:
        """
        Ensure every 4-byte-aligned length in 0..20 is accepted by the
        'aux_data' alignment check.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        for length in (0, 4, 8, 12, 16, 20):
            with self.subTest(length=length):
                kwargs = {**self._kwargs, "aux_data": b"X" * length}
                record = Icmp6Mld2MulticastAddressRecord(**kwargs)
                self.assertEqual(
                    record.aux_data_len,
                    length,
                    msg=f"Aligned aux_data of length {length} must be accepted verbatim.",
                )

    def test__icmp6__mld2__multicast_address_record__record_types_accepted(self) -> None:
        """
        Ensure the constructor accepts every defined
        Icmp6Mld2MulticastAddressRecordType value for the 'type' field.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        for record_type in Icmp6Mld2MulticastAddressRecordType:
            with self.subTest(record_type=record_type):
                kwargs = {**self._kwargs, "type": record_type}
                record = Icmp6Mld2MulticastAddressRecord(**kwargs)
                self.assertEqual(
                    record.type,
                    record_type,
                    msg=f"'type' {record_type!r} must be preserved on the record.",
                )

    def test__icmp6__mld2__multicast_address_record__source_addresses__all_unicast_accepted(self) -> None:
        """
        Ensure the constructor accepts a 'source_addresses' list of
        unicast IPv6 addresses and preserves them in order.

        Reference: RFC 3810 §5.2.12 (Multicast Address Record).
        """

        sources = [Ip6Address("2001::1"), Ip6Address("2001::2"), Ip6Address("2001::3")]
        self._kwargs["source_addresses"] = sources

        record = Icmp6Mld2MulticastAddressRecord(**self._kwargs)

        self.assertEqual(
            record.source_addresses,
            sources,
            msg="Unicast 'source_addresses' must be preserved in order.",
        )
        self.assertEqual(
            record.number_of_sources,
            len(sources),
            msg="'number_of_sources' must match len(source_addresses).",
        )
