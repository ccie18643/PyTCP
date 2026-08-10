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
Module contains tests for the ICMPv6 MLDv2 Report message assembler
& parser constructor argument asserts.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__asserts.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    ICMP6__MLD2__REPORT__LEN,
    IP6__PAYLOAD__MAX_LEN,
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6Mld2ReportCode,
)
from net_proto.lib.int_checks import UINT_16__MAX, UINT_16__MIN


class TestIcmp6Mld2MessageReportAsserts(TestCase):
    """
    The ICMPv6 MLDv2 Report message constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline used as the starting point for every
        negative/positive boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6Mld2ReportCode.DEFAULT,
            "cksum": 0,
            "records": [],
        }

    def test__icmp6__mld2__message__report__code__not_Icmp6Mld2ReportCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument whose type is not
        Icmp6Mld2ReportCode.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self._kwargs["code"] = value = "not an Icmp6Mld2ReportCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageReport(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6Mld2ReportCode. Got: {type(value)!r}",
            msg="Unexpected 'code' assert message.",
        )

    def test__icmp6__mld2__message__report__code__default_accepted(self) -> None:
        """
        Ensure the constructor accepts the only defined Icmp6Mld2ReportCode
        value (DEFAULT).

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        for code in Icmp6Mld2ReportCode:
            with self.subTest(code=code):
                message = Icmp6Mld2MessageReport(**{**self._kwargs, "code": code})
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"'code' {code!r} must be preserved on the message.",
                )

    def test__icmp6__mld2__message__report__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the 16-bit
        unsigned minimum.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageReport(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' under-min assert message.",
        )

    def test__icmp6__mld2__message__report__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the 16-bit
        unsigned maximum.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageReport(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' over-max assert message.",
        )

    def test__icmp6__mld2__message__report__cksum__bounds_accepted(self) -> None:
        """
        Ensure the constructor accepts both endpoints of the valid 16-bit
        unsigned 'cksum' range.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        for cksum in (UINT_16__MIN, UINT_16__MAX):
            with self.subTest(cksum=cksum):
                message = Icmp6Mld2MessageReport(**{**self._kwargs, "cksum": cksum})
                self.assertEqual(
                    message.cksum,
                    cksum,
                    msg=f"Boundary 'cksum' value {cksum} must be preserved.",
                )

    def test__icmp6__mld2__message__report__records_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'records' list whose total
        on-wire length exceeds the IPv6 payload budget.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        records_len_max = IP6__PAYLOAD__MAX_LEN - ICMP6__MLD2__REPORT__LEN
        records_len = records_len_max + 1

        offender = Icmp6Mld2MulticastAddressRecord(
            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
            multicast_address=Ip6Address("ff02::1"),
            # 20 bytes = bare record header (type+aux_dlen+src_count+mcast_addr).
            aux_data=b"X" * (records_len - 20),
        )

        self._kwargs["records"] = [offender]

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageReport(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'records' field length must be less than or equal to {records_len_max}. Got: {records_len}",
            msg="Unexpected 'records' over-max assert message.",
        )

    def test__icmp6__mld2__message__report__records_len__under_max_accepted(self) -> None:
        """
        Ensure a 'records' list filled to the largest 4-byte-aligned size
        ≤ records_len_max is accepted. Every record is 4-byte aligned, so
        the true achievable ceiling is records_len_max rounded down to a
        multiple of 4.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        records_len_max = IP6__PAYLOAD__MAX_LEN - ICMP6__MLD2__REPORT__LEN
        records_len = records_len_max - (records_len_max % 4)

        record = Icmp6Mld2MulticastAddressRecord(
            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
            multicast_address=Ip6Address("ff02::1"),
            aux_data=b"X" * (records_len - 20),
        )

        message = Icmp6Mld2MessageReport(**{**self._kwargs, "records": [record]})

        self.assertEqual(
            len(message),
            ICMP6__MLD2__REPORT__LEN + records_len,
            msg="Message at the largest achievable records_len must be accepted verbatim.",
        )

    def test__icmp6__mld2__message__report__records__empty_accepted(self) -> None:
        """
        Ensure an empty 'records' list is accepted and produces a bare
        8-byte header message.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        message = Icmp6Mld2MessageReport(**self._kwargs)

        self.assertEqual(
            message.records,
            [],
            msg="Empty 'records' list must be preserved verbatim.",
        )
        self.assertEqual(
            message.number_of_records,
            0,
            msg="'number_of_records' must report 0 for an empty records list.",
        )
        self.assertEqual(
            len(message),
            ICMP6__MLD2__REPORT__LEN,
            msg="Message with no records must have the bare-header length.",
        )

    def test__icmp6__mld2__message__report__records__multiple_accepted(self) -> None:
        """
        Ensure a 'records' list with multiple entries is preserved in
        order and 'number_of_records' reflects the count.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        records = [
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                multicast_address=Ip6Address("ff02::1"),
            ),
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                multicast_address=Ip6Address("ff02::2"),
            ),
            Icmp6Mld2MulticastAddressRecord(
                type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                multicast_address=Ip6Address("ff02::3"),
            ),
        ]

        message = Icmp6Mld2MessageReport(**{**self._kwargs, "records": records})

        self.assertEqual(
            message.records,
            records,
            msg="'records' must be preserved in order.",
        )
        self.assertEqual(
            message.number_of_records,
            len(records),
            msg="'number_of_records' must match len(records).",
        )


class TestIcmp6Mld2MessageReportParserAsserts(TestCase):
    """
    The ICMPv6 MLDv2 Report message parser 'from_buffer()' assert tests.
    """

    def test__icmp6__mld2__message__report__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' rejects a buffer whose type byte is not
        Icmp6Type.MLD2__REPORT (143).

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2MessageReport.from_buffer(
                # ICMPv6 (invalid type)
                #   Type         : 255 (unknown)
                #   Code         : 0
                #   Checksum     : 0xff00
                #   Reserved     : 0x0000
                #   Record count : 0x0000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.MLD2__REPORT: 143>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected 'type' assert message from from_buffer().",
        )

    def test__icmp6__mld2__message__report__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'from_buffer()' accepts a buffer with type 143 and returns
        a message with the default code, zero checksum, and no records.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        message = Icmp6Mld2MessageReport.from_buffer(
            # ICMPv6 MLDv2 Report (no records)
            #   Type         : 143 (MLDv2 Report)
            #   Code         : 0 (Default)
            #   Checksum     : 0x0000
            #   Reserved     : 0x0000
            #   Record count : 0x0000
            b"\x8f\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertEqual(
            message.code,
            Icmp6Mld2ReportCode.DEFAULT,
            msg="'code' must parse as DEFAULT for a valid MLDv2 Report buffer.",
        )
        self.assertEqual(
            message.cksum,
            0,
            msg="'cksum' must be preserved from the buffer.",
        )
        self.assertEqual(
            message.records,
            [],
            msg="Empty record count must yield an empty 'records' list.",
        )
