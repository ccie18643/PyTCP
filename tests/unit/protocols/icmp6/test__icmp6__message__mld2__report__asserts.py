#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains tests for the ICMPv6 MLDv2 Report message assembler & parser
arguments.

tests/unit/protocols/icmp6/test__icmp6__message__echo_reply__asserts.py

ver 3.0.0
"""

from testslide import TestCase

from pytcp.lib.int_checks import UINT_16__MAX, UINT_16__MIN
from pytcp.lib.ip6_address import Ip6Address
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    ICMP6__MLD2__REPORT__LEN,
    Icmp6Mld2ReportCode,
    Icmp6Mld2ReportMessage,
)
from pytcp.protocols.ip6.ip6__header import IP6__PAYLOAD__MAX_LEN


class TestIcmp6MessageMld2ReportAsserts(TestCase):
    """
    The ICMPv6 MLDv2 Report message assembler & parser constructor
    argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv6 MLDv2 Report message
        constructor.
        """

        self._message_args = {
            "code": Icmp6Mld2ReportCode.DEFAULT,
            "cksum": 0,
            "records": [],
        }

    def test__icmp6__message__mld2_report__code__not_Icmp6Mld2ReportCode(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message constructor raises an exception
        when the provided 'code' argument is not an Icmp6EchoRequestCode.
        """

        self._message_args["code"] = value = "not an Icmp6Mld2ReportCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2ReportMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6Mld2ReportCode. Got: {type(value)!r}",
        )

    def test__icmp6__message__mld2__report__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than the
        minimum supported value.
        """

        self._message_args["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2ReportMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp6__message__mld2__report__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than the
        maximum supported value.
        """

        self._message_args["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2ReportMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
        )

    def test__icmp6__message__mld2__report__records_len__over_max(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message assembler constructor raises
        an exception when the length of the provided 'records' argument is
        higher than the maximum supported value.
        """

        records_len_max = IP6__PAYLOAD__MAX_LEN - ICMP6__MLD2__REPORT__LEN
        records_len = records_len_max + 1

        multicast_address_report = Icmp6Mld2MulticastAddressRecord(
            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
            multicast_address=Ip6Address("ff02::1"),
            aux_data=b"X"
            * (
                records_len
                - 20  # 20 is the length of the record except aux_data.
            ),
        )

        self._message_args["records"] = [multicast_address_report]

        with self.assertRaises(AssertionError) as error:
            Icmp6Mld2ReportMessage(**self._message_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'records' field length must be less than or equal to {records_len_max}. "
            f"Got: {records_len}",
        )
