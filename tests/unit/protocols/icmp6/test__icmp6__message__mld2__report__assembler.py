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
This module contains tests for the ICMPv6 MLDv2 Report message assembler.

tests/unit/protocols/icmp6/test__icmp6__message__mld2__report__assembler.py

ver 3.0.0
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Type
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    Icmp6Mld2ReportCode,
    Icmp6Mld2ReportMessage,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Report message, no records.",
            "_args": {
                "cksum": 12345,
                "records": [],
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 MLDv2 Report",
                "__repr__": (
                    "Icmp6Mld2ReportMessage(code=<Icmp6Mld2ReportCode.DEFAULT: 0>, "
                    "cksum=12345, records=[])"
                ),
                "__bytes__": b"\x8f\x00\x00\x00\x00\x00\x00\x00",
                "type": Icmp6Type.MLD2__REPORT,
                "code": Icmp6Mld2ReportCode.DEFAULT,
                "cksum": 12345,
                "number_of_records": 0,
                "records": [],
            },
        },
        {
            "_description": ("ICMPv6 MLDv2 Report message, single record."),
            "_args": {
                "cksum": 12345,
                "records": [
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::1"),
                        source_addresses=[
                            Ip6Address("2001:db8::1"),
                            Ip6Address("2001:db8::2"),
                        ],
                    ),
                ],
            },
            "_results": {
                "__len__": 60,
                "__str__": (
                    "ICMPv6 MLDv2 Report, records "
                    "[type 'Mode Is Include', addr ff02::1, sources (2001:db8::1, 2001:db8::2)]"
                ),
                "__repr__": (
                    "Icmp6Mld2ReportMessage(code=<Icmp6Mld2ReportCode.DEFAULT: 0>, "
                    "cksum=12345, records=[Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[Ip6Address('2001:db8::1'), "
                    "Ip6Address('2001:db8::2')], aux_data=b'')])"
                ),
                "__bytes__": (
                    b"\x8f\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                ),
                "type": Icmp6Type.MLD2__REPORT,
                "code": Icmp6Mld2ReportCode.DEFAULT,
                "cksum": 12345,
                "number_of_records": 1,
                "records": [
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::1"),
                        source_addresses=[
                            Ip6Address("2001:db8::1"),
                            Ip6Address("2001:db8::2"),
                        ],
                        aux_data=b"",
                    ),
                ],
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, multiple records.",
            "_args": {
                "cksum": 12345,
                "records": [
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::1"),
                        source_addresses=[
                            Ip6Address("2001:db8::1"),
                        ],
                        aux_data=b"0123456789ABCDEF",
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip6Address("ff02::2"),
                        source_addresses=[
                            Ip6Address("2001:db8::2"),
                            Ip6Address("2001:db8::3"),
                            Ip6Address("2001:db8::4"),
                        ],
                        aux_data=b"0123456789ABCDEF0123456789ABCDEF",
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                        multicast_address=Ip6Address("ff02::3"),
                        source_addresses=[
                            Ip6Address("2001:db8::6"),
                            Ip6Address("2001:db8::7"),
                            Ip6Address("2001:db8::8"),
                            Ip6Address("2001:db8::9"),
                        ],
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                        multicast_address=Ip6Address("ff02::4"),
                        aux_data=b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                    ),
                ],
            },
            "_results": {
                "__len__": 328,
                "__str__": (
                    "ICMPv6 MLDv2 Report, records [type 'Mode Is Include', addr ff02::1, sources (200"
                    "1:db8::1), aux data b'0123456789ABCDEF'], [type 'Mode Is Exclude', addr ff02::2,"
                    " sources (2001:db8::2, 2001:db8::3, 2001:db8::4), aux data b'0123456789ABCDEF012"
                    "3456789ABCDEF'], [type 'Change To Include', addr ff02::3, sources (2001:db8::6, "
                    "2001:db8::7, 2001:db8::8, 2001:db8::9)], [type 'Block Old Sources', addr ff02::4"
                    ", aux data b'0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF']"
                ),
                "__repr__": (
                    "Icmp6Mld2ReportMessage(code=<Icmp6Mld2ReportCode.DEFAULT: 0>, cksum=12345, "
                    "records=[Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2M"
                    "ulticastAddressRecordType.MODE_IS_INCLUDE: 1>, multicast_address=Ip6Address('ff0"
                    "2::1'), source_addresses=[Ip6Address('2001:db8::1')], aux_data=b'0123456789ABCDE"
                    "F'), Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordType.M"
                    "ODE_IS_EXCLUDE: 2>, multicast_address=Ip6Address('ff02::2'), source_addresses=[I"
                    "p6Address('2001:db8::2'), Ip6Address('2001:db8::3'), Ip6Address('2001:db8::4')],"
                    " aux_data=b'0123456789ABCDEF0123456789ABCDEF'), Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE: 3>, multicast_addre"
                    "ss=Ip6Address('ff02::3'), source_addresses=[Ip6Address('2001:db8::6'), Ip6Addres"
                    "s('2001:db8::7'), Ip6Address('2001:db8::8'), Ip6Address('2001:db8::9')], aux_dat"
                    "a=b''), Icmp6Mld2MulticastAddressRecord(type=<Icmp6Mld2MulticastAddressRecordTyp"
                    "e.BLOCK_OLD_SOURCES: 6>, multicast_address=Ip6Address('ff02::4'), source_address"
                    "es=[], aux_data=b'0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCD"
                    "EF')])"
                ),
                "__bytes__": (
                    b"\x8f\x00\x00\x00\x00\x00\x00\x04\x01\x04\x00\x01\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x31\x32\x33"
                    b"\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x02\x08\x00\x03"
                    b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                    b"\x03\x00\x00\x04\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x03\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x06\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x08\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x09\x06\x10\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x04\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp6Type.MLD2__REPORT,
                "code": Icmp6Mld2ReportCode.DEFAULT,
                "cksum": 12345,
                "number_of_records": 4,
                "records": [
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::1"),
                        source_addresses=[
                            Ip6Address("2001:db8::1"),
                        ],
                        aux_data=b"0123456789ABCDEF",
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                        multicast_address=Ip6Address("ff02::2"),
                        source_addresses=[
                            Ip6Address("2001:db8::2"),
                            Ip6Address("2001:db8::3"),
                            Ip6Address("2001:db8::4"),
                        ],
                        aux_data=b"0123456789ABCDEF0123456789ABCDEF",
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                        multicast_address=Ip6Address("ff02::3"),
                        source_addresses=[
                            Ip6Address("2001:db8::6"),
                            Ip6Address("2001:db8::7"),
                            Ip6Address("2001:db8::8"),
                            Ip6Address("2001:db8::9"),
                        ],
                    ),
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                        multicast_address=Ip6Address("ff02::4"),
                        aux_data=b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
                    ),
                ],
            },
        },
    ]
)
class TestIcmp6MessageMld2ReportAssembler(TestCase):
    """
    The ICMPv6 MLDv2 Report message assembler tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        The ICMPv6 MLDv2 message assembler tests.
        """

        self._icmp6__mld2__report__message = Icmp6Mld2ReportMessage(
            **self._args
        )

    def test__icmp6__message__mld2__report__assembler__len(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp6__mld2__report__message),
            self._results["__len__"],
        )

    def test__icmp6__message__mld2__report__assembler__str(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp6__mld2__report__message),
            self._results["__str__"],
        )

    def test__icmp6__message__mld2__report__assembler__repr(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp6__mld2__report__message),
            self._results["__repr__"],
        )

    def test__icmp6__message__mld2__report__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp6__mld2__report__message),
            self._results["__bytes__"],
        )

    def test__icmp6__message__mld2__report__assembler__type(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'type' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__report__message.type,
            self._results["type"],
        )

    def test__icmp6__message__mld2__report__assembler__code(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'code' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__report__message.code,
            self._results["code"],
        )

    def test__icmp6__message__mld2__report__assembler__cksum(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'cksum' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__report__message.cksum,
            self._results["cksum"],
        )

    def test__icmp6__message__mld2__report__assembler__number_of_records(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'number_of_records' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__report__message.number_of_records,
            self._results["number_of_records"],
        )

    def test__icmp6__message__mld2__report__assembler__records(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'records' property returns
        a correct value.
        """

        self.assertEqual(
            self._icmp6__mld2__report__message.records,
            self._results["records"],
        )
