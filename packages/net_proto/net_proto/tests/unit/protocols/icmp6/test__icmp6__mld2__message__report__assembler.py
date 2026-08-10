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
Module contains tests for the ICMPv6 MLDv2 Report message assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__assembler.py

ver 3.0.10
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer, Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6Mld2MessageReport,
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6Mld2ReportCode,
    Icmp6Type,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Report message, no records.",
            "_kwargs": {
                "records": [],
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 MLDv2 Report",
                "__repr__": "Icmp6Mld2MessageReport(code=<Icmp6Mld2ReportCode.DEFAULT: 0>, cksum=0, records=[])",
                "__bytes__": (
                    # ICMPv6 MLDv2 Report
                    #   Type         : 143 (MLDv2 Report)
                    #   Code         : 0 (Default)
                    #   Checksum     : 0x70ff (computed by assemble(), pshdr_sum=0)
                    #   Reserved     : 0x0000
                    #   Record count : 0x0000
                    b"\x8f\x00\x70\xff\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.MLD2__REPORT,
                "code": Icmp6Mld2ReportCode.DEFAULT,
                "cksum": 0,
                "number_of_records": 0,
                "records": [],
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, single record (MODE_IS_INCLUDE, two sources).",
            "_kwargs": {
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
                    "ICMPv6 MLDv2 Report, records [type 'Mode Is Include', "
                    "addr ff02::1, sources (2001:db8::1, 2001:db8::2)]"
                ),
                "__repr__": (
                    "Icmp6Mld2MessageReport("
                    "code=<Icmp6Mld2ReportCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "records=["
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[Ip6Address('2001:db8::1'), Ip6Address('2001:db8::2')], "
                    "aux_data=b'')"
                    "])"
                ),
                "__bytes__": (
                    # ICMPv6 MLDv2 Report
                    #   Type         : 143 (MLDv2 Report)
                    #   Code         : 0 (Default)
                    #   Checksum     : 0x1583 (computed by assemble(), pshdr_sum=0)
                    #   Reserved     : 0x0000
                    #   Record count : 0x0001
                    #   Record [0]   : Type 0x01 (MODE_IS_INCLUDE), Aux 0, Src 2,
                    #                  Multicast ff02::1,
                    #                  Sources 2001:db8::1, 2001:db8::2
                    b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                ),
                "type": Icmp6Type.MLD2__REPORT,
                "code": Icmp6Mld2ReportCode.DEFAULT,
                "cksum": 0,
                "number_of_records": 1,
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
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, four records (every record-type variant exercised).",
            "_kwargs": {
                "records": [
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::1"),
                        source_addresses=[Ip6Address("2001:db8::1")],
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
                        aux_data=b"0123456789ABCDEF" * 4,
                    ),
                ],
            },
            "_results": {
                "__len__": 328,
                "__str__": (
                    "ICMPv6 MLDv2 Report, records [type 'Mode Is Include', addr ff02::1, "
                    "sources (2001:db8::1), aux data b'0123456789ABCDEF'], [type "
                    "'Mode Is Exclude', addr ff02::2, sources (2001:db8::2, 2001:db8::3, "
                    "2001:db8::4), aux data b'0123456789ABCDEF0123456789ABCDEF'], [type "
                    "'Change To Include', addr ff02::3, sources (2001:db8::6, 2001:db8::7, "
                    "2001:db8::8, 2001:db8::9)], [type 'Block Old Sources', addr ff02::4, "
                    "aux data b'0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
                    "0123456789ABCDEF']"
                ),
                "__repr__": (
                    "Icmp6Mld2MessageReport("
                    "code=<Icmp6Mld2ReportCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "records=["
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[Ip6Address('2001:db8::1')], "
                    "aux_data=b'0123456789ABCDEF'), "
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE: 2>, "
                    "multicast_address=Ip6Address('ff02::2'), "
                    "source_addresses=["
                    "Ip6Address('2001:db8::2'), "
                    "Ip6Address('2001:db8::3'), "
                    "Ip6Address('2001:db8::4')], "
                    "aux_data=b'0123456789ABCDEF0123456789ABCDEF'), "
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE: 3>, "
                    "multicast_address=Ip6Address('ff02::3'), "
                    "source_addresses=["
                    "Ip6Address('2001:db8::6'), "
                    "Ip6Address('2001:db8::7'), "
                    "Ip6Address('2001:db8::8'), "
                    "Ip6Address('2001:db8::9')], "
                    "aux_data=b''), "
                    "Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES: 6>, "
                    "multicast_address=Ip6Address('ff02::4'), "
                    "source_addresses=[], "
                    "aux_data=b'0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')"
                    "])"
                ),
                "__bytes__": (
                    # ICMPv6 MLDv2 Report
                    #   Type         : 143 (MLDv2 Report)
                    #   Code         : 0 (Default)
                    #   Checksum     : 0x52f0 (computed by assemble(), pshdr_sum=0)
                    #   Reserved     : 0x0000
                    #   Record count : 0x0004
                    #   Record [0]   : MODE_IS_INCLUDE,    ff02::1, src 2001:db8::1, aux 16B
                    #   Record [1]   : MODE_IS_EXCLUDE,    ff02::2, src 2001:db8::2/3/4, aux 32B
                    #   Record [2]   : CHANGE_TO_INCLUDE,  ff02::3, src 2001:db8::6/7/8/9
                    #   Record [3]   : BLOCK_OLD_SOURCES,  ff02::4, aux 64B
                    b"\x8f\x00\x52\xf0\x00\x00\x00\x04\x01\x04\x00\x01\xff\x02\x00\x00"
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
                "cksum": 0,
                "number_of_records": 4,
                "records": [
                    Icmp6Mld2MulticastAddressRecord(
                        type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                        multicast_address=Ip6Address("ff02::1"),
                        source_addresses=[Ip6Address("2001:db8::1")],
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
                        aux_data=b"0123456789ABCDEF" * 4,
                    ),
                ],
            },
        },
    ]
)
class TestIcmp6Mld2MessageReportAssembler(TestCase):
    """
    The ICMPv6 MLDv2 Report message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build an assembler wrapping the parametrized MLDv2 Report message.
        """

        self._icmp6__assembler = Icmp6Assembler(icmp6__message=Icmp6Mld2MessageReport(**self._kwargs))

    def test__icmp6__mld2__message__report__assembler__len(self) -> None:
        """
        Ensure 'len()' on the assembler equals ICMP6__MLD2__REPORT__LEN
        plus the summed lengths of every record.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__str(self) -> None:
        """
        Ensure 'str()' renders the canonical MLDv2 Report log line.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__repr(self) -> None:
        """
        Ensure 'repr()' forwards the wrapped message's dataclass repr.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the full wire form including the
        recomputed Internet checksum at bytes 2-3.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__type(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'type' field.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__code(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'code' field.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__cksum(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'cksum' field as
        passed to the constructor (the on-wire checksum is written during
        assemble() and does not mutate this attribute).

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__number_of_records(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'number_of_records'
        property.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            cast(Icmp6Mld2MessageReport, self._icmp6__assembler.message).number_of_records,
            self._results["number_of_records"],
            msg=f"Unexpected 'number_of_records' for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__records(self) -> None:
        """
        Ensure the assembler exposes the wrapped message 'records' field.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        self.assertEqual(
            cast(Icmp6Mld2MessageReport, self._icmp6__assembler.message).records,
            self._results["records"],
            msg=f"Unexpected 'records' for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the packed buffers, back-patches the
        checksum, and yields the same wire bytes as 'bytes()'.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__icmp6__mld2__message__report__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' produces exactly two buffers — the packed
        8-byte report header followed by the concatenated records — so the
        ICMPv6 checksum back-patch in Icmp6Assembler.assemble() targets
        the header buffer.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg=f"assemble() must append exactly 2 buffers (header + records) for case: {self._description}",
        )
        self.assertEqual(
            len(buffers[0]),
            8,
            msg=f"First buffer must be the 8-byte MLDv2 Report header for case: {self._description}",
        )
