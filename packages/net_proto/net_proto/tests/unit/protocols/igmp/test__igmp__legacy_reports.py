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
This module contains tests for the legacy 8-octet IGMP report / leave
messages (IGMPv2 Report, IGMPv2 Leave Group, IGMPv1 Report).

net_proto/tests/unit/protocols/igmp/test__igmp__legacy_reports.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto.protocols.igmp.igmp__errors import IgmpSanityError
from net_proto.protocols.igmp.message.igmp__message import IgmpMessage, IgmpType
from net_proto.protocols.igmp.message.igmp__message__v1_report import (
    IgmpMessageV1Report,
)
from net_proto.protocols.igmp.message.igmp__message__v2_leave import (
    IgmpMessageV2Leave,
)
from net_proto.protocols.igmp.message.igmp__message__v2_report import (
    IgmpMessageV2Report,
)


@parameterized_class(
    [
        {
            "_description": "IGMPv2 Membership Report (type 0x16).",
            "_cls": IgmpMessageV2Report,
            "_type": IgmpType.V2_MEMBERSHIP_REPORT,
            # IGMPv2 Membership Report (8 bytes):
            #   Byte 0    : 0x16 -> type (V2 Membership Report)
            #   Byte 1    : 0x00 -> Max Resp Time (0 in non-Query messages)
            #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            "_bytes": b"\x16\x00\x00\x00\xef\x01\x01\x01",
            "_str": "IGMPv2 Membership Report group 239.1.1.1",
        },
        {
            "_description": "IGMPv2 Leave Group (type 0x17).",
            "_cls": IgmpMessageV2Leave,
            "_type": IgmpType.V2_LEAVE_GROUP,
            # IGMPv2 Leave Group (8 bytes):
            #   Byte 0    : 0x17 -> type (V2 Leave Group)
            #   Byte 1    : 0x00 -> Max Resp Time (0 in non-Query messages)
            #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            "_bytes": b"\x17\x00\x00\x00\xef\x01\x01\x01",
            "_str": "IGMPv2 Leave Group group 239.1.1.1",
        },
        {
            "_description": "IGMPv1 Membership Report (type 0x12).",
            "_cls": IgmpMessageV1Report,
            "_type": IgmpType.V1_MEMBERSHIP_REPORT,
            # IGMPv1 Membership Report (8 bytes):
            #   Byte 0    : 0x12 -> type (V1 Membership Report)
            #   Byte 1    : 0x00 -> unused
            #   Bytes 2-3 : 0x0000 -> checksum (injected by the assembler)
            #   Bytes 4-7 : 0xef010101 -> Group Address 239.1.1.1
            "_bytes": b"\x12\x00\x00\x00\xef\x01\x01\x01",
            "_str": "IGMPv1 Membership Report group 239.1.1.1",
        },
    ]
)
class TestIgmpLegacyReports(TestCase):
    """
    The legacy 8-octet IGMP report / leave message tests.
    """

    _description: str
    _cls: type[IgmpMessage]
    _type: IgmpType
    _bytes: bytes
    _str: str

    @override
    def setUp(self) -> None:
        """
        Build the parametrized legacy IGMP message instance.
        """

        self._message = self._cls(group_address=Ip4Address("239.1.1.1"))  # type: ignore[call-arg]

    def test__igmp__legacy__type_is_fixed(self) -> None:
        """
        Ensure each legacy message class fixes its own 'type' field.

        Reference: RFC 2236 §2.1 (IGMPv2 message types 0x16 / 0x17).
        Reference: RFC 1112 §6 (IGMPv1 Membership Report type 0x12).
        """

        self.assertEqual(
            self._message.type,
            self._type,
            msg=f"Unexpected fixed type for case: {self._description}",
        )

    def test__igmp__legacy__len(self) -> None:
        """
        Ensure the legacy message is always 8 octets.

        Reference: RFC 2236 §2 (8-octet message format).
        Reference: RFC 1112 §6 (V1 Membership Report).
        """

        self.assertEqual(len(self._message), 8, msg=f"Unexpected __len__ for case: {self._description}")

    def test__igmp__legacy__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical per-type log line.

        Reference: RFC 2236 §2 (message format).
        """

        self.assertEqual(str(self._message), self._str, msg=f"Unexpected __str__ for case: {self._description}")

    def test__igmp__legacy__bytes(self) -> None:
        """
        Ensure 'bytes()' returns the 8-octet wire encoding with the
        second octet zeroed and the checksum slot left for injection.

        Reference: RFC 2236 §2 (message format).
        Reference: RFC 2236 §2.2 (Max Resp Time zero in non-Query messages).
        """

        self.assertEqual(bytes(self._message), self._bytes, msg=f"Unexpected __bytes__ for case: {self._description}")

    def test__igmp__legacy__roundtrip(self) -> None:
        """
        Ensure the wire bytes round-trip through 'from_buffer()' and
        reproduce the same type and group address.

        Reference: RFC 2236 §2 (message format).
        """

        parsed = self._cls.from_buffer(self._bytes)

        self.assertEqual(parsed.type, self._type, msg=f"Unexpected type for case: {self._description}")
        self.assertEqual(
            parsed.group_address,  # type: ignore[attr-defined]
            Ip4Address("239.1.1.1"),
            msg=f"Unexpected group_address for case: {self._description}",
        )

    def test__igmp__legacy__sanity_accepts_multicast_group(self) -> None:
        """
        Ensure a legacy message naming a multicast group passes sanity.

        Reference: RFC 2236 §2.4 (Group Address holds the multicast group).
        """

        self._message.validate_sanity()

    def test__igmp__legacy__sanity_rejects_non_multicast_group(self) -> None:
        """
        Ensure a legacy message whose group address is not multicast is
        rejected at sanity.

        Reference: RFC 2236 §2.4 (Group Address holds the multicast group).
        """

        message = self._cls(group_address=Ip4Address("192.0.2.1"))  # type: ignore[call-arg]

        with self.assertRaises(IgmpSanityError) as error:
            message.validate_sanity()

        self.assertIn("must be a multicast address", str(error.exception))
