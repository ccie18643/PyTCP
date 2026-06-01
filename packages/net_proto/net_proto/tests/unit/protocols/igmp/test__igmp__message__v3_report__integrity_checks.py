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
This module contains integrity-check tests for the IGMPv3 Membership
Report parser.

net_proto/tests/unit/protocols/igmp/test__igmp__message__v3_report__integrity_checks.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.protocols.igmp.igmp__errors import IgmpIntegrityError
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)


class TestIgmpMessageV3ReportIntegrity(TestCase):
    """
    The IGMPv3 Membership Report parser integrity-check tests.
    """

    def test__igmp__v3_report__integrity__accepts_empty_report(self) -> None:
        """
        Ensure the 8-byte report header with zero group records passes
        integrity validation.

        Reference: RFC 3376 §4.2 (V3 Membership Report layout).
        """

        frame = b"\x22\x00\x00\x00\x00\x00\x00\x00"

        IgmpMessageV3Report.validate_integrity(frame=frame, ip4__payload_len=8)

    def test__igmp__v3_report__integrity__accepts_one_record(self) -> None:
        """
        Ensure a report carrying exactly the declared number of group
        records passes integrity validation.

        Reference: RFC 3376 §4.2.3 (Number of Group Records).
        """

        frame = b"\x22\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00\xef\x01\x01\x01"

        IgmpMessageV3Report.validate_integrity(frame=frame, ip4__payload_len=16)

    def test__igmp__v3_report__integrity__rejects_short_header(self) -> None:
        """
        Ensure a frame shorter than the 8-byte report header is rejected.

        Reference: RFC 3376 §4.2 (V3 Membership Report header).
        """

        frame = b"\x22\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpMessageV3Report.validate_integrity(frame=frame, ip4__payload_len=7)

        self.assertIn("IGMP__V3_REPORT__LEN <= ip4__payload_len", str(error.exception))

    def test__igmp__v3_report__integrity__rejects_truncated_record(self) -> None:
        """
        Ensure a report whose declared group-record count overruns the
        payload is rejected.

        Reference: RFC 3376 §4.2.4 (Group Record).
        """

        # Number of Group Records = 1 but only 4 record bytes present
        # (a full record needs 8).
        frame = b"\x22\x00\x00\x00\x00\x00\x00\x01\x02\x00\x00\x00"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpMessageV3Report.validate_integrity(frame=frame, ip4__payload_len=12)

        self.assertIn("record_offset + IGMP__V3_GROUP_RECORD__LEN", str(error.exception))

    def test__igmp__v3_report__integrity__rejects_trailing_bytes(self) -> None:
        """
        Ensure a report whose records do not consume the whole payload
        (the walked offset does not land exactly on the payload end) is
        rejected.

        Reference: RFC 3376 §4.2.3 (records span the declared payload).
        """

        # Zero records declared, yet 4 trailing octets are present.
        frame = b"\x22\x00\x00\x00\x00\x00\x00\x00\xaa\xbb\xcc\xdd"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpMessageV3Report.validate_integrity(frame=frame, ip4__payload_len=12)

        self.assertIn("record_offset == ip4__payload_len", str(error.exception))
