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
This module contains integrity-check tests for the IGMP Membership
Query parser.

net_proto/tests/unit/protocols/igmp/test__igmp__message__query__integrity_checks.py

ver 3.0.10
"""

from unittest import TestCase

from net_proto.protocols.igmp.igmp__errors import IgmpIntegrityError
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)


class TestIgmpMessageQueryIntegrity(TestCase):
    """
    The IGMP Membership Query parser integrity-check tests.
    """

    def test__igmp__query__integrity__accepts_8_byte_query(self) -> None:
        """
        Ensure the shortest legal Query (8-octet v1/v2 form) passes
        integrity validation.

        Reference: RFC 2236 §2 (8-octet IGMPv2 Query).
        """

        frame = b"\x11\x64\x00\x00\x00\x00\x00\x00"

        IgmpMessageQuery.validate_integrity(frame=frame, ip4__payload_len=8)

    def test__igmp__query__integrity__accepts_12_byte_v3_query(self) -> None:
        """
        Ensure the shortest IGMPv3 Query (12 octets, no sources) passes
        integrity validation.

        Reference: RFC 3376 §4.1 (IGMPv3 Query, 12-octet minimum).
        """

        frame = b"\x11\x64\x00\x00\x00\x00\x00\x00\x02\x7d\x00\x00"

        IgmpMessageQuery.validate_integrity(frame=frame, ip4__payload_len=12)

    def test__igmp__query__integrity__rejects_short_query(self) -> None:
        """
        Ensure a Query shorter than 8 octets is rejected.

        Reference: RFC 3376 §4.1 (Query is at least 8 octets).
        """

        frame = b"\x11\x64\x00\x00\x00\x00\x00"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpMessageQuery.validate_integrity(frame=frame, ip4__payload_len=7)

        self.assertIn("IGMP__QUERY__SIMPLE__LEN <= ip4__payload_len", str(error.exception))

    def test__igmp__query__integrity__rejects_ambiguous_length(self) -> None:
        """
        Ensure a Query of 9-11 octets is rejected as ambiguous between
        the v1/v2 (8-octet) and v3 (12-octet) forms.

        Reference: RFC 3376 §7.1 (9-11 octet Query ignored).
        """

        frame = b"\x11\x64\x00\x00\x00\x00\x00\x00\x02\x7d"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpMessageQuery.validate_integrity(frame=frame, ip4__payload_len=10)

        self.assertIn("ambiguous", str(error.exception))

    def test__igmp__query__integrity__rejects_truncated_source_list(self) -> None:
        """
        Ensure an IGMPv3 Query declaring more sources than the payload
        carries is rejected.

        Reference: RFC 3376 §4.1.8 (Number of Sources).
        Reference: RFC 3376 §4.1.9 (Source Address list).
        """

        # Number of Sources = 2 (declares 8 source bytes) but only one
        # 4-byte source is present (16-octet payload, not 20).
        frame = b"\x11\x64\x00\x00\xef\x01\x01\x01\x02\x00\x00\x02\xc0\x00\x02\x01"

        with self.assertRaises(IgmpIntegrityError) as error:
            IgmpMessageQuery.validate_integrity(frame=frame, ip4__payload_len=16)

        self.assertIn("truncates the declared source-address list", str(error.exception))

    def test__igmp__query__integrity__allows_additional_data(self) -> None:
        """
        Ensure an IGMPv3 Query carrying additional octets beyond the
        declared source list passes (those octets are covered by the
        checksum but otherwise ignored).

        Reference: RFC 3376 §4.1.10 (Additional Data).
        """

        # Number of Sources = 0; payload is 16 octets (12 + 4 trailing
        # additional-data octets).
        frame = b"\x11\x64\x00\x00\xef\x01\x01\x01\x02\x00\x00\x00\xaa\xbb\xcc\xdd"

        IgmpMessageQuery.validate_integrity(frame=frame, ip4__payload_len=16)
