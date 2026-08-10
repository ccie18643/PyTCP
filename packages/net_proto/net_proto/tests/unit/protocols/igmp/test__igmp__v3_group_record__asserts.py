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
This module contains assert tests for the IGMPv3 Group Record.

net_proto/tests/unit/protocols/igmp/test__igmp__v3_group_record__asserts.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip4Address
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3GroupRecord,
    IgmpV3RecordType,
)


class TestIgmpV3GroupRecordAsserts(TestCase):
    """
    The IGMPv3 Group Record '__post_init__' assertion tests.
    """

    def test__igmp__v3_group_record__default_accepted(self) -> None:
        """
        Ensure the minimal valid record (multicast group, no sources, no
        aux data) constructs and reports the 8-byte fixed length.

        Reference: RFC 3376 §4.2.4 (Group Record).
        """

        record = IgmpV3GroupRecord(
            type=IgmpV3RecordType.MODE_IS_INCLUDE,
            multicast_address=Ip4Address("239.1.1.1"),
        )

        self.assertEqual(
            len(record),
            8,
            msg="The minimal IGMPv3 Group Record must be 8 bytes long.",
        )

    def test__igmp__v3_group_record__multicast_address__not_multicast(self) -> None:
        """
        Ensure a non-multicast 'multicast_address' is rejected — the
        Group Record always names a multicast group.

        Reference: RFC 3376 §4.2.8 (Multicast Address).
        """

        with self.assertRaises(AssertionError) as error:
            IgmpV3GroupRecord(
                type=IgmpV3RecordType.MODE_IS_INCLUDE,
                multicast_address=Ip4Address("192.0.2.1"),
            )

        self.assertIn("must be a multicast address", str(error.exception))

    def test__igmp__v3_group_record__source_addresses__not_unicast(self) -> None:
        """
        Ensure a non-unicast entry in 'source_addresses' is rejected —
        source addresses are unicast senders.

        Reference: RFC 3376 §4.2.9 (Source Address [i]).
        """

        with self.assertRaises(AssertionError) as error:
            IgmpV3GroupRecord(
                type=IgmpV3RecordType.MODE_IS_INCLUDE,
                multicast_address=Ip4Address("239.1.1.1"),
                source_addresses=[Ip4Address("224.0.0.5")],
            )

        self.assertIn("must contain only unicast addresses", str(error.exception))

    def test__igmp__v3_group_record__aux_data__misaligned(self) -> None:
        """
        Ensure 'aux_data' whose length is not a multiple of 4 octets is
        rejected — Aux Data Len counts whole 32-bit words.

        Reference: RFC 3376 §4.2.6 (Aux Data Len in 32-bit words).
        """

        with self.assertRaises(AssertionError) as error:
            IgmpV3GroupRecord(
                type=IgmpV3RecordType.MODE_IS_INCLUDE,
                multicast_address=Ip4Address("239.1.1.1"),
                aux_data=b"\x01\x02\x03",
            )

        self.assertIn("must be 4-byte aligned", str(error.exception))
