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
This module contains tests for the ICMPv6 MLDv1 Multicast Listener
Query message (type 130, 24-octet form) support class.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld1__message__query.py

ver 3.0.10
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.icmp6__message import Icmp6Type
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__query import (
    Icmp6Mld1MessageQuery,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    ICMP6__MLD1__MESSAGE__LEN,
)

# ICMPv6 MLDv1 General Query (type 130) wire frame (24 bytes):
#   Byte  0     : 0x82 -> type=130 (Multicast Listener Query)
#   Byte  1     : 0x00 -> code=0
#   Bytes 2-3   : 0x0000 -> checksum (0 here)
#   Bytes 4-5   : 0x2710 -> Maximum Response Delay = 10000 ms
#   Bytes 6-7   : 0x0000 -> Reserved
#   Bytes 8-23  : :: -> Multicast Address (General Query)
_GENERAL_QUERY_FRAME = b"\x82\x00\x00\x00\x27\x10\x00\x00" + bytes(Ip6Address())


class TestIcmp6Mld1MessageQuery(TestCase):
    """
    The ICMPv6 MLDv1 Query message tests.
    """

    def test__icmp6__mld1__query__from_buffer_decodes_fields(self) -> None:
        """
        Ensure 'from_buffer' decodes the Maximum Response Delay and
        the (unspecified) Multicast Address of a General Query.

        Reference: RFC 2710 §3.1 (Multicast Listener Query format).
        """

        message = Icmp6Mld1MessageQuery.from_buffer(_GENERAL_QUERY_FRAME)
        self.assertEqual(
            message.maximum_response_delay,
            10000,
            msg="from_buffer must decode the Maximum Response Delay field.",
        )
        self.assertEqual(
            message.multicast_address,
            Ip6Address(),
            msg="A General Query carries the unspecified multicast address.",
        )
        self.assertIs(
            message.type,
            Icmp6Type.MULTICAST_LISTENER_QUERY,
            msg="from_buffer must yield an MLDv1 Query (type 130).",
        )

    def test__icmp6__mld1__query__is_fixed_24_octets(self) -> None:
        """
        Ensure the MLDv1 Query is the fixed 24-octet form (the length
        that distinguishes it from the larger MLDv2 Query).

        Reference: RFC 3810 §8.1 (24-octet Query is MLDv1).
        """

        self.assertEqual(
            len(Icmp6Mld1MessageQuery.from_buffer(_GENERAL_QUERY_FRAME)),
            ICMP6__MLD1__MESSAGE__LEN,
            msg="An MLDv1 Query must be a fixed 24 octets.",
        )

    def test__icmp6__mld1__query__integrity_rejects_short_frame(self) -> None:
        """
        Ensure 'validate_integrity' rejects a frame shorter than the
        fixed 24-octet MLDv1 message length.

        Reference: RFC 2710 §3.1 (fixed 24-octet message).
        """

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6Mld1MessageQuery.validate_integrity(frame=_GENERAL_QUERY_FRAME[:20], ip6__dlen=20)
