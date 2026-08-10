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
This module contains tests for the IGMP unknown-message carrier.

net_proto/tests/unit/protocols/igmp/test__igmp__message__unknown.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto.protocols.igmp.igmp__errors import IgmpSanityError
from net_proto.protocols.igmp.message.igmp__message import IgmpType
from net_proto.protocols.igmp.message.igmp__message__unknown import (
    IgmpMessageUnknown,
)


class TestIgmpMessageUnknown(TestCase):
    """
    The IGMP unknown-message carrier tests.
    """

    def test__igmp__unknown__from_buffer_parses_unknown_type(self) -> None:
        """
        Ensure an unrecognised IGMP type byte parses into the unknown
        carrier preserving the type and trailing data.

        Reference: RFC 3376 §4 (unrecognized message types).
        """

        # Unknown IGMP message:
        #   Byte 0    : 0x99 -> unrecognised type
        #   Byte 1    : 0x00 -> reserved/unused
        #   Bytes 2-3 : 0x0000 -> checksum
        #   Bytes 4-7 : trailing data
        frame = b"\x99\x00\x00\x00\xde\xad\xbe\xef"

        message = IgmpMessageUnknown.from_buffer(frame)

        self.assertEqual(int(message.type), 0x99, msg="Unknown type byte must be preserved.")
        self.assertTrue(message.type.is_unknown, msg="An unrecognised type must be flagged is_unknown.")
        self.assertEqual(bytes(message.data), b"\xde\xad\xbe\xef", msg="Trailing data must be preserved.")

    def test__igmp__unknown__sanity_rejects(self) -> None:
        """
        Ensure the unknown carrier is rejected at sanity so the RX
        handler silently drops the frame.

        Reference: RFC 3376 §4 (unrecognized message types MUST be silently ignored).
        """

        message = IgmpMessageUnknown.from_buffer(b"\x99\x00\x00\x00")

        with self.assertRaises(IgmpSanityError) as error:
            message.validate_sanity()

        self.assertIn("must be one of", str(error.exception))

    def test__igmp__unknown__from_buffer_rejects_known_type(self) -> None:
        """
        Ensure the unknown carrier refuses to parse a recognised type —
        recognised types route to their own message classes.

        Reference: RFC 3376 §4 (known types route to their handlers).
        """

        # Type 0x11 (Membership Query) is a known type.
        with self.assertRaises(AssertionError) as error:
            IgmpMessageUnknown.from_buffer(b"\x11\x00\x00\x00\x00\x00\x00\x00")

        self.assertIn("must not be known", str(error.exception))

    def test__igmp__unknown__len(self) -> None:
        """
        Ensure '__len__()' counts the 4-byte common header plus the
        trailing data.

        Reference: RFC 3376 §4 (IGMP common header).
        """

        message = IgmpMessageUnknown(type=IgmpType.from_int(0x99), data=b"\xde\xad\xbe\xef")

        self.assertEqual(len(message), 8, msg="Unknown message length must be 4-byte header + data.")
