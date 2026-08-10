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
Done message (type 132) support class.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld1__message__done.py

ver 3.0.9
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.icmp6__message import Icmp6Type
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__done import (
    Icmp6Mld1MessageDone,
)
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    ICMP6__MLD1__MESSAGE__LEN,
)

# ICMPv6 MLDv1 Done (type 132) wire frame (24 bytes):
#   Byte  0     : 0x84 -> type=132 (Multicast Listener Done)
#   Byte  1     : 0x00 -> code=0
#   Bytes 2-3   : 0x0000 -> checksum (0 here; injected by assembler)
#   Bytes 4-5   : 0x0000 -> Maximum Response Delay (0; ignored in Done)
#   Bytes 6-7   : 0x0000 -> Reserved
#   Bytes 8-23  : ff02::dead -> Multicast Address
_GROUP = Ip6Address("ff02::dead")
_DONE_FRAME = b"\x84\x00\x00\x00\x00\x00\x00\x00" + bytes(_GROUP)


class TestIcmp6Mld1MessageDone(TestCase):
    """
    The ICMPv6 MLDv1 Done message tests.
    """

    def test__icmp6__mld1__done__default_accepted_and_type(self) -> None:
        """
        Ensure a minimal valid MLDv1 Done constructs at the fixed
        24-octet length and carries ICMPv6 type 132.

        Reference: RFC 2710 §3 (Multicast Listener Done format).
        """

        message = Icmp6Mld1MessageDone(multicast_address=_GROUP)
        self.assertEqual(
            len(message),
            ICMP6__MLD1__MESSAGE__LEN,
            msg="An MLDv1 Done must be a fixed 24 octets.",
        )
        self.assertIs(
            message.type,
            Icmp6Type.MULTICAST_LISTENER_DONE,
            msg="An MLDv1 Done must carry ICMPv6 type 132.",
        )

    def test__icmp6__mld1__done__bytes(self) -> None:
        """
        Ensure the assembled MLDv1 Done wire form matches the
        24-octet layout (type 132, zeroed Max Resp Delay + Reserved,
        16-byte Multicast Address).

        Reference: RFC 2710 §3 (Multicast Listener Done format).
        """

        self.assertEqual(
            bytes(Icmp6Mld1MessageDone(multicast_address=_GROUP)),
            _DONE_FRAME,
            msg="The assembled MLDv1 Done must match the RFC 2710 §3 wire layout.",
        )

    def test__icmp6__mld1__done__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer' decodes the multicast address from a
        well-formed MLDv1 Done frame.

        Reference: RFC 2710 §3 (Multicast Listener Done format).
        """

        message = Icmp6Mld1MessageDone.from_buffer(_DONE_FRAME)
        self.assertEqual(
            message.multicast_address,
            _GROUP,
            msg="from_buffer must decode the Multicast Address field.",
        )
        self.assertIs(
            message.type,
            Icmp6Type.MULTICAST_LISTENER_DONE,
            msg="from_buffer must yield an MLDv1 Done (type 132).",
        )

    def test__icmp6__mld1__done__integrity_rejects_short_frame(self) -> None:
        """
        Ensure 'validate_integrity' rejects a frame shorter than the
        fixed 24-octet MLDv1 message length.

        Reference: RFC 2710 §3 (fixed 24-octet message).
        """

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6Mld1MessageDone.validate_integrity(frame=_DONE_FRAME[:20], ip6__dlen=20)
