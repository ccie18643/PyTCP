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
Report message (type 131) support class.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld1__message__report.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto.lib.buffer import Buffer
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.icmp6__message import Icmp6Type
from net_proto.protocols.icmp6.message.mld1.icmp6__mld1__message__report import (
    ICMP6__MLD1__MESSAGE__LEN,
    Icmp6Mld1MessageReport,
)

# ICMPv6 MLDv1 Report (type 131) wire frame (24 bytes):
#   Byte  0     : 0x83 -> type=131 (Multicast Listener Report)
#   Byte  1     : 0x00 -> code=0
#   Bytes 2-3   : 0x0000 -> checksum (0 here; injected by assembler)
#   Bytes 4-5   : 0x0000 -> Maximum Response Delay (0; ignored in Report)
#   Bytes 6-7   : 0x0000 -> Reserved
#   Bytes 8-23  : ff02::dead -> Multicast Address
_GROUP = Ip6Address("ff02::dead")
_REPORT_FRAME = b"\x83\x00\x00\x00\x00\x00\x00\x00" + bytes(_GROUP)


class TestIcmp6Mld1MessageReportAsserts(TestCase):
    """
    The ICMPv6 MLDv1 Report message field-assertion tests.
    """

    def test__icmp6__mld1__report__default_accepted(self) -> None:
        """
        Ensure a minimal valid MLDv1 Report constructs and is the
        fixed 24-octet length.

        Reference: RFC 2710 §3 (Multicast Listener Report format).
        """

        message = Icmp6Mld1MessageReport(multicast_address=_GROUP)
        self.assertEqual(
            len(message),
            ICMP6__MLD1__MESSAGE__LEN,
            msg="An MLDv1 Report must be a fixed 24 octets.",
        )
        self.assertIs(
            message.type,
            Icmp6Type.MULTICAST_LISTENER_REPORT,
            msg="An MLDv1 Report must carry ICMPv6 type 131.",
        )

    def test__icmp6__mld1__report__rejects_non_ip6_address(self) -> None:
        """
        Ensure the constructor rejects a 'multicast_address' that is
        not an Ip6Address.

        Reference: RFC 2710 §3 (Multicast Address field).
        """

        with self.assertRaises(AssertionError):
            Icmp6Mld1MessageReport(multicast_address="ff02::dead")  # type: ignore[arg-type]


class TestIcmp6Mld1MessageReportAssembler(TestCase):
    """
    The ICMPv6 MLDv1 Report message assembly tests.
    """

    def test__icmp6__mld1__report__bytes(self) -> None:
        """
        Ensure the assembled MLDv1 Report wire form matches the
        24-octet layout (type 131, zeroed Max Resp Delay + Reserved,
        16-byte Multicast Address).

        Reference: RFC 2710 §3 (Multicast Listener Report format).
        """

        message = Icmp6Mld1MessageReport(multicast_address=_GROUP)
        self.assertEqual(
            bytes(message),
            _REPORT_FRAME,
            msg="The assembled MLDv1 Report must match the RFC 2710 §3 wire layout.",
        )

    def test__icmp6__mld1__report__assemble_appends_full_message(self) -> None:
        """
        Ensure 'assemble' appends the complete 24-octet message to the
        buffer list.

        Reference: RFC 2710 §3 (Multicast Listener Report format).
        """

        buffers: list[Buffer] = []
        Icmp6Mld1MessageReport(multicast_address=_GROUP).assemble(buffers)
        self.assertEqual(
            b"".join(bytes(b) for b in buffers),
            _REPORT_FRAME,
            msg="assemble() must append the full MLDv1 Report wire form.",
        )


class TestIcmp6Mld1MessageReportParser(TestCase):
    """
    The ICMPv6 MLDv1 Report message parser tests.
    """

    def test__icmp6__mld1__report__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer' decodes the multicast address from a
        well-formed MLDv1 Report frame.

        Reference: RFC 2710 §3 (Multicast Listener Report format).
        """

        message = Icmp6Mld1MessageReport.from_buffer(_REPORT_FRAME)
        self.assertEqual(
            message.multicast_address,
            _GROUP,
            msg="from_buffer must decode the Multicast Address field.",
        )
        self.assertIs(
            message.type,
            Icmp6Type.MULTICAST_LISTENER_REPORT,
            msg="from_buffer must yield an MLDv1 Report (type 131).",
        )

    def test__icmp6__mld1__report__integrity_rejects_short_frame(self) -> None:
        """
        Ensure 'validate_integrity' rejects a frame shorter than the
        fixed 24-octet MLDv1 message length.

        Reference: RFC 2710 §3 (fixed 24-octet message).
        """

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6Mld1MessageReport.validate_integrity(frame=_REPORT_FRAME[:20], ip6__dlen=20)
