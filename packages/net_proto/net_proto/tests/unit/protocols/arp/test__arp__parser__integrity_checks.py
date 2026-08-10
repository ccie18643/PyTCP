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
This module contains tests for the ARP packet parser integrity checks.

net_proto/tests/unit/protocols/arp/test__arp__parser__integrity_checks.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import ARP__HEADER__LEN, ArpIntegrityError, ArpParser, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "The frame length is less than the value of the 'ARP__HEADER__LEN' constant.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103 (truncated; missing one octet)
                #
                #   Summary       : Header cut short at 27 bytes (< 28-byte minimum).
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67"
            ),
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {ARP__HEADER__LEN} bytes. Got: {ARP__HEADER__LEN - 1} bytes."
                ),
            },
        },
        {
            "_description": "The frame is empty.",
            "_frame_rx": b"",
            "_results": {
                "error_message": f"The minimum packet length must be {ARP__HEADER__LEN} bytes. Got: 0 bytes.",
            },
        },
        {
            "_description": "The value of the 'hrtype' field is incorrect (unknown = 0).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0000 (unknown)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103.104
                #
                #   Summary       : Invalid hardware type triggers integrity error.
                b"\x00\x00\x08\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            "_results": {
                "error_message": (
                    "The 'hrtype' field value must be <ArpHardwareType.ETHERNET: 1>. "
                    "Got: <ArpHardwareType.UNKNOWN_0: 0>."
                ),
            },
        },
        {
            "_description": "The value of the 'prtype' field is incorrect (unknown = 0).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0000 (unknown)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103.104
                #
                #   Summary       : Invalid protocol type triggers integrity error.
                b"\x00\x01\x00\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            "_results": {
                "error_message": (
                    "The 'prtype' field value must be <EtherType.IP4: 2048>. Got: <EtherType.UNKNOWN_0: 0>."
                ),
            },
        },
        {
            "_description": "The value of the 'hrlen' field is incorrect (0 instead of 6).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 0 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103.104
                #
                #   Summary       : Hardware length field cleared (0) instead of 6.
                b"\x00\x01\x08\x00\x00\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            "_results": {
                "error_message": "The 'hrlen' field value must be 6. Got: 0.",
            },
        },
        {
            "_description": "The value of the 'hrlen' field is incorrect (8 instead of 6).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 8 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103.104
                #
                #   Summary       : Hardware length field set to 8 instead of canonical 6.
                b"\x00\x01\x08\x00\x08\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            "_results": {
                "error_message": "The 'hrlen' field value must be 6. Got: 8.",
            },
        },
        {
            "_description": "The value of the 'prlen' field is incorrect (0 instead of 4).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 0
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103.104
                #
                #   Summary       : Protocol length field cleared (0) instead of 4.
                b"\x00\x01\x08\x00\x06\x00\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            "_results": {
                "error_message": "The 'prlen' field value must be 4. Got: 0.",
            },
        },
        {
            "_description": "The value of the 'prlen' field is incorrect (16 instead of 4, as if IPv6).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 16
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:02:03:04:05:06
                #   Sender IP     : 11.22.33.44
                #   Target MAC    : 0a:0b:0c:0d:0e:0f
                #   Target IP     : 101.102.103.104
                #
                #   Summary       : Protocol length field advertises 16 bytes (IPv6-sized) instead of 4.
                b"\x00\x01\x08\x00\x06\x10\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
            ),
            "_results": {
                "error_message": "The 'prlen' field value must be 4. Got: 16.",
            },
        },
    ]
)
class TestArpParserIntegrityChecks(TestCase):
    """
    The ARP packet parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the raw frame in a PacketRx for the parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__arp__parser__integrity_error(self) -> None:
        """
        Ensure the ARP packet parser raises ArpIntegrityError on malformed
        frames and reports the expected message.

        Reference: RFC 826 (ARP — fixed 28-byte Ethernet/IPv4 wire layout, Packet Reception hrtype/prtype guards).
        """

        with self.assertRaises(ArpIntegrityError) as error:
            ArpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ARP] {self._results['error_message']}",
            msg=f"Unexpected integrity-error message for case: {self._description}",
        )


class TestArpParserIntegrityBoundary(TestCase):
    """
    Boundary tests for the ARP integrity validator.
    """

    def test__arp__parser__integrity__minimum_length_accepted(self) -> None:
        """
        Ensure a frame of exactly ARP__HEADER__LEN bytes passes integrity checks.

        Wire contents (valid ARP Request):
          Hardware type : 0x0001 (Ethernet)
          Protocol type : 0x0800 (IPv4)
          HLEN / PLEN   : 6 / 4
          Operation     : 1 (Request)
          Sender MAC    : 02:00:00:00:00:91
          Sender IP     : 10.0.1.91
          Target MAC    : 00:00:00:00:00:07
          Target IP     : 10.0.1.7

        Reference: RFC 826 (ARP — 28-byte Ethernet/IPv4 packet layout is the structural floor).
        """

        frame = (
            b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00"
            b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
        )

        self.assertEqual(len(frame), ARP__HEADER__LEN, msg="Fixture frame must match ARP__HEADER__LEN.")

        ArpParser(PacketRx(frame))
