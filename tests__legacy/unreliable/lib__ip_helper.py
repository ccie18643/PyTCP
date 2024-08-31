#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/unit/test_ip_helper.py - unit tests for ip helper functions
#
# ver 3.0.2
#


from dataclasses import dataclass

from testslide import TestCase

from pytcp.lib.ip_helper import inet_cksum, ip_version


class TestIpHelper(TestCase):
    """
    IP helper library unit test class.
    """

    def test_inet_cksum(self) -> None:
        """
        Test calculating the Internet Checksum
        """

        @dataclass
        class Sample:
            data: bytes
            init: int
            result: int

        samples = [
            Sample(
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                * 80,
                0,
                0x2D2D,
            ),
            Sample(b"\xFF" * 1500, 0, 0x0000),
            Sample(b"\x00" * 1500, 0, 0xFFFF),
            Sample(
                b"\xF7\x24\x09" * 100 + b"\x35\x67\x0F\x00" * 250, 0, 0xF1E5
            ),
            Sample(b"\x07" * 9999, 0, 0xBEC5),
            Sample(
                b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                * 80,
                0x03DF,
                0x294E,
            ),
            Sample(b"\xFF" * 1500, 0x0015, 0xFFEA),
            Sample(b"\x00" * 1500, 0xF3FF, 0x0C00),
            Sample(
                b"\xF7\x24\x09" * 100 + b"\x35\x67\x0F\x00" * 250,
                0x7314,
                0x7ED1,
            ),
            Sample(b"\x07" * 9999, 0xA3DC, 0x1AE9),
        ]

        for sample in samples:
            result = inet_cksum(data=memoryview(sample.data), init=sample.init)
            self.assertEqual(result, sample.result)

    def test_ip_version(self) -> None:
        """
        Test detecting the version of IP protocol.
        """
        self.assertEqual(ip_version("1:2:3:4:5:6:7:8"), 6)
        self.assertEqual(ip_version("1.2.3.4"), 4)
        self.assertEqual(ip_version("ZHOPA"), None)
