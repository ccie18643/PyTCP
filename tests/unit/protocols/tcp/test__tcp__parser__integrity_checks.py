#!/usr/bin/env python3

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
Module contains tests for the TCP packet integrity checks.

tests/unit/protocols/tcp/test__tcp__parser__integrity_checks.py

ver 3.0.2
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet import PacketRx
from pytcp.protocols.tcp.tcp__errors import TcpIntegrityError
from pytcp.protocols.tcp.tcp__header import TCP__HEADER__LEN
from pytcp.protocols.tcp.tcp__parser import TcpParser
from tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4
from tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6

testcases = [
    {
        "_description": (
            "The value of the 'ip__payload_len' variable is lower than the "
            "value of the 'TCP_HEADER_LEN' constant."
        ),
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                b"\xcb\x5b\x00\x00\x01\x01\x01\x01"
            ),
        },
        "_mocked_values": {
            "ip4__payload_len": TCP__HEADER__LEN - 1,
            "ip6__dlen": TCP__HEADER__LEN - 1,
        },
        "_results": {
            "error_message": (
                "The condition 'TCP__HEADER__LEN <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, "
                "self._ip__payload_len=19, len(self._frame)=24"
            ),
        },
    },
    {
        "_description": (
            "The value of the 'ip__payload_len' variable is higher than the frame length."
        ),
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                b"\xcb\x5b\x00\x00\x01\x01\x01\x01"
            ),
        },
        "_mocked_values": {
            "ip4__payload_len": TCP__HEADER__LEN + 4 + 1,
            "ip6__dlen": TCP__HEADER__LEN + 4 + 1,
        },
        "_results": {
            "error_message": (
                "The condition 'TCP__HEADER__LEN <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, "
                "self._ip__payload_len=25, len(self._frame)=24"
            ),
        },
    },
    {
        "_description": (
            "The value of the header 'hlen' field (19) is lower than the 'TCP_HEADER_LEN'."
        ),
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x4c\x10\x2b\x67"
                b"\xdf\x5b\x00\x00\x01\x01\x01\x01"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": (
                "The condition 'TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, hlen=16, "
                "self._ip__payload_len=24, len(self._frame)=24"
            ),
        },
    },
    {
        "_description": (
            "The value of the header 'hlen' field (28) is higher than the value "
            "of the 'ip__payload_len' variable."
        ),
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x70\x10\x2b\x67"
                b"\xbb\x5b\x00\x00\x01\x01\x01\x01"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": (
                "The condition 'TCP__HEADER__LEN <= hlen <= self._ip__payload_len <= "
                "len(self._frame)' must be met. Got: TCP__HEADER__LEN=20, hlen=28, "
                "self._ip__payload_len=24, len(self._frame)=24"
            ),
        },
    },
    {
        "_description": "Packet has incorrect checksum.",
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                b"\xbe\x86\x00\x00\x03\x03\x0a\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": "The packet checksum must be valid.",
        },
    },
    {
        "_description": (
            "The value of the option 'len' field (1) is lower than the minimum "
            "acceptable value (2)."
        ),
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                b"\xce\x5b\x00\x00\xff\x01\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": (
                "The TCP option length must be greater than 1. Got: 1."
            ),
        },
    },
    {
        "_description": (
            "The value of the option 'len' field (5 vs 3) extends past the value "
            "of the 'hlen' header field."
        ),
        "_args": {
            "bytes": (
                b"\x30\x39\xd4\x31\x00\x12\xd6\x87\x00\x74\xcb\xb1\x60\x10\x2b\x67"
                b"\xce\x57\x00\x00\xff\x05\x00\x00"
            ),
        },
        "_mocked_values": {},
        "_results": {
            "error_message": (
                "The TCP option length must not extend past the header length. "
                "Got: offset=25, hlen=24"
            ),
        },
    },
]


@parameterized_class(testcases)
class TestTcpParserIntegrityChecks__Ip4(TestCasePacketRxIp4):
    """
    The TCP packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser raises integrity error on malformed packets.
        """

        with self.assertRaises(TcpIntegrityError) as error:
            TcpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][TCP] {self._results["error_message"]}",
        )


@parameterized_class(testcases)
class TestTcpParserIntegrityChecks__Ip6(TestCasePacketRxIp6):
    """
    The TCP packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__tcp__parser__from_bytes(self) -> None:
        """
        Ensure the TCP packet parser raises integrity error on malformed packets.
        """

        with self.assertRaises(TcpIntegrityError) as error:
            TcpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][TCP] {self._results["error_message"]}",
        )
