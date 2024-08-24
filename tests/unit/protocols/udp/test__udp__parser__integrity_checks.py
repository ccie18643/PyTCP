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
Module contains tests for the UDP packet integrity checks.

tests/unit/protocols/udp/test__udp__parser__integrity_checks.py

ver 3.0.1
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.packet import PacketRx
from pytcp.protocols.ip4.ip4__parser import Ip4Parser
from pytcp.protocols.udp.udp__errors import UdpIntegrityError
from pytcp.protocols.udp.udp__header import UDP__HEADER__LEN
from pytcp.protocols.udp.udp__parser import UdpParser


@parameterized_class(
    [
        {
            "_description": (
                "The value of the 'ip__payload_len' variable is lower than the "
                "value of the 'UDP_HEADER_LEN' constant."
            ),
            "_args": {
                "bytes": b"\x30\x39\xd4\x31\x00\x08\xfb\x8c",
            },
            "_conditions": {
                "ip__payload_len": UDP__HEADER__LEN - 1,
            },
            "_results": {
                "error_message": (
                    "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
                    "len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, "
                    "self._ip__payload_len=7, len(self._frame)=8"
                ),
            },
        },
        {
            "_description": (
                "The value of the 'ip__payload_len' variable is higher than the frame length."
            ),
            "_args": {
                "bytes": b"\x30\x39\xd4\x31\x00\x08\xfb\x8c",
            },
            "_conditions": {
                "ip__payload_len": UDP__HEADER__LEN + 1,
            },
            "_results": {
                "error_message": (
                    "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
                    "len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, "
                    "self._ip__payload_len=9, len(self._frame)=8"
                ),
            },
        },
        {
            "_description": (
                "The value of the header 'plen' field is lower than the header length."
            ),
            "_args": {
                "bytes": b"\x30\x39\xd4\x31\x00\x07\xfb\x8c",
            },
            "_conditions": {},
            "_results": {
                "error_message": (
                    "The condition 'UDP__HEADER__LEN <= plen == self._ip__payload_len "
                    "<= len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, plen=7, "
                    "self._ip__payload_len=8, len(self._frame)=8"
                ),
            },
        },
        {
            "_description": (
                "The value of the  header 'plen' field is different than the 'ip__payload_len' "
                "variable."
            ),
            "_args": {
                "bytes": b"\x30\x39\xd4\x31\x00\x08\xfb\x8c\00\00",
            },
            "_conditions": {
                "ip__payload_len": UDP__HEADER__LEN + 1,
            },
            "_results": {
                "error_message": (
                    "The condition 'UDP__HEADER__LEN <= plen == self._ip__payload_len "
                    "<= len(self._frame)' must be met. Got: UDP__HEADER__LEN=8, plen=8, "
                    "self._ip__payload_len=9, len(self._frame)=10"
                ),
            },
        },
        {
            "_description": "Packet has incorrect checksum.",
            "_args": {
                "bytes": (
                    b"\x30\x39\xd4\x31\x00\x18\xab\xcd\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
            },
            "_conditions": {},
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestUdpParserIntegrityChecks(TestCase):
    """
    The UDP packet parser integrity checks tests.
    """

    _description: str
    _args: dict[str, Any]
    _conditions: dict[str, Any]
    _results: dict[str, Any]

    def test__udp__parser__from_bytes(self) -> None:
        """
        Ensure the UDP packet parser raises integrity error on malformed packets.
        """

        packet_rx = PacketRx(self._args["bytes"])

        packet_rx.ip = cast(Ip4Parser, StrictMock(template=Ip4Parser))
        self.patch_attribute(
            target=packet_rx.ip,
            attribute="payload_len",
            new_value=self._conditions.get(
                "ip__payload_len", len(self._args["bytes"])
            ),
        )
        self.patch_attribute(
            target=packet_rx.ip,
            attribute="pshdr_sum",
            new_value=0,
        )

        with self.assertRaises(UdpIntegrityError) as error:
            UdpParser(packet_rx=packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][UDP] {self._results["error_message"]}",
        )
