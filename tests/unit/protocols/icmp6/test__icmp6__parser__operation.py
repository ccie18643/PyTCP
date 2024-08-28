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
Module contains tests for the ICMPv6 packet parser operation.

tests/unit/protocols/icmp6/test__icmp6__parser__operation.py

ver 3.0.1
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import StrictMock, TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.packet import PacketRx
from pytcp.protocols.icmp6.icmp6__parser import Icmp6Parser
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Code, Icmp6Type
from pytcp.protocols.icmp6.message.icmp6_message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6DestinationUnreachableMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_reply import (
    Icmp6EchoReplyCode,
    Icmp6EchoReplyMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__echo_request import (
    Icmp6EchoRequestCode,
    Icmp6EchoRequestMessage,
)
from pytcp.protocols.icmp6.message.icmp6_message__unknown import (
    Icmp6UnknownMessage,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from pytcp.protocols.icmp6.message.mld2.icmp6_mld2_message__report import (
    Icmp6Mld2ReportCode,
    Icmp6Mld2ReportMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_advertisement import (
    Icmp6NdNeighborAdvertisementCode,
    Icmp6NdNeighborAdvertisementMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__neighbor_solicitation import (
    Icmp6NdNeighborSolicitationCode,
    Icmp6NdNeighborSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_advertisement import (
    Icmp6NdRouterAdvertisementCode,
    Icmp6NdRouterAdvertisementMessage,
)
from pytcp.protocols.icmp6.message.nd.icmp6_nd_message__router_solicitation import (
    Icmp6NdRouterSolicitationCode,
    Icmp6NdRouterSolicitationMessage,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_option__slla import (
    Icmp6NdOptionSlla,
)
from pytcp.protocols.icmp6.message.nd.option.icmp6_nd_options import (
    Icmp6NdOptions,
)
from pytcp.protocols.ip6.ip6__parser import Ip6Parser


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Echo Reply message.",
            "_args": {
                "bytes": b"\x81\x00\x7e\xff\x00\x00\x00\x00",
            },
            "_mocked_values": {},
            "_results": {
                "message": Icmp6EchoReplyMessage(
                    code=Icmp6EchoReplyCode.DEFAULT,
                    cksum=32511,
                    id=0,
                    seq=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message.",
            "_args": {
                "bytes": b"\x01\x04\xfe\xfb\x00\x00\x00\x00",
            },
            "_mocked_values": {},
            "_results": {
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=65275,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request message.",
            "_args": {
                "bytes": b"\x80\x00\x7f\xff\x00\x00\x00\x00",
            },
            "_mocked_values": {},
            "_results": {
                "message": Icmp6EchoRequestMessage(
                    code=Icmp6EchoRequestCode.DEFAULT,
                    cksum=32767,
                    id=0,
                    seq=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, single record.",
            "_args": {
                "bytes": (
                    b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                ),
            },
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    code=Icmp6Mld2ReportCode.DEFAULT,
                    cksum=5507,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                                Ip6Address("2001:db8::2"),
                            ],
                            aux_data=b"",
                        ),
                    ],
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, Slla option present.",
            "_args": {
                "bytes": (
                    b"\x88\x00\xa2\xa9\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
            },
            "_mocked_values": {
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
                "ip6__hop": 255,
            },
            "_results": {
                "message": Icmp6NdNeighborAdvertisementMessage(
                    code=Icmp6NdNeighborAdvertisementCode.DEFAULT,
                    cksum=41641,
                    flag_r=False,
                    flag_s=True,
                    flag_o=False,
                    target_address=Ip6Address("2001:db8::2"),
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Solicitation message, Slla option present.",
            "_args": {
                "bytes": (
                    b"\x87\x00\xe3\xa9\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
            },
            "_mocked_values": {
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
                "ip6__hop": 255,
            },
            "_results": {
                "message": Icmp6NdNeighborSolicitationMessage(
                    code=Icmp6NdNeighborSolicitationCode.DEFAULT,
                    cksum=58281,
                    target_address=Ip6Address("2001:db8::2"),
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla option present.",
            "_args": {
                "bytes": (
                    b"\x86\x00\xcd\x0c\x40\x00\x00\x7b\x00\x00\x01\xc8\x00\x00\x03\x15"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
            },
            "_mocked_values": {
                "ip6__src": Ip6Address("fe80::1"),
                "ip6__dst": Ip6Address("2001:db8::2"),
                "ip6__hop": 255,
            },
            "_results": {
                "message": Icmp6NdRouterAdvertisementMessage(
                    code=Icmp6NdRouterAdvertisementCode.DEFAULT,
                    cksum=52492,
                    hop=64,
                    flag_m=False,
                    flag_o=False,
                    router_lifetime=123,
                    reachable_time=456,
                    retrans_timer=789,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Solicitation message, Slla option present.",
            "_args": {
                "bytes": (
                    b"\x85\x00\x13\x65\x00\x00\x00\x00\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
            },
            "_mocked_values": {
                "ip6__src": Ip6Address("2001:db8::1"),
                "ip6__dst": Ip6Address("ff02::2"),
                "ip6__hop": 255,
            },
            "_results": {
                "message": Icmp6NdRouterSolicitationMessage(
                    code=Icmp6NdRouterSolicitationCode.DEFAULT,
                    cksum=4965,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 unknown message.",
            "_args": {
                "bytes": b"\xff\xff\x00\x00",
            },
            "_mocked_values": {},
            "_results": {
                "message": Icmp6UnknownMessage(
                    type=Icmp6Type.from_int(255),
                    code=Icmp6Code.from_int(255),
                    cksum=0,
                    raw=b"",
                ),
            },
        },
    ]
)
class TestIcmp6ParserOperation(TestCase):
    """
    The ICMPv6 packet parser operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp6__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 packet parser creates the proper header and payload
        objects and also updates the appropriate 'tx_packet' object fields.
        """

        packet_rx = PacketRx(self._args["bytes"])

        packet_rx.ip6 = cast(Ip6Parser, StrictMock(template=Ip6Parser))
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="dlen",
            new_value=len(self._args["bytes"]),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="pshdr_sum",
            new_value=self._mocked_values.get("ip6__pshdr_sum", 0),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="src",
            new_value=self._mocked_values.get("ip6__src", Ip6Address()),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="dst",
            new_value=self._mocked_values.get("ip6__dst", Ip6Address()),
        )
        self.patch_attribute(
            target=packet_rx.ip6,
            attribute="hop",
            new_value=self._mocked_values.get("ip6__hop", 64),
        )

        icmp6_parser = Icmp6Parser(packet_rx=packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )

        self.assertIs(
            packet_rx.icmp6,
            icmp6_parser,
        )

        self.assertEqual(
            bytes(packet_rx.frame),
            b"",
        )
