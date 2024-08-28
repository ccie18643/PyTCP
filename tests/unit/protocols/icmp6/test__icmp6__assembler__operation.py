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
Module contains tests for the ICMPv6 packet assembler operation.

tests/unit/protocols/icmp6/test__icmp6__assembler__operation.py

ver 3.0.1
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from pytcp.lib.ip6_address import Ip6Address
from pytcp.lib.mac_address import MacAddress
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.icmp6__assembler import Icmp6Assembler
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


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Echo Reply message.",
            "_args": {
                "icmp6__message": Icmp6EchoReplyMessage(),
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Echo Reply, id 0, seq 0, len 8 (8+0)",
                "__repr__": (
                    "Icmp6EchoReplyMessage(code=<Icmp6EchoReplyCode.DEFAULT: 0>, "
                    "cksum=0, id=0, seq=0, data=b'')"
                ),
                "__bytes__": b"\x81\x00\x7e\xff\x00\x00\x00\x00",
                "message": Icmp6EchoReplyMessage(
                    code=Icmp6EchoReplyCode.DEFAULT,
                    cksum=0,
                    id=0,
                    seq=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message.",
            "_args": {
                "icmp6__message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                ),
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Destination Unreachable - Port, len 8 (8+0)",
                "__repr__": (
                    "Icmp6DestinationUnreachableMessage(code=<Icmp6DestinationUnreachableCode"
                    ".PORT: 4>, cksum=0, data=b'')"
                ),
                "__bytes__": b"\x01\x04\xfe\xfb\x00\x00\x00\x00",
                "message": Icmp6DestinationUnreachableMessage(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Echo Request message.",
            "_args": {
                "icmp6__message": Icmp6EchoRequestMessage(),
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv6 Echo Request, id 0, seq 0, len 8 (8+0)",
                "__repr__": (
                    "Icmp6EchoRequestMessage(code=<Icmp6EchoRequestCode.DEFAULT: 0>, "
                    "cksum=0, id=0, seq=0, data=b'')"
                ),
                "__bytes__": b"\x80\x00\x7f\xff\x00\x00\x00\x00",
                "message": Icmp6EchoRequestMessage(
                    code=Icmp6EchoRequestCode.DEFAULT,
                    cksum=0,
                    id=0,
                    seq=0,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, single record.",
            "_args": {
                "icmp6__message": Icmp6Mld2ReportMessage(
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                                Ip6Address("2001:db8::2"),
                            ],
                        ),
                    ],
                ),
            },
            "_results": {
                "__len__": 60,
                "__str__": (
                    "ICMPv6 MLDv2 Report, records "
                    "[type 'Mode Is Include', addr ff02::1, sources (2001:db8::1, 2001:db8::2)]"
                ),
                "__repr__": (
                    "Icmp6Mld2ReportMessage(code=<Icmp6Mld2ReportCode.DEFAULT: 0>, "
                    "cksum=0, records=[Icmp6Mld2MulticastAddressRecord("
                    "type=<Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE: 1>, "
                    "multicast_address=Ip6Address('ff02::1'), "
                    "source_addresses=[Ip6Address('2001:db8::1'), "
                    "Ip6Address('2001:db8::2')], aux_data=b'')])"
                ),
                "__bytes__": (
                    b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                ),
                "message": Icmp6Mld2ReportMessage(
                    code=Icmp6Mld2ReportCode.DEFAULT,
                    cksum=0,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                                Ip6Address("2001:db8::2"),
                            ],
                        ),
                    ],
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, Slla option present.",
            "_args": {
                "icmp6__message": Icmp6NdNeighborAdvertisementMessage(
                    flag_r=False,
                    flag_s=True,
                    flag_o=False,
                    target_address=Ip6Address("2001:db8::2"),
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                    ),
                ),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "ICMPv6 ND Neighbor Advertisement, flags -S-, target 2001:db8::2, opts "
                    "[slla 00:11:22:33:44:55], len 32 (24+8)"
                ),
                "__repr__": (
                    "Icmp6NdNeighborAdvertisementMessage(code=<Icmp6NdNeighborAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55'))]), flag_r=False, flag_s=True, flag_o"
                    "=False, target_address=Ip6Address('2001:db8::2'))"
                ),
                "__bytes__": (
                    b"\x88\x00\xa2\xa9\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "message": Icmp6NdNeighborAdvertisementMessage(
                    code=Icmp6NdNeighborAdvertisementCode.DEFAULT,
                    cksum=0,
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
                "icmp6__message": Icmp6NdNeighborSolicitationMessage(
                    target_address=Ip6Address("2001:db8::2"),
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))
                    ),
                ),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "ICMP6 ND Neighbor Solicitation, target 2001:db8::2, opts [slla 00:11:22:33:44:55], "
                    "len 32 (24+8)"
                ),
                "__repr__": (
                    "Icmp6NdNeighborSolicitationMessage(code=<Icmp6NdNeighborSolicitationCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55'))]), target_address=Ip6Address("
                    "'2001:db8::2'))"
                ),
                "__bytes__": (
                    b"\x87\x00\xe3\xa9\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "message": Icmp6NdNeighborSolicitationMessage(
                    code=Icmp6NdNeighborSolicitationCode.DEFAULT,
                    cksum=0,
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
                "icmp6__message": Icmp6NdRouterAdvertisementMessage(
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
            "_results": {
                "__len__": 24,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 64, flags --, rlft 123, reacht 456, "
                    "retrt 789, opts [slla 00:11:22:33:44:55], len 24 (16+8)"
                ),
                "__repr__": (
                    "Icmp6NdRouterAdvertisementMessage(code=<Icmp6NdRouterAdvertisementCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55'))]), hop=64, flag_m=False, flag_o=False, "
                    "router_lifetime=123, reachable_time=456, retrans_timer=789)"
                ),
                "__bytes__": (
                    b"\x86\x00\xcd\x0c\x40\x00\x00\x7b\x00\x00\x01\xc8\x00\x00\x03\x15"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "message": Icmp6NdRouterAdvertisementMessage(
                    code=Icmp6NdRouterAdvertisementCode.DEFAULT,
                    cksum=0,
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
                "icmp6__message": Icmp6NdRouterSolicitationMessage(
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
            "_results": {
                "__len__": 16,
                "__str__": (
                    "ICMPv6 ND Router Solicitation, opts [slla 00:11:22:33:44:55], len 16 (8+8)"
                ),
                "__repr__": (
                    "Icmp6NdRouterSolicitationMessage(code=<Icmp6NdRouterSolicitationCode"
                    ".DEFAULT: 0>, cksum=0, options=Icmp6NdOptions(options=[Icmp6NdOptionSlla("
                    "slla=MacAddress('00:11:22:33:44:55'))]))"
                ),
                "__bytes__": (
                    b"\x85\x00\x13\x65\x00\x00\x00\x00\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "message": Icmp6NdRouterSolicitationMessage(
                    code=Icmp6NdRouterSolicitationCode.DEFAULT,
                    cksum=0,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    ),
                ),
            },
        },
        {
            "_description": "ICMPv6 unknown message.",
            "_args": {
                "icmp6__message": Icmp6UnknownMessage(
                    type=Icmp6Type.from_int(255),
                    code=Icmp6Code.from_int(255),
                ),
            },
            "_results": {
                "__len__": 4,
                "__str__": (
                    "ICMPv6 Unknown Message, type 255, code 255, cksum 0, len 4 (4+0)"
                ),
                "__repr__": (
                    "Icmp6UnknownMessage(type=<Icmp6Type.UNKNOWN_255: 255>, "
                    "code=<Icmp6Code.UNKNOWN_255: 255>, cksum=0, raw=b'')"
                ),
                "__bytes__": b"\xff\xff\x00\x00",
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
class TestIcmp6AssemblerOperation(TestCase):
    """
    The ICMPv6 packet assembler operation tests.
    """

    _description: str
    _args: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv6 packet assembler object with testcase arguments.
        """

        self._icmp6__assembler = Icmp6Assembler(**self._args)

    def test__icmp6__assembler__len(self) -> None:
        """
        Ensure the ICMPv6 packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
        )

    def test__icmp6__assembler__str(self) -> None:
        """
        Ensure the ICMPv6 packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
        )

    def test__icmp6__assembler__repr(self) -> None:
        """
        Ensure the ICMPv6 packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
        )

    def test__icmp6__assembler__bytes(self) -> None:
        """
        Ensure the ICMPv6 packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
        )

    def test__icmp6__assembler__message(self) -> None:
        """
        Ensure the ICMPv6 packet assembler 'message' property returns a correct
        value.
        """

        self.assertEqual(
            self._icmp6__assembler.message,
            self._results["message"],
        )


class TestIcmp6AssemblerMisc(TestCase):
    """
    The ICMPv6 packet assembler miscellaneous functions tests.
    """

    def test__icmp6__assembler__echo_tracker(self) -> None:
        """
        Ensure the ICMPv6 packet assembler 'tracker' property returns
        a correct value.
        """

        echo_tracker = Tracker(prefix="RX")

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6EchoReplyMessage(),
            echo_tracker=echo_tracker,
        )

        self.assertEqual(
            icmp6__assembler.tracker.echo_tracker,
            echo_tracker,
        )
