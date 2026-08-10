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
Module contains tests for the ICMPv6 ND Router Advertisement message
assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_advertisement__assembler.py

ver 3.0.9
"""

from typing import Any, cast, override
from unittest import TestCase

from net_addr import Buffer, Ip6Network, MacAddress
from net_proto import (
    ICMP6__ND__ROUTER_ADVERTISEMENT__LEN,
    Icmp6Assembler,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptionPi,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6NdRouterAdvertisementCode,
    Icmp6Type,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Router Advertisement message, no options.",
            "_kwargs": {
                "hop": 255,
                "flag_m": True,
                "flag_o": True,
                "router_lifetime": 65535,
                "reachable_time": 4294967295,
                "retrans_timer": 4294967295,
                "options": Icmp6NdOptions(),
            },
            "_results": {
                "__len__": 16,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 255, flags MO, rlft 65535, "
                    "reacht 4294967295, retrt 4294967295, len 16 (16+0)"
                ),
                "__repr__": (
                    "Icmp6NdMessageRouterAdvertisement("
                    "code=<Icmp6NdRouterAdvertisementCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "options=Icmp6NdOptions(options=[]), "
                    "hop=255, "
                    "flag_m=True, "
                    "flag_o=True, "
                    "prf=<Icmp6NdRoutePreference.MEDIUM: 0>, "
                    "router_lifetime=65535, "
                    "reachable_time=4294967295, "
                    "retrans_timer=4294967295)"
                ),
                "__bytes__": (
                    # ICMPv6 Router Advertisement
                    #   Type             : 134 (Router Advertisement)
                    #   Code             : 0
                    #   Checksum         : 0x7a3e (back-patched by Icmp6Assembler)
                    #   Hop Limit        : 255
                    #   Flags            : 0xc0 (M=1, O=1)
                    #   Router Lifetime  : 0xffff
                    #   Reachable Time   : 0xffffffff
                    #   Retrans Timer    : 0xffffffff
                    #   Options          : none
                    b"\x86\x00\x7a\x3e\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                ),
                "type": Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
                "cksum": 0,
                "hop": 255,
                "flag_m": True,
                "flag_o": True,
                "router_lifetime": 65535,
                "reachable_time": 4294967295,
                "retrans_timer": 4294967295,
                "options": Icmp6NdOptions(),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla option present.",
            "_kwargs": {
                "hop": 64,
                "flag_m": False,
                "flag_o": False,
                "router_lifetime": 123,
                "reachable_time": 456,
                "retrans_timer": 789,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                ),
            },
            "_results": {
                "__len__": 24,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 64, flags --, rlft 123, "
                    "reacht 456, retrt 789, opts [slla 00:11:22:33:44:55], "
                    "len 24 (16+8)"
                ),
                "__repr__": (
                    "Icmp6NdMessageRouterAdvertisement("
                    "code=<Icmp6NdRouterAdvertisementCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "options=Icmp6NdOptions(options=["
                    "Icmp6NdOptionSlla(slla=MacAddress('00:11:22:33:44:55'))"
                    "]), "
                    "hop=64, "
                    "flag_m=False, "
                    "flag_o=False, "
                    "prf=<Icmp6NdRoutePreference.MEDIUM: 0>, "
                    "router_lifetime=123, "
                    "reachable_time=456, "
                    "retrans_timer=789)"
                ),
                "__bytes__": (
                    # ICMPv6 Router Advertisement
                    #   Type             : 134
                    #   Code             : 0
                    #   Checksum         : 0xcd0c (back-patched by Icmp6Assembler)
                    #   Hop Limit        : 64
                    #   Flags            : 0x00
                    #   Router Lifetime  : 123
                    #   Reachable Time   : 456
                    #   Retrans Timer    : 789
                    #   Options          : Type 1 (SLLA) = 00:11:22:33:44:55
                    b"\x86\x00\xcd\x0c\x40\x00\x00\x7b\x00\x00\x01\xc8\x00\x00\x03\x15"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "type": Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
                "cksum": 0,
                "hop": 64,
                "flag_m": False,
                "flag_o": False,
                "router_lifetime": 123,
                "reachable_time": 456,
                "retrans_timer": 789,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                ),
            },
        },
        {
            "_description": "ICMPv6 ND Router Advertisement message, Slla & Pi options present.",
            "_kwargs": {
                "hop": 22,
                "flag_m": True,
                "flag_o": False,
                "router_lifetime": 33,
                "reachable_time": 44,
                "retrans_timer": 55,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    Icmp6NdOptionPi(
                        prefix=Ip6Network("2001:db8::/64"),
                        valid_lifetime=123456,
                        preferred_lifetime=654321,
                        flag_l=True,
                        flag_a=True,
                        flag_r=True,
                    ),
                ),
            },
            "_results": {
                "__len__": 56,
                "__str__": (
                    "ICMPv6 ND Router Advertisement, hop 22, flags M-, rlft 33, "
                    "reacht 44, retrt 55, opts [slla 00:11:22:33:44:55, prefix_info "
                    "(prefix 2001:db8::/64, flags LAR, valid_lifetime 123456, "
                    "preferred_lifetime 654321)], len 56 (16+40)"
                ),
                "__repr__": (
                    "Icmp6NdMessageRouterAdvertisement("
                    "code=<Icmp6NdRouterAdvertisementCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "options=Icmp6NdOptions(options=["
                    "Icmp6NdOptionSlla(slla=MacAddress('00:11:22:33:44:55')), "
                    "Icmp6NdOptionPi(flag_l=True, flag_a=True, flag_r=True, "
                    "valid_lifetime=123456, preferred_lifetime=654321, "
                    "prefix=Ip6Network('2001:db8::/64'))"
                    "]), "
                    "hop=22, "
                    "flag_m=True, "
                    "flag_o=False, "
                    "prf=<Icmp6NdRoutePreference.MEDIUM: 0>, "
                    "router_lifetime=33, "
                    "reachable_time=44, "
                    "retrans_timer=55)"
                ),
                "__bytes__": (
                    # ICMPv6 Router Advertisement
                    #   Type             : 134
                    #   Code             : 0
                    #   Checksum         : 0xab86 (back-patched by Icmp6Assembler)
                    #   Hop Limit        : 22
                    #   Flags            : 0x80 (M=1)
                    #   Router Lifetime  : 33
                    #   Reachable Time   : 44
                    #   Retrans Timer    : 55
                    #   Options          : Type 1 (SLLA) = 00:11:22:33:44:55;
                    #                      Type 3 (PI)   prefix=2001:db8::/64,
                    #                                    vlft=123456, plft=654321,
                    #                                    L=1, A=1, R=1
                    b"\x86\x00\xab\x86\x16\x80\x00\x21\x00\x00\x00\x2c\x00\x00\x00\x37"
                    b"\x01\x01\x00\x11\x22\x33\x44\x55\x03\x04\x40\xe0\x00\x01\xe2\x40"
                    b"\x00\x09\xfb\xf1\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00"
                ),
                "type": Icmp6Type.ND__ROUTER_ADVERTISEMENT,
                "code": Icmp6NdRouterAdvertisementCode.DEFAULT,
                "cksum": 0,
                "hop": 22,
                "flag_m": True,
                "flag_o": False,
                "router_lifetime": 33,
                "reachable_time": 44,
                "retrans_timer": 55,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55")),
                    Icmp6NdOptionPi(
                        prefix=Ip6Network("2001:db8::/64"),
                        valid_lifetime=123456,
                        preferred_lifetime=654321,
                        flag_l=True,
                        flag_a=True,
                        flag_r=True,
                    ),
                ),
            },
        },
    ]
)
class TestIcmp6NdMessageRouterAdvertisementAssembler(TestCase):
    """
    The ICMPv6 ND Router Advertisement message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the ICMPv6 assembler wrapping a Router Advertisement message
        configured from the parametrized kwargs.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageRouterAdvertisement(**self._kwargs),
        )

    def test__icmp6__nd__message__router_advertisement__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes with a
        back-patched checksum.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__type(self) -> None:
        """
        Ensure the assembled message carries type
        Icmp6Type.ND__ROUTER_ADVERTISEMENT.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__code(self) -> None:
        """
        Ensure the assembled message carries the expected 'code' value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__cksum(self) -> None:
        """
        Ensure the assembled message's 'cksum' field reflects the value
        passed at construction (the back-patch happens on the buffer, not
        on the dataclass).

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__hop(self) -> None:
        """
        Ensure the assembled message carries the expected 'hop' value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).hop,
            self._results["hop"],
            msg=f"Unexpected 'hop' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__flag_m(self) -> None:
        """
        Ensure the assembled message carries the expected 'flag_m' value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).flag_m,
            self._results["flag_m"],
            msg=f"Unexpected 'flag_m' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__flag_o(self) -> None:
        """
        Ensure the assembled message carries the expected 'flag_o' value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).flag_o,
            self._results["flag_o"],
            msg=f"Unexpected 'flag_o' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__router_lifetime(self) -> None:
        """
        Ensure the assembled message carries the expected 'router_lifetime'
        value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).router_lifetime,
            self._results["router_lifetime"],
            msg=f"Unexpected 'router_lifetime' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__reachable_time(self) -> None:
        """
        Ensure the assembled message carries the expected 'reachable_time'
        value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).reachable_time,
            self._results["reachable_time"],
            msg=f"Unexpected 'reachable_time' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__retrans_timer(self) -> None:
        """
        Ensure the assembled message carries the expected 'retrans_timer'
        value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).retrans_timer,
            self._results["retrans_timer"],
            msg=f"Unexpected 'retrans_timer' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__options(self) -> None:
        """
        Ensure the assembled message carries the expected 'options' value.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        self.assertEqual(
            cast(Icmp6NdMessageRouterAdvertisement, self._icmp6__assembler.message).options,
            self._results["options"],
            msg=f"Unexpected 'options' for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the Router Advertisement wire bytes
        (header + options) to the provided buffer list.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"assemble() output mismatch for case: {self._description}",
        )

    def test__icmp6__nd__message__router_advertisement__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers (fixed header +
        options payload) so Icmp6Assembler can back-patch the checksum at
        buffers[-2][2:4].

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.message.assemble(buffers)

        self.assertEqual(
            len(buffers),
            2,
            msg=f"assemble() must append exactly two buffers for case: {self._description}",
        )
        self.assertEqual(
            len(buffers[0]),
            ICMP6__ND__ROUTER_ADVERTISEMENT__LEN,
            msg=f"First buffer must be the 16-byte fixed header for case: {self._description}",
        )
