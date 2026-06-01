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
Module contains tests for the ICMPv6 ND Neighbor Advertisement message
assembler.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_advertisement__assembler.py

ver 3.0.8
"""

from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address, MacAddress
from net_proto import (
    ICMP6__ND__NEIGHBOR_ADVERTISEMENT__LEN,
    Icmp6Assembler,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdNeighborAdvertisementCode,
    Icmp6NdOptions,
    Icmp6NdOptionSlla,
    Icmp6Type,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, no options.",
            "_kwargs": {
                "flag_r": True,
                "flag_s": False,
                "flag_o": True,
                "target_address": Ip6Address("2001:db8::1"),
                "options": Icmp6NdOptions(),
            },
            "_results": {
                "__len__": 24,
                "__str__": ("ICMPv6 ND Neighbor Advertisement, flags R-O, target 2001:db8::1, len 24 (24+0)"),
                "__repr__": (
                    "Icmp6NdMessageNeighborAdvertisement("
                    "code=<Icmp6NdNeighborAdvertisementCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "options=Icmp6NdOptions(options=[]), "
                    "flag_r=True, "
                    "flag_s=False, "
                    "flag_o=True, "
                    "target_address=Ip6Address('2001:db8::1'))"
                ),
                "__bytes__": (
                    # ICMPv6 Neighbor Advertisement
                    #   Type     : 136 (Neighbor Advertisement)
                    #   Code     : 0
                    #   Checksum : 0xaa44 (back-patched by Icmp6Assembler)
                    #   Flags    : 0xa0 (R=1, S=0, O=1)
                    #   Reserved : 0x000000
                    #   Target   : 2001:db8::1
                    #   Options  : none
                    b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x01"
                ),
                "type": Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
                "code": Icmp6NdNeighborAdvertisementCode.DEFAULT,
                "cksum": 0,
                "flag_r": True,
                "flag_s": False,
                "flag_o": True,
                "target_address": Ip6Address("2001:db8::1"),
                "options": Icmp6NdOptions(),
            },
        },
        {
            "_description": "ICMPv6 ND Neighbor Advertisement message, Slla option present.",
            "_kwargs": {
                "flag_r": False,
                "flag_s": True,
                "flag_o": False,
                "target_address": Ip6Address("2001:db8::2"),
                "options": Icmp6NdOptions(Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))),
            },
            "_results": {
                "__len__": 32,
                "__str__": (
                    "ICMPv6 ND Neighbor Advertisement, flags -S-, target 2001:db8::2, "
                    "opts [slla 00:11:22:33:44:55], len 32 (24+8)"
                ),
                "__repr__": (
                    "Icmp6NdMessageNeighborAdvertisement("
                    "code=<Icmp6NdNeighborAdvertisementCode.DEFAULT: 0>, "
                    "cksum=0, "
                    "options=Icmp6NdOptions(options=["
                    "Icmp6NdOptionSlla(slla=MacAddress('00:11:22:33:44:55'))"
                    "]), "
                    "flag_r=False, "
                    "flag_s=True, "
                    "flag_o=False, "
                    "target_address=Ip6Address('2001:db8::2'))"
                ),
                "__bytes__": (
                    # ICMPv6 Neighbor Advertisement
                    #   Type     : 136 (Neighbor Advertisement)
                    #   Code     : 0
                    #   Checksum : 0xa2a9 (back-patched by Icmp6Assembler)
                    #   Flags    : 0x40 (R=0, S=1, O=0)
                    #   Reserved : 0x000000
                    #   Target   : 2001:db8::2
                    #   Options  : Type 1 (Source Link-Layer Address) = 00:11:22:33:44:55
                    b"\x88\x00\xa2\xa9\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
                ),
                "type": Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT,
                "code": Icmp6NdNeighborAdvertisementCode.DEFAULT,
                "cksum": 0,
                "flag_r": False,
                "flag_s": True,
                "flag_o": False,
                "target_address": Ip6Address("2001:db8::2"),
                "options": Icmp6NdOptions(Icmp6NdOptionSlla(slla=MacAddress("00:11:22:33:44:55"))),
            },
        },
    ]
)
class TestIcmp6NdMessageNeighborAdvertisementAssembler(TestCase):
    """
    The ICMPv6 ND Neighbor Advertisement message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the ICMPv6 assembler wrapping a Neighbor Advertisement message
        configured from the parametrized kwargs.
        """

        self._icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6NdMessageNeighborAdvertisement(**self._kwargs),
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            len(self._icmp6__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            str(self._icmp6__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            repr(self._icmp6__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire bytes with a
        back-patched checksum.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            bytes(self._icmp6__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__type(self) -> None:
        """
        Ensure the assembled message carries type
        Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            self._icmp6__assembler.message.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__code(self) -> None:
        """
        Ensure the assembled message carries the expected 'code' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            self._icmp6__assembler.message.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__cksum(self) -> None:
        """
        Ensure the assembled message's 'cksum' field reflects the value
        passed at construction (the back-patch happens on the buffer, not
        on the dataclass).

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            self._icmp6__assembler.message.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__flag_r(self) -> None:
        """
        Ensure the assembled message carries the expected 'flag_r' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            cast(Icmp6NdMessageNeighborAdvertisement, self._icmp6__assembler.message).flag_r,
            self._results["flag_r"],
            msg=f"Unexpected 'flag_r' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__flag_s(self) -> None:
        """
        Ensure the assembled message carries the expected 'flag_s' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            cast(Icmp6NdMessageNeighborAdvertisement, self._icmp6__assembler.message).flag_s,
            self._results["flag_s"],
            msg=f"Unexpected 'flag_s' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__flag_o(self) -> None:
        """
        Ensure the assembled message carries the expected 'flag_o' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            cast(Icmp6NdMessageNeighborAdvertisement, self._icmp6__assembler.message).flag_o,
            self._results["flag_o"],
            msg=f"Unexpected 'flag_o' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__target_address(self) -> None:
        """
        Ensure the assembled message carries the expected 'target_address' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            cast(Icmp6NdMessageNeighborAdvertisement, self._icmp6__assembler.message).target_address,
            self._results["target_address"],
            msg=f"Unexpected 'target_address' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__options(self) -> None:
        """
        Ensure the assembled message carries the expected 'options' value.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        self.assertEqual(
            cast(Icmp6NdMessageNeighborAdvertisement, self._icmp6__assembler.message).options,
            self._results["options"],
            msg=f"Unexpected 'options' for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends the Neighbor Advertisement wire bytes
        (header + options) to the provided buffer list.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        buffers: list[Buffer] = []

        self._icmp6__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"assemble() output mismatch for case: {self._description}",
        )

    def test__icmp6__nd__message__neighbor_advertisement__assembler__assemble_buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly two buffers (fixed header +
        options payload) so Icmp6Assembler can back-patch the checksum at
        buffers[-2][2:4].

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
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
            ICMP6__ND__NEIGHBOR_ADVERTISEMENT__LEN,
            msg=f"First buffer must be the 24-byte fixed header for case: {self._description}",
        )
