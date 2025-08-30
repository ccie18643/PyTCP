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
This module contains tests for the ARP protocol packet assembling functionality.

net_addr/tests/unit/protocols/arp/test__arp_assembler__operation.py

ver 3.0.4
"""


from typing import Any

from net_addr import Ip4Address, MacAddress
from net_proto import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__PROTOCOL_LEN__IP4,
    ArpAssembler,
    ArpHardwareType,
    ArpHeader,
    ArpOperation,
    EtherType,
    Tracker,
)
from parameterized import parameterized_class  # type: ignore
from testslide import TestCase


@parameterized_class(
    [
        {
            "_description": "ARP Request.",
            "_args": [],
            "_kwargs": {
                "arp__oper": ArpOperation.REQUEST,
                "arp__sha": MacAddress("01:02:03:04:05:06"),
                "arp__spa": Ip4Address("11.22.33.44"),
                "arp__tha": MacAddress("0a:0b:0c:0d:0e:0f"),
                "arp__tpa": Ip4Address("101.102.103.104"),
            },
            "_results": {
                "__len__": 28,
                "__str__": (
                    "ARP Request 11.22.33.44 / 01:02:03:04:05:06 > "
                    "101.102.103.104 / 0a:0b:0c:0d:0e:0f, len 28"
                ),
                "__repr__": (
                    "ArpAssembler(header=ArpHeader(oper=<ArpOperation.REQUEST: 1>, "
                    "sha=MacAddress('01:02:03:04:05:06'), spa=Ip4Address('11.22.33.44'), "
                    "tha=MacAddress('0a:0b:0c:0d:0e:0f'), tpa=Ip4Address('101.102.103.104')))"
                ),
                "__bytes__": (
                    b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                    b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
                ),
                "hrtype": ArpHardwareType.ETHERNET,
                "prtype": EtherType.IP4,
                "hrlen": ARP__HARDWARE_LEN__ETHERNET,
                "prlen": ARP__PROTOCOL_LEN__IP4,
                "oper": ArpOperation.REQUEST,
                "sha": MacAddress("01:02:03:04:05:06"),
                "spa": Ip4Address("11.22.33.44"),
                "tha": MacAddress("0a:0b:0c:0d:0e:0f"),
                "tpa": Ip4Address("101.102.103.104"),
                "cksum": 0,
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("01:02:03:04:05:06"),
                    spa=Ip4Address("11.22.33.44"),
                    tha=MacAddress("0a:0b:0c:0d:0e:0f"),
                    tpa=Ip4Address("101.102.103.104"),
                ),
            },
        },
        {
            "_description": "ARP Reply.",
            "_args": [],
            "_kwargs": {
                "arp__oper": ArpOperation.REPLY,
                "arp__sha": MacAddress("a1:b2:c3:d4:e5:f6"),
                "arp__spa": Ip4Address("5.5.5.5"),
                "arp__tha": MacAddress("7a:7b:7c:7d:7e:7f"),
                "arp__tpa": Ip4Address("7.7.7.7"),
            },
            "_results": {
                "__len__": 28,
                "__str__": (
                    "ARP Reply 5.5.5.5 / a1:b2:c3:d4:e5:f6 > "
                    "7.7.7.7 / 7a:7b:7c:7d:7e:7f, len 28"
                ),
                "__repr__": (
                    "ArpAssembler(header=ArpHeader(oper=<ArpOperation.REPLY: 2>, "
                    "sha=MacAddress('a1:b2:c3:d4:e5:f6'), spa=Ip4Address('5.5.5.5'), "
                    "tha=MacAddress('7a:7b:7c:7d:7e:7f'), tpa=Ip4Address('7.7.7.7')))"
                ),
                "__bytes__": (
                    b"\x00\x01\x08\x00\x06\x04\x00\x02\xa1\xb2\xc3\xd4\xe5\xf6\x05\x05"
                    b"\x05\x05\x7a\x7b\x7c\x7d\x7e\x7f\x07\x07\x07\x07"
                ),
                "hrtype": ArpHardwareType.ETHERNET,
                "prtype": EtherType.IP4,
                "hrlen": ARP__HARDWARE_LEN__ETHERNET,
                "prlen": ARP__PROTOCOL_LEN__IP4,
                "oper": ArpOperation.REPLY,
                "sha": MacAddress("a1:b2:c3:d4:e5:f6"),
                "spa": Ip4Address("5.5.5.5"),
                "tha": MacAddress("7a:7b:7c:7d:7e:7f"),
                "tpa": Ip4Address("7.7.7.7"),
                "cksum": 0,
                "header": ArpHeader(
                    oper=ArpOperation.REPLY,
                    sha=MacAddress("a1:b2:c3:d4:e5:f6"),
                    spa=Ip4Address("5.5.5.5"),
                    tha=MacAddress("7a:7b:7c:7d:7e:7f"),
                    tpa=Ip4Address("7.7.7.7"),
                ),
            },
        },
    ]
)
class TestArpAssemblerPackets(TestCase):
    """
    The ARP packet assembler operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ARP packet assembler object with testcase arguments.
        """

        self._arp__assembler = ArpAssembler(*self._args, **self._kwargs)

    def test__arp__assembler__len(self) -> None:
        """
        Ensure the ARP packet assembler '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._arp__assembler),
            self._results["__len__"],
        )

    def test__arp__assembler__str(self) -> None:
        """
        Ensure the ARP packet assembler '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._arp__assembler),
            self._results["__str__"],
        )

    def test__arp__assembler__repr(self) -> None:
        """
        Ensure the ARP packet assembler '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._arp__assembler),
            self._results["__repr__"],
        )

    def test__arp__assembler__bytes(self) -> None:
        """
        Ensure the ARP packet assembler '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._arp__assembler),
            self._results["__bytes__"],
        )

    def test__arp__assembler__hrlen(self) -> None:
        """
        Ensure the ARP packet assembler 'hrlen' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.hrlen,
            self._results["hrlen"],
        )

    def test__arp__assembler__prlen(self) -> None:
        """
        Ensure the ARP packet assembler 'prlen' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.prlen,
            self._results["prlen"],
        )

    def test__arp__assembler__oper(self) -> None:
        """
        Ensure the ARP packet assembler 'oper' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.oper,
            self._results["oper"],
        )

    def test__arp__assembler__sha(self) -> None:
        """
        Ensure the ARP packet assembler 'sha' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.sha,
            self._results["sha"],
        )

    def test__arp__assembler__spa(self) -> None:
        """
        Ensure the ARP packet assembler 'spa' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.spa,
            self._results["spa"],
        )

    def test__arp__assembler__tha(self) -> None:
        """
        Ensure the ARP packet assembler 'tha' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.tha,
            self._results["tha"],
        )

    def test__arp__assembler__tpa(self) -> None:
        """
        Ensure the ARP packet assembler 'tpa' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.tpa,
            self._results["tpa"],
        )

    def test__arp__assembler__header(self) -> None:
        """
        Ensure the ARP packet assembler 'header' property returns a correct
        value.
        """

        self.assertEqual(
            self._arp__assembler.header,
            self._results["header"],
        )


class TestArpAssemblerMisc(TestCase):
    """
    The ARP packet assembler miscellaneous functions tests.
    """

    def test__arp__assembler__echo_tracker(self) -> None:
        """
        Ensure the ARP packet assembler 'tracker' property returns
        a correct value.
        """

        echo_tracker = Tracker(prefix="RX")

        arp__assembler = ArpAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            arp__assembler.tracker.echo_tracker,
            echo_tracker,
        )
