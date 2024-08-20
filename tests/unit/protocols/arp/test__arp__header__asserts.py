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


"""
This module contains tests for the ARP header fields asserts.

tests/unit/protocols/arp/test__arp__header__asserts.py

ver 3.0.0
"""


from testslide import TestCase

from pytcp.lib.ip4_address import Ip4Address
from pytcp.lib.mac_address import MacAddress
from pytcp.protocols.arp.arp__enums import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__PROTOCOL_LEN__IP4,
    ArpHardwareType,
    ArpOperation,
    ArpProtocolType,
)
from pytcp.protocols.arp.arp__header import ArpHeader


class TestArpHeaderAsserts(TestCase):
    """
    The ARP header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ARP header constructor.
        """

        self._header_args = {
            "hrtype": ArpHardwareType.ETHERNET,
            "prtype": ArpProtocolType.IP4,
            "hrlen": 6,
            "prlen": 4,
            "oper": ArpOperation.REQUEST,
            "sha": MacAddress(0),
            "spa": Ip4Address(0),
            "tha": MacAddress(0),
            "tpa": Ip4Address(0),
        }

    def test__arp__header__hrtype__incorrect(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'hrtype' argument is incorrect.
        """

        self._header_args["hrtype"] = value = ArpHardwareType.from_int(0)

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'hrtype' field must be an ArpHardwareType.ETHERNET. Got: {value!r}",
        )

    def test__arp__header__prtype__incorrect(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'prtype' argument is incorrect.
        """

        self._header_args["prtype"] = value = ArpProtocolType.from_int(0)

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'prtype' field must be an ArpProtocolType.IP4. Got: {value!r}",
        )

    def test__arp__header__hrlen__incorrect(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'hrlen' argument is incorrect.
        """

        for value in range(0, 256):
            if value == ARP__HARDWARE_LEN__ETHERNET:
                continue

            self._header_args["hrlen"] = value

            with self.assertRaises(AssertionError) as error:
                ArpHeader(**self._header_args)  # type: ignore

            self.assertEqual(
                str(error.exception),
                f"The 'hrlen' field must be {ARP__HARDWARE_LEN__ETHERNET}. Got: {value!r}",
            )

    def test__arp__header__prlen__incorrect(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'prlen' argument is incorrect.
        """

        for value in range(0, 256):
            if value == ARP__PROTOCOL_LEN__IP4:
                continue

            self._header_args["prlen"] = value

            with self.assertRaises(AssertionError) as error:
                ArpHeader(**self._header_args)  # type: ignore

            self.assertEqual(
                str(error.exception),
                f"The 'prlen' field must be {ARP__PROTOCOL_LEN__IP4}. Got: {value!r}",
            )

    def test__arp__header__sha__not_MacAddress(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'sha' argument is not a MacAddress.
        """

        self._header_args["sha"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'sha' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__arp__header__spa__not_Ip4Address(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'sha' argument is not an Ip4Address.
        """

        self._header_args["spa"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'spa' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__arp__header__tha__not_MacAddress(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'tha' argument is not a MacAddress.
        """

        self._header_args["tha"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'tha' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__arp__header__tpa__not_Ip4Address(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'tha' argument is not a Ip4Address.
        """

        self._header_args["tpa"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_args)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'tpa' field must be an Ip4Address. Got: {type(value)!r}",
        )
