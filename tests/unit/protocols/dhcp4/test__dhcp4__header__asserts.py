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
This module contains tests for the DHCPv4 header fields asserts.

tests/unit/protocols/arp/test__dhcp4__header__asserts.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.lib.net_addr import Ip4Address, MacAddress
from pytcp.protocols.dhcp4.dhcp4__enums import Dhcp4Operation
from pytcp.protocols.dhcp4.dhcp4__header import Dhcp4Header


class TestDhcp4HeaderAsserts(TestCase):
    """
    The DHCPv4 header fields asserts tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ARP header constructor.
        """

        self._header_kwargs = {
            "oper": Dhcp4Operation.REQUEST,
            "hops": 0,
            "xid": 0x12345678,
            "secs": 0,
            "flag_b": 0,
            "ciaddr": Ip4Address(),
            "yiaddr": Ip4Address(),
            "siaddr": Ip4Address(),
            "giaddr": Ip4Address(),
            "chaddr": MacAddress(),
            "sname": "",
            "file": "",
        }

    def test__dhcp4__header__oper__not_Dhcp4Operation(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'oper' argument is not a Dhcp4Operation.
        """

        self._header_kwargs["oper"] = value = "not a Dhcp4Operation"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._header_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'oper' field must be a Dhcp4Operation. Got: {type(value)!r}",
        )

    '''
    def test__arp__header__spa__not_Ip4Address(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'sha' argument is not an Ip4Address.
        """

        self._header_kwargs["spa"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'spa' field must be an Ip4Address. Got: {type(value)!r}",
        )

    def test__arp__header__tha__not_MacAddress(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'tha' argument is not a MacAddress.
        """

        self._header_kwargs["tha"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'tha' field must be a MacAddress. Got: {type(value)!r}",
        )

    def test__arp__header__tpa__not_Ip4Address(self) -> None:
        """
        Ensure the ARP header constructor raises an exception when the provided
        'tha' argument is not a Ip4Address.
        """

        self._header_kwargs["tpa"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            ArpHeader(**self._header_kwargs)  # type: ignore

        self.assertEqual(
            str(error.exception),
            f"The 'tpa' field must be an Ip4Address. Got: {type(value)!r}",
        )
    '''
