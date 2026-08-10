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
This module contains tests for the DHCPv6 protocol enum classes.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__enums.py

ver 3.0.9
"""

from unittest import TestCase

from net_proto import Dhcp6MessageType, Dhcp6StatusCode


class TestDhcp6MessageType(TestCase):
    """
    The DHCPv6 'msg-type' enum string-rendering tests.
    """

    def test__dhcp6__message_type__str__known(self) -> None:
        """
        Ensure each known DHCPv6 message type renders its canonical name.

        Reference: RFC 8415 §7.3 (DHCP message types).
        """

        for member, expected in [
            (Dhcp6MessageType.SOLICIT, "Solicit"),
            (Dhcp6MessageType.ADVERTISE, "Advertise"),
            (Dhcp6MessageType.REQUEST, "Request"),
            (Dhcp6MessageType.CONFIRM, "Confirm"),
            (Dhcp6MessageType.RENEW, "Renew"),
            (Dhcp6MessageType.REBIND, "Rebind"),
            (Dhcp6MessageType.REPLY, "Reply"),
            (Dhcp6MessageType.RELEASE, "Release"),
            (Dhcp6MessageType.DECLINE, "Decline"),
            (Dhcp6MessageType.RECONFIGURE, "Reconfigure"),
            (Dhcp6MessageType.INFORMATION_REQUEST, "Information-Request"),
            (Dhcp6MessageType.RELAY_FORW, "Relay-Forward"),
            (Dhcp6MessageType.RELAY_REPL, "Relay-Reply"),
        ]:
            with self.subTest(member=member):
                self.assertEqual(
                    str(member),
                    expected,
                    msg=f"Unexpected string rendering for {member!r}.",
                )

    def test__dhcp6__message_type__str__unknown(self) -> None:
        """
        Ensure an unknown DHCPv6 message type renders its numeric wire value.

        Reference: RFC 8415 §7.3 (DHCP message types; unknown handling).
        """

        unknown = Dhcp6MessageType.from_int(0xFE)

        self.assertEqual(
            str(unknown),
            "254",
            msg="An unknown DHCPv6 message type must render its numeric value.",
        )


class TestDhcp6StatusCode(TestCase):
    """
    The DHCPv6 Status Code enum string-rendering tests.
    """

    def test__dhcp6__status_code__str__known(self) -> None:
        """
        Ensure each known DHCPv6 status code renders its canonical name.

        Reference: RFC 8415 §21.13 (Status Code option values).
        """

        for member, expected in [
            (Dhcp6StatusCode.SUCCESS, "Success"),
            (Dhcp6StatusCode.UNSPEC_FAIL, "UnspecFail"),
            (Dhcp6StatusCode.NO_ADDRS_AVAIL, "NoAddrsAvail"),
            (Dhcp6StatusCode.NO_BINDING, "NoBinding"),
            (Dhcp6StatusCode.NOT_ON_LINK, "NotOnLink"),
            (Dhcp6StatusCode.USE_MULTICAST, "UseMulticast"),
            (Dhcp6StatusCode.NO_PREFIX_AVAIL, "NoPrefixAvail"),
        ]:
            with self.subTest(member=member):
                self.assertEqual(
                    str(member),
                    expected,
                    msg=f"Unexpected string rendering for {member!r}.",
                )

    def test__dhcp6__status_code__str__unknown(self) -> None:
        """
        Ensure an unknown DHCPv6 status code renders its numeric wire value.

        Reference: RFC 8415 §21.13 (Status Code option values; unknown handling).
        """

        unknown = Dhcp6StatusCode.from_int(99)

        self.assertEqual(
            str(unknown),
            "99",
            msg="An unknown DHCPv6 status code must render its numeric value.",
        )
