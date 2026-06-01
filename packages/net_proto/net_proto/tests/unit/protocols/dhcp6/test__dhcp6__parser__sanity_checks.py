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
Module contains sanity-check tests for the DHCPv6 packet parser.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__parser__sanity_checks.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto import Dhcp6MessageType, Dhcp6Parser, Dhcp6SanityError


class TestDhcp6ParserSanityChecks(TestCase):
    """
    The DHCPv6 packet parser sanity-check tests.
    """

    def test__dhcp6__parser__sanity__unknown_msg_type(self) -> None:
        """
        Ensure an unknown message type is rejected after parsing.

        Reference: RFC 8415 §7.3 (DHCP message types).
        """

        with self.assertRaises(Dhcp6SanityError) as error:
            Dhcp6Parser(memoryview(b"\xfe\x00\x00\x01"))

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][DHCPv6] The 'msg_type' field value must be one of "
            f"{Dhcp6MessageType.get_known_values()}. Got: 254.",
            msg="Unexpected unknown-msg-type sanity error message.",
        )

    def test__dhcp6__parser__sanity__relay_forw(self) -> None:
        """
        Ensure a Relay-forward message is rejected by the client/server parser.

        Reference: RFC 8415 §9 (Relay Agent/Server Message Formats).
        """

        with self.assertRaises(Dhcp6SanityError) as error:
            Dhcp6Parser(memoryview(b"\x0c\x00\x00\x01"))

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][DHCPv6] DHCPv6 relay messages (RELAY-FORW / RELAY-REPL) use the "
            "relay-agent/server message format (RFC 8415 §9), not the client/server format. "
            "Got: Relay-Forward.",
            msg="Unexpected relay-forward sanity error message.",
        )

    def test__dhcp6__parser__sanity__relay_repl(self) -> None:
        """
        Ensure a Relay-reply message is rejected by the client/server parser.

        Reference: RFC 8415 §9 (Relay Agent/Server Message Formats).
        """

        with self.assertRaises(Dhcp6SanityError) as error:
            Dhcp6Parser(memoryview(b"\x0d\x00\x00\x01"))

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][DHCPv6] DHCPv6 relay messages (RELAY-FORW / RELAY-REPL) use the "
            "relay-agent/server message format (RFC 8415 §9), not the client/server format. "
            "Got: Relay-Reply.",
            msg="Unexpected relay-reply sanity error message.",
        )
