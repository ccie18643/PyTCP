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
Module contains constructor-assert tests for the DHCPv6 packet assembler.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__assembler__asserts.py

ver 3.0.10
"""

from unittest import TestCase

from net_proto import Dhcp6Assembler, Dhcp6MessageType


class TestDhcp6AssemblerAsserts(TestCase):
    """
    The DHCPv6 packet assembler constructor assert tests.
    """

    def test__dhcp6__assembler__defaults_accepted(self) -> None:
        """
        Ensure the assembler constructor accepts a minimal valid message type.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        assembler = Dhcp6Assembler(dhcp6__msg_type=Dhcp6MessageType.SOLICIT, dhcp6__xid=1)

        self.assertIs(assembler.msg_type, Dhcp6MessageType.SOLICIT, msg="A valid message type must be accepted.")

    def test__dhcp6__assembler__msg_type_unknown(self) -> None:
        """
        Ensure the assembler refuses to emit an unknown message type.

        Reference: RFC 8415 §7.3 (DHCP message types).
        """

        value = Dhcp6MessageType.from_int(254)

        with self.assertRaises(AssertionError) as error:
            Dhcp6Assembler(dhcp6__msg_type=value, dhcp6__xid=1)

        self.assertEqual(
            str(error.exception),
            f"The 'dhcp6__msg_type' field must be a known Dhcp6MessageType member. Got: {value!r}",
            msg="Unexpected unknown-msg-type assert message.",
        )

    def test__dhcp6__assembler__msg_type_relay_forw(self) -> None:
        """
        Ensure the assembler refuses to build a Relay-forward message.

        Reference: RFC 8415 §9 (Relay Agent/Server Message Formats).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6Assembler(dhcp6__msg_type=Dhcp6MessageType.RELAY_FORW, dhcp6__xid=1)

        self.assertEqual(
            str(error.exception),
            "The 'dhcp6__msg_type' field must be a client/server message type, not a relay "
            f"message (RFC 8415 §9). Got: {Dhcp6MessageType.RELAY_FORW!r}",
            msg="Unexpected relay-forward assert message.",
        )

    def test__dhcp6__assembler__msg_type_relay_repl(self) -> None:
        """
        Ensure the assembler refuses to build a Relay-reply message.

        Reference: RFC 8415 §9 (Relay Agent/Server Message Formats).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6Assembler(dhcp6__msg_type=Dhcp6MessageType.RELAY_REPL, dhcp6__xid=1)

        self.assertEqual(
            str(error.exception),
            "The 'dhcp6__msg_type' field must be a client/server message type, not a relay "
            f"message (RFC 8415 §9). Got: {Dhcp6MessageType.RELAY_REPL!r}",
            msg="Unexpected relay-reply assert message.",
        )
