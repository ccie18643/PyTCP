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
Module contains operation tests for the DHCPv6 packet assembler.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__assembler__operation.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from net_proto import (
    Dhcp6Assembler,
    Dhcp6Header,
    Dhcp6MessageType,
    Dhcp6OptionClientId,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionRapidCommit,
    Dhcp6Options,
)
from net_proto.lib.tracker import Tracker

_CLIENT_DUID = b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\x07"


class TestDhcp6AssemblerOperation(TestCase):
    """
    The DHCPv6 packet assembler operation tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 SOLICIT assembler.
        """

        self._options = Dhcp6Options(
            Dhcp6OptionClientId(_CLIENT_DUID),
            Dhcp6OptionElapsedTime(0),
            Dhcp6OptionRapidCommit(),
        )
        self._assembler = Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.SOLICIT,
            dhcp6__xid=0xAABBCC,
            dhcp6__options=self._options,
        )

    def test__dhcp6__assembler__msg_type(self) -> None:
        """
        Ensure the assembled header carries the SOLICIT message type.

        Reference: RFC 8415 §16.2 (Solicit message).
        """

        self.assertIs(self._assembler.msg_type, Dhcp6MessageType.SOLICIT, msg="Unexpected msg_type.")

    def test__dhcp6__assembler__xid(self) -> None:
        """
        Ensure the assembled header carries the transaction-id.

        Reference: RFC 8415 §8 (transaction-id field).
        """

        self.assertEqual(self._assembler.xid, 0xAABBCC, msg="Unexpected xid.")

    def test__dhcp6__assembler__header(self) -> None:
        """
        Ensure the assembled header matches the provided fields.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            self._assembler.header,
            Dhcp6Header(msg_type=Dhcp6MessageType.SOLICIT, xid=0xAABBCC),
            msg="Unexpected header.",
        )

    def test__dhcp6__assembler__options(self) -> None:
        """
        Ensure the assembled options are the ones provided.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(self._assembler.options, self._options, msg="Unexpected options.")

    def test__dhcp6__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns the 4-byte header plus the options block.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        # header(4) + client-id(14) + elapsed-time(6) + rapid-commit(4) = 28
        self.assertEqual(len(self._assembler), 28, msg="Unexpected assembled packet length.")

    def test__dhcp6__assembler__str(self) -> None:
        """
        Ensure '__str__()' renders the message-type, xid, and options.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            str(self._assembler),
            "DHCPv6 Solicit, xid 0xaabbcc, opts " "[client_id 00030001020000000007, elapsed_time 0, rapid_commit]",
            msg="Unexpected log string.",
        )

    def test__dhcp6__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass-style header and options.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            repr(self._assembler),
            f"Dhcp6Assembler(header={self._assembler.header!r}, options={self._assembler.options!r})",
            msg="Unexpected repr string.",
        )

    def test__dhcp6__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the header followed by the options block.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            bytes(self._assembler),
            b"\x01\xaa\xbb\xcc" + bytes(self._options),
            msg="Unexpected wire image.",
        )

    def test__dhcp6__assembler__tracker(self) -> None:
        """
        Ensure the assembler builds a TX-prefixed tracker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIn("TX", str(self._assembler.tracker), msg="Tracker must carry the 'TX' prefix.")


class TestDhcp6AssemblerMisc(TestCase):
    """
    The DHCPv6 packet assembler miscellaneous tests.
    """

    def test__dhcp6__assembler__defaults(self) -> None:
        """
        Ensure constructing with no options yields an empty options block.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        assembler = Dhcp6Assembler(dhcp6__msg_type=Dhcp6MessageType.SOLICIT, dhcp6__xid=1)

        self.assertEqual(len(assembler), 4, msg="A no-option assembler must be 4 bytes.")
        self.assertFalse(assembler.options, msg="A no-option assembler must carry no options.")

    def test__dhcp6__assembler__echo_tracker(self) -> None:
        """
        Ensure the assembler chains a provided echo tracker.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        echo = Tracker(prefix="RX")
        assembler = Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.SOLICIT,
            dhcp6__xid=1,
            echo_tracker=echo,
        )

        self.assertIs(assembler.tracker.echo_tracker, echo, msg="The assembler must chain the echo tracker.")

    def test__dhcp6__assembler__assemble_not_implemented(self) -> None:
        """
        Ensure 'assemble()' raises NotImplementedError — DHCPv6 is an L7
        protocol carried over UDP via the socket layer.

        Reference: RFC 8415 §7 (DHCP is a UDP-based application protocol).
        """

        assembler = Dhcp6Assembler(dhcp6__msg_type=Dhcp6MessageType.SOLICIT, dhcp6__xid=1)

        with self.assertRaises(NotImplementedError):
            assembler.assemble([])
