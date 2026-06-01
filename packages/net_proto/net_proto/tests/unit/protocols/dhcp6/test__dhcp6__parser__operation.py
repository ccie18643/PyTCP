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
Module contains operation tests for the DHCPv6 packet parser.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__parser__operation.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Dhcp6MessageType,
    Dhcp6OptionDnsServers,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionIaAddr,
    Dhcp6OptionIaNa,
    Dhcp6OptionOro,
    Dhcp6OptionRapidCommit,
    Dhcp6Options,
    Dhcp6OptionStatusCode,
    Dhcp6OptionType,
    Dhcp6Parser,
    Dhcp6StatusCode,
)

# DHCPv6 REPLY (server -> client) wire frame:
#   Bytes 0     : 0x07 -> msg-type = REPLY
#   Bytes 1-3   : 0x112233 -> transaction-id
#   --- Client Identifier option (code 1) ---
#   Bytes 4-5   : 0x0001 -> OPTION_CLIENTID
#   Bytes 6-7   : 0x000a -> option-len = 10
#   Bytes 8-17  : 00 03 00 01 02 00 00 00 00 07 -> DUID-LL
#   --- Server Identifier option (code 2) ---
#   Bytes 18-19 : 0x0002 -> OPTION_SERVERID
#   Bytes 20-21 : 0x000a -> option-len = 10
#   Bytes 22-31 : 00 03 00 01 02 00 00 00 00 09 -> DUID-LL
#   --- Status Code option (code 13) ---
#   Bytes 32-33 : 0x000d -> OPTION_STATUS_CODE
#   Bytes 34-35 : 0x0004 -> option-len = 4
#   Bytes 36-37 : 0x0000 -> status-code = Success
#   Bytes 38-39 : 0x6f6b -> status-message = "ok"
_REPLY_FRAME = (
    b"\x07\x11\x22\x33"
    b"\x00\x01\x00\x0a\x00\x03\x00\x01\x02\x00\x00\x00\x00\x07"
    b"\x00\x02\x00\x0a\x00\x03\x00\x01\x02\x00\x00\x00\x00\x09"
    b"\x00\x0d\x00\x04\x00\x00\x6f\x6b"
)


class TestDhcp6ParserOperation(TestCase):
    """
    The DHCPv6 packet parser operation tests.
    """

    def setUp(self) -> None:
        """
        Parse the reference DHCPv6 REPLY frame.
        """

        self._parser = Dhcp6Parser(memoryview(_REPLY_FRAME))

    def test__dhcp6__parser__msg_type(self) -> None:
        """
        Ensure the parsed header 'msg_type' is REPLY.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertIs(self._parser.msg_type, Dhcp6MessageType.REPLY, msg="Unexpected msg_type.")

    def test__dhcp6__parser__xid(self) -> None:
        """
        Ensure the parsed header 'xid' is the 24-bit transaction-id.

        Reference: RFC 8415 §8 (transaction-id field).
        """

        self.assertEqual(self._parser.xid, 0x112233, msg="Unexpected xid.")

    def test__dhcp6__parser__client_id(self) -> None:
        """
        Ensure the parsed Client Identifier DUID is exposed.

        Reference: RFC 8415 §21.2 (Client Identifier option).
        """

        self.assertEqual(
            self._parser.client_id,
            b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\x07",
            msg="Unexpected client_id.",
        )

    def test__dhcp6__parser__server_id(self) -> None:
        """
        Ensure the parsed Server Identifier DUID is exposed.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(
            self._parser.server_id,
            b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\x09",
            msg="Unexpected server_id.",
        )

    def test__dhcp6__parser__status_code(self) -> None:
        """
        Ensure the parsed Status Code option is exposed.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(
            self._parser.status_code,
            Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS, "ok"),
            msg="Unexpected status_code.",
        )

    def test__dhcp6__parser__len(self) -> None:
        """
        Ensure '__len__()' returns the 4-byte header plus the options block.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(len(self._parser), 40, msg="Unexpected parsed packet length.")

    def test__dhcp6__parser__str(self) -> None:
        """
        Ensure '__str__()' renders the message-type, xid, and options.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            str(self._parser),
            "DHCPv6 Reply, xid 0x112233, opts [client_id 00030001020000000007, "
            "server_id 00030001020000000009, status_code Success (ok)]",
            msg="Unexpected log string.",
        )

    def test__dhcp6__parser__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass-style header and options.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            repr(self._parser),
            f"Dhcp6Parser(header={self._parser.header!r}, options={self._parser.options!r})",
            msg="Unexpected repr string.",
        )

    def test__dhcp6__parser__buffer_roundtrip(self) -> None:
        """
        Ensure the parsed packet reserialises to the original wire frame.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            bytes(memoryview(self._parser)),
            _REPLY_FRAME,
            msg="Reserialised packet must match the original frame.",
        )

    def test__dhcp6__parser__frame(self) -> None:
        """
        Ensure the parser exposes the original received frame.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        self.assertEqual(
            bytes(self._parser.frame),
            _REPLY_FRAME,
            msg="The parser must expose the received frame.",
        )


class TestDhcp6ParserOperationMinimal(TestCase):
    """
    The DHCPv6 packet parser minimal-message tests.
    """

    def test__dhcp6__parser__header_only(self) -> None:
        """
        Ensure a 4-byte header with no options parses with an empty options set.

        Reference: RFC 8415 §8 (Client/Server Message Formats).
        """

        parser = Dhcp6Parser(memoryview(b"\x01\x00\x00\x01"))

        self.assertIs(parser.msg_type, Dhcp6MessageType.SOLICIT, msg="Unexpected msg_type.")
        self.assertEqual(parser.xid, 1, msg="Unexpected xid.")
        self.assertFalse(parser.options, msg="A header-only message must carry no options.")


class TestDhcp6ParserOptionAccessors(TestCase):
    """
    The DHCPv6 parser option-accessor tests.

    Exercises every option lookup through a parsed message so the
    Dhcp6OptionsProperties mixin delegations are covered on the parser
    surface, not only on the bare container.
    """

    def setUp(self) -> None:
        """
        Parse a REPLY frame carrying one of every value-bearing option.
        """

        options = Dhcp6Options(
            Dhcp6OptionElapsedTime(1234),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
            Dhcp6OptionRapidCommit(),
            Dhcp6OptionIaNa(iaid=1, t1=1800, t2=2880),
            Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::100"), preferred_lifetime=3600, valid_lifetime=7200),
            Dhcp6OptionDnsServers([Ip6Address("2001:db8::1")]),
        )
        self._parser = Dhcp6Parser(memoryview(b"\x07\x00\x00\x01" + bytes(options)))

    def test__dhcp6__parser__elapsed_time(self) -> None:
        """
        Ensure the parser exposes the Elapsed Time value.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(self._parser.elapsed_time, 1234, msg="Unexpected elapsed_time.")

    def test__dhcp6__parser__oro(self) -> None:
        """
        Ensure the parser exposes the Option Request list.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(self._parser.oro, [Dhcp6OptionType.DNS_SERVERS], msg="Unexpected oro.")

    def test__dhcp6__parser__rapid_commit(self) -> None:
        """
        Ensure the parser exposes the Rapid Commit presence flag.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertTrue(self._parser.rapid_commit, msg="rapid_commit must be True when present.")

    def test__dhcp6__parser__ia_na(self) -> None:
        """
        Ensure the parser exposes the IA_NA option.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(
            self._parser.ia_na,
            Dhcp6OptionIaNa(iaid=1, t1=1800, t2=2880),
            msg="Unexpected ia_na.",
        )

    def test__dhcp6__parser__ia_addr(self) -> None:
        """
        Ensure the parser exposes the IA Address option.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(
            self._parser.ia_addr,
            Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::100"), preferred_lifetime=3600, valid_lifetime=7200),
            msg="Unexpected ia_addr.",
        )

    def test__dhcp6__parser__dns_servers(self) -> None:
        """
        Ensure the parser exposes the DNS server list.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(self._parser.dns_servers, [Ip6Address("2001:db8::1")], msg="Unexpected dns_servers.")
