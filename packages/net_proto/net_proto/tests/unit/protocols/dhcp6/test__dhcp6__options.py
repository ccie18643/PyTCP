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
Module contains tests for the DHCPv6 packet options container.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__options.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Dhcp6IntegrityError,
    Dhcp6OptionClientId,
    Dhcp6OptionDnsServers,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionIaAddr,
    Dhcp6OptionIaNa,
    Dhcp6OptionOro,
    Dhcp6OptionRapidCommit,
    Dhcp6Options,
    Dhcp6OptionServerId,
    Dhcp6OptionStatusCode,
    Dhcp6OptionType,
    Dhcp6OptionUnknown,
    Dhcp6StatusCode,
)

_CLIENT_DUID = b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\x07"
_SERVER_DUID = b"\x00\x03\x00\x01\x02\x00\x00\x00\x00\x09"


def _populated() -> Dhcp6Options:
    """
    Build a DHCPv6 options container carrying one of every modelled option.
    """

    return Dhcp6Options(
        Dhcp6OptionClientId(_CLIENT_DUID),
        Dhcp6OptionServerId(_SERVER_DUID),
        Dhcp6OptionElapsedTime(1234),
        Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        Dhcp6OptionRapidCommit(),
        Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS, "ok"),
        Dhcp6OptionIaNa(iaid=1, t1=1800, t2=2880),
        Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::100"), preferred_lifetime=3600, valid_lifetime=7200),
        Dhcp6OptionDnsServers([Ip6Address("2001:db8::1")]),
    )


class TestDhcp6OptionsLookupsPresent(TestCase):
    """
    The DHCPv6 options container lookup-property tests (options present).
    """

    def setUp(self) -> None:
        """
        Build a fully-populated DHCPv6 options container.
        """

        self._options = _populated()

    def test__dhcp6__options__client_id(self) -> None:
        """
        Ensure 'client_id' returns the Client Identifier DUID bytes.

        Reference: RFC 8415 §21.2 (Client Identifier option).
        """

        self.assertEqual(self._options.client_id, _CLIENT_DUID, msg="Unexpected client_id.")

    def test__dhcp6__options__server_id(self) -> None:
        """
        Ensure 'server_id' returns the Server Identifier DUID bytes.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertEqual(self._options.server_id, _SERVER_DUID, msg="Unexpected server_id.")

    def test__dhcp6__options__elapsed_time(self) -> None:
        """
        Ensure 'elapsed_time' returns the Elapsed Time value.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertEqual(self._options.elapsed_time, 1234, msg="Unexpected elapsed_time.")

    def test__dhcp6__options__oro(self) -> None:
        """
        Ensure 'oro' returns the requested option-code list.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertEqual(self._options.oro, [Dhcp6OptionType.DNS_SERVERS], msg="Unexpected oro.")

    def test__dhcp6__options__rapid_commit(self) -> None:
        """
        Ensure 'rapid_commit' returns True when the option is present.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertTrue(self._options.rapid_commit, msg="rapid_commit must be True when present.")

    def test__dhcp6__options__status_code(self) -> None:
        """
        Ensure 'status_code' returns the Status Code option object.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertEqual(
            self._options.status_code,
            Dhcp6OptionStatusCode(Dhcp6StatusCode.SUCCESS, "ok"),
            msg="Unexpected status_code.",
        )

    def test__dhcp6__options__ia_na(self) -> None:
        """
        Ensure 'ia_na' returns the IA_NA option object.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertEqual(
            self._options.ia_na,
            Dhcp6OptionIaNa(iaid=1, t1=1800, t2=2880),
            msg="Unexpected ia_na.",
        )

    def test__dhcp6__options__ia_addr(self) -> None:
        """
        Ensure 'ia_addr' returns the IA Address option object.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertEqual(
            self._options.ia_addr,
            Dhcp6OptionIaAddr(address=Ip6Address("2001:db8::100"), preferred_lifetime=3600, valid_lifetime=7200),
            msg="Unexpected ia_addr.",
        )

    def test__dhcp6__options__dns_servers(self) -> None:
        """
        Ensure 'dns_servers' returns the DNS server address list.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(self._options.dns_servers, [Ip6Address("2001:db8::1")], msg="Unexpected dns_servers.")


class TestDhcp6OptionsLookupsAbsent(TestCase):
    """
    The DHCPv6 options container lookup-property tests (options absent).
    """

    def setUp(self) -> None:
        """
        Build an empty DHCPv6 options container.
        """

        self._options = Dhcp6Options()

    def test__dhcp6__options__client_id_absent(self) -> None:
        """
        Ensure 'client_id' returns None when the option is absent.

        Reference: RFC 8415 §21.2 (Client Identifier option).
        """

        self.assertIsNone(self._options.client_id, msg="client_id must be None when absent.")

    def test__dhcp6__options__server_id_absent(self) -> None:
        """
        Ensure 'server_id' returns None when the option is absent.

        Reference: RFC 8415 §21.3 (Server Identifier option).
        """

        self.assertIsNone(self._options.server_id, msg="server_id must be None when absent.")

    def test__dhcp6__options__elapsed_time_absent(self) -> None:
        """
        Ensure 'elapsed_time' returns None when the option is absent.

        Reference: RFC 8415 §21.9 (Elapsed Time option).
        """

        self.assertIsNone(self._options.elapsed_time, msg="elapsed_time must be None when absent.")

    def test__dhcp6__options__oro_absent(self) -> None:
        """
        Ensure 'oro' returns None when the option is absent.

        Reference: RFC 8415 §21.7 (Option Request option).
        """

        self.assertIsNone(self._options.oro, msg="oro must be None when absent.")

    def test__dhcp6__options__rapid_commit_absent(self) -> None:
        """
        Ensure 'rapid_commit' returns False when the option is absent.

        Reference: RFC 8415 §21.14 (Rapid Commit option).
        """

        self.assertFalse(self._options.rapid_commit, msg="rapid_commit must be False when absent.")

    def test__dhcp6__options__status_code_absent(self) -> None:
        """
        Ensure 'status_code' returns None when the option is absent.

        Reference: RFC 8415 §21.13 (Status Code option).
        """

        self.assertIsNone(self._options.status_code, msg="status_code must be None when absent.")

    def test__dhcp6__options__ia_na_absent(self) -> None:
        """
        Ensure 'ia_na' returns None when the option is absent.

        Reference: RFC 8415 §21.4 (IA_NA option).
        """

        self.assertIsNone(self._options.ia_na, msg="ia_na must be None when absent.")

    def test__dhcp6__options__ia_addr_absent(self) -> None:
        """
        Ensure 'ia_addr' returns None when the option is absent.

        Reference: RFC 8415 §21.6 (IA Address option).
        """

        self.assertIsNone(self._options.ia_addr, msg="ia_addr must be None when absent.")

    def test__dhcp6__options__dns_servers_absent(self) -> None:
        """
        Ensure 'dns_servers' returns None when the option is absent.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertIsNone(self._options.dns_servers, msg="dns_servers must be None when absent.")


class TestDhcp6OptionsParser(TestCase):
    """
    The DHCPv6 options container parser tests.
    """

    def test__dhcp6__options__from_buffer_roundtrip(self) -> None:
        """
        Ensure a fully-populated options block roundtrips through
        bytes()/from_buffer().

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        options = _populated()

        self.assertEqual(
            Dhcp6Options.from_buffer(bytes(options)),
            options,
            msg="Options block roundtrip must preserve equality.",
        )

    def test__dhcp6__options__from_buffer_empty(self) -> None:
        """
        Ensure an empty options block parses to an empty container.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        self.assertEqual(
            Dhcp6Options.from_buffer(b""),
            Dhcp6Options(),
            msg="An empty options block must parse to an empty container.",
        )

    def test__dhcp6__options__from_buffer_unknown(self) -> None:
        """
        Ensure an unrecognised option code parses into a Dhcp6OptionUnknown
        and does not disturb the surrounding options.

        Reference: RFC 8415 §16 (unknown options discarded by the receiver).
        """

        block = bytes(Dhcp6OptionElapsedTime(7)) + b"\xff\xff\x00\x02AB" + bytes(Dhcp6OptionRapidCommit())

        options = Dhcp6Options.from_buffer(block)

        self.assertEqual(options.elapsed_time, 7, msg="Known option before the unknown must parse.")
        self.assertTrue(options.rapid_commit, msg="Known option after the unknown must parse.")
        self.assertIsInstance(options[1], Dhcp6OptionUnknown, msg="The middle option must be Dhcp6OptionUnknown.")


class TestDhcp6OptionsValidateIntegrity(TestCase):
    """
    The DHCPv6 options container integrity-walker tests.
    """

    def test__dhcp6__options__validate_integrity_clean(self) -> None:
        """
        Ensure a well-formed options block passes the integrity walker.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        block = bytes(_populated())

        # Must not raise.
        Dhcp6Options.validate_integrity(frame=block, hlen=len(block), offset=0)

    def test__dhcp6__options__validate_integrity_truncated_header(self) -> None:
        """
        Ensure the integrity walker rejects a trailing fragment shorter than
        the 4-byte option header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6Options.validate_integrity(frame=b"\x00\x01\x00", hlen=3, offset=0)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 option is missing its 4-byte code+len header. "
            "Got: offset=0, hlen=3",
            msg="Unexpected truncated-header integrity error message.",
        )

    def test__dhcp6__options__validate_integrity_overrun_length(self) -> None:
        """
        Ensure the integrity walker rejects an option whose length extends
        past the end of the block.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6Options.validate_integrity(frame=b"\x00\x01\x00\x10\x41\x42", hlen=6, offset=0)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 option length must not extend past the "
            "message length. Got: offset=20, hlen=6",
            msg="Unexpected overrun-length integrity error message.",
        )
