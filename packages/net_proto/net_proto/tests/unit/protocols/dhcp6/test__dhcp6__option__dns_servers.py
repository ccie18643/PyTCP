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
Module contains tests for the DHCPv6 DNS Recursive Name Server option.

net_proto/tests/unit/protocols/dhcp6/test__dhcp6__option__dns_servers.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import override
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Dhcp6IntegrityError,
    Dhcp6OptionDnsServers,
    Dhcp6OptionType,
)


class TestDhcp6OptionDnsServersAsserts(TestCase):
    """
    The DHCPv6 DNS Recursive Name Server option constructor assert tests.
    """

    def test__dhcp6__option__dns_servers__not_list(self) -> None:
        """
        Ensure the constructor raises an exception when 'dns_servers' is not a
        list.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        value = "not a list"

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionDnsServers(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'dns_servers' field must be a list. Got: {type(value)!r}",
            msg="Unexpected not-a-list assert message.",
        )

    def test__dhcp6__option__dns_servers__element_not_ip6(self) -> None:
        """
        Ensure the constructor raises an exception when an element is not an
        Ip6Address.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionDnsServers([Ip6Address("2001:db8::1"), "bad"])  # type: ignore[list-item]

        self.assertEqual(
            str(error.exception),
            "The 'dns_servers' field must be a list of Ip6Address elements. " f"Got: {[Ip6Address, str]!r}",
            msg="Unexpected element-type assert message.",
        )

    def test__dhcp6__option__dns_servers__empty(self) -> None:
        """
        Ensure the constructor raises an exception when 'dns_servers' is empty.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionDnsServers([])

        self.assertEqual(
            str(error.exception),
            "The 'dns_servers' field must carry at least 1 DNS server address (RFC 3646 §3). Got: 0",
            msg="Unexpected empty-list assert message.",
        )


class TestDhcp6OptionDnsServersAssembler(TestCase):
    """
    The DHCPv6 DNS Recursive Name Server option assembler tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a reference DHCPv6 DNS Recursive Name Server option.
        """

        self._servers = [Ip6Address("2001:db8::1"), Ip6Address("2001:db8::2")]
        self._option = Dhcp6OptionDnsServers(self._servers)

    def test__dhcp6__option__dns_servers__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + 16 octets per server.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(len(self._option), 36, msg="Unexpected option length.")

    def test__dhcp6__option__dns_servers__str(self) -> None:
        """
        Ensure '__str__()' renders the server addresses.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(
            str(self._option),
            "dns_servers ['2001:db8::1', '2001:db8::2']",
            msg="Unexpected log string.",
        )

    def test__dhcp6__option__dns_servers__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        DHCPv6 DNS Recursive Name Server option [RFC 3646]:
          option-code : 0x0017 (OPTION_DNS_SERVERS)
          option-len  : 0x0020 (32, two 16-octet addresses)
          servers     : 2001:db8::1, 2001:db8::2

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(
            bytes(self._option),
            b"\x00\x17\x00\x20" + bytes(Ip6Address("2001:db8::1")) + bytes(Ip6Address("2001:db8::2")),
            msg="Unexpected wire image.",
        )

    def test__dhcp6__option__dns_servers__type(self) -> None:
        """
        Ensure the 'type' field is OPTION_DNS_SERVERS.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertIs(self._option.type, Dhcp6OptionType.DNS_SERVERS, msg="Unexpected option type.")

    def test__dhcp6__option__dns_servers__field(self) -> None:
        """
        Ensure the 'dns_servers' field reflects the constructor argument.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(self._option.dns_servers, self._servers, msg="Unexpected dns_servers.")

    def test__dhcp6__option__dns_servers__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option, ignoring
        trailing bytes.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(
            Dhcp6OptionDnsServers.from_buffer(bytes(self._option) + b"TRAIL"),
            self._option,
            msg="Roundtrip must preserve equality.",
        )


class TestDhcp6OptionDnsServersParserErrors(TestCase):
    """
    The DHCPv6 DNS Recursive Name Server option parser error tests.
    """

    def test__dhcp6__option__dns_servers__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        4-byte code+len header.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionDnsServers.from_buffer(b"\x00\x17\x00")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv6 DNS Recursive Name Server option must be 4 bytes. Got: 3",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp6__option__dns_servers__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option code is not
        OPTION_DNS_SERVERS.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp6OptionDnsServers.from_buffer(b"\x00\x06\x00\x02\x00\x17")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv6 DNS Recursive Name Server option type must be {Dhcp6OptionType.DNS_SERVERS!r}. "
            f"Got: {Dhcp6OptionType.ORO!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp6__option__dns_servers__short_length(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is below one 16-octet address.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionDnsServers.from_buffer(b"\x00\x17\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 DNS Recursive Name Server option must carry "
            "at least one address (RFC 3646 §3). Got: 8",
            msg="Unexpected short-length integrity error message.",
        )

    def test__dhcp6__option__dns_servers__not_multiple_of_16(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length is not a multiple of 16 octets.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionDnsServers.from_buffer(b"\x00\x17\x00\x14" + b"\x00" * 20)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 DNS Recursive Name Server option length value "
            "(less header) must be a multiple of 16. Got: 4",
            msg="Unexpected not-multiple-of-16 integrity error message.",
        )

    def test__dhcp6__option__dns_servers__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp6IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 8415 §21.1 (DHCPv6 option TLV format).
        """

        with self.assertRaises(Dhcp6IntegrityError) as error:
            Dhcp6OptionDnsServers.from_buffer(b"\x00\x17\x00\x20" + b"\x00" * 16)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv6] The DHCPv6 DNS Recursive Name Server option length value "
            "must be less than or equal to the length of provided bytes (20). Got: 36",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp6OptionDnsServersBehavior(TestCase):
    """
    The DHCPv6 DNS Recursive Name Server option behavioral tests.
    """

    def test__dhcp6__option__dns_servers__equality(self) -> None:
        """
        Ensure two options with equal server lists compare equal.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        self.assertEqual(
            Dhcp6OptionDnsServers([Ip6Address("2001:db8::1")]),
            Dhcp6OptionDnsServers([Ip6Address("2001:db8::1")]),
            msg="Options with identical server lists must compare equal.",
        )

    def test__dhcp6__option__dns_servers__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 3646 §3 (DNS Recursive Name Server option).
        """

        option = Dhcp6OptionDnsServers([Ip6Address("2001:db8::1")])

        with self.assertRaises(FrozenInstanceError):
            option.dns_servers = []  # type: ignore[misc]
