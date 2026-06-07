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
This module contains the DHCPv6 DNS Recursive Name Server option support code.

net_proto/protocols/dhcp6/options/dhcp6__option__dns_servers.py

ver 3.0.8
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    DHCP6__OPTION__STRUCT,
    Dhcp6Option,
    Dhcp6OptionType,
)

# The DHCPv6 DNS Recursive Name Server option [RFC 3646 §3].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    OPTION_DNS_SERVERS = 23    |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |            DNS-recursive-name-server (IPv6 address)           |
# |                          (16 octets)                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                              ...                              .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN = 16
DHCP6__OPTION__DNS_SERVERS__ELEMENT__STRUCT = "! 16s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp6OptionDnsServers(Dhcp6Option):
    """
    The DHCPv6 DNS Recursive Name Server option support class.
    """

    type: Dhcp6OptionType = field(
        repr=False,
        init=False,
        default=Dhcp6OptionType.DNS_SERVERS,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    dns_servers: list[Ip6Address]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the DHCPv6 DNS Recursive Name Server option fields.
        """

        assert isinstance(
            self.dns_servers, list
        ), f"The 'dns_servers' field must be a list. Got: {type(self.dns_servers)!r}"

        assert all(isinstance(item, Ip6Address) for item in self.dns_servers), (
            f"The 'dns_servers' field must be a list of Ip6Address elements. "
            f"Got: {[type(element) for element in self.dns_servers]!r}"
        )

        assert len(self.dns_servers) >= 1, (
            f"The 'dns_servers' field must carry at least 1 DNS server address "
            f"(RFC 3646 §3). Got: {len(self.dns_servers)}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self, "len", DHCP6__OPTION__LEN + len(self.dns_servers) * DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv6 DNS Recursive Name Server option log string.
        """

        return f"dns_servers {[str(server) for server in self.dns_servers]}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv6 DNS Recursive Name Server option as a memoryview.
        """

        struct.pack_into(
            DHCP6__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP6__OPTION__LEN,
        )

        for index, server in enumerate(self.dns_servers):
            struct.pack_into(
                DHCP6__OPTION__DNS_SERVERS__ELEMENT__STRUCT,
                buffer,
                DHCP6__OPTION__LEN + index * DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN,
                bytes(server),
            )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the DHCPv6 DNS Recursive Name Server option before parsing it.
        """

        option_len = int.from_bytes(buffer[2:4])

        if option_len < DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN:
            raise Dhcp6IntegrityError(
                "The DHCPv6 DNS Recursive Name Server option must carry at least one address "
                f"(RFC 3646 §3). Got: {option_len!r}"
            )

        if (value := option_len % DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN) != 0:
            raise Dhcp6IntegrityError(
                f"The DHCPv6 DNS Recursive Name Server option length value (less header) must "
                f"be a multiple of {DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN}. Got: {value!r}"
            )

        if (value := DHCP6__OPTION__LEN + option_len) > len(buffer):
            raise Dhcp6IntegrityError(
                "The DHCPv6 DNS Recursive Name Server option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv6 DNS Recursive Name Server option from buffer.
        """

        assert (value := len(buffer)) >= DHCP6__OPTION__LEN, (
            f"The minimum length of the DHCPv6 DNS Recursive Name Server option must "
            f"be {DHCP6__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := int.from_bytes(buffer[0:2])) == int(Dhcp6OptionType.DNS_SERVERS), (
            f"The DHCPv6 DNS Recursive Name Server option type must be {Dhcp6OptionType.DNS_SERVERS!r}. "
            f"Got: {Dhcp6OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        option_len = int.from_bytes(buffer[2:4])

        return cls(
            [
                Ip6Address(buffer[index : index + DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN])
                for index in range(
                    DHCP6__OPTION__LEN, DHCP6__OPTION__LEN + option_len, DHCP6__OPTION__DNS_SERVERS__ELEMENT__LEN
                )
            ]
        )
