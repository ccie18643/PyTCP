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
This module contains the DHCPv6 option base class and the
Dhcp6OptionType codepoint enum. DHCPv6 option carriage and the
per-option formats are defined in RFC 8415 §21 (and RFC 3646
for the DNS options); the canonical registry is IANA "Dynamic
Host Configuration Protocol for IPv6 (DHCPv6) > Option Codes".

net_proto/protocols/dhcp6/options/dhcp6__option.py

ver 3.0.10
"""

from dataclasses import dataclass
from typing import Self, override

from net_addr import Buffer
from net_proto.lib.proto_option import ProtoOption, ProtoOptionType

# RFC 8415 §21.1 — DHCPv6 option TLV fixed prefix. Unlike DHCPv4,
# both the option-code and option-len are 16-bit fields, and
# option-len counts the option-data octets only (excluding the
# 4-byte code+len header):
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          option-code          |           option-len          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          option-data                          |
# |                      (option-len octets)                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

DHCP6__OPTION__STRUCT = "! HH"
DHCP6__OPTION__LEN = 4


class Dhcp6OptionType(ProtoOptionType):
    """
    DHCPv6 option types.

    DHCPv6 option codes are 16-bit (RFC 8415 §21.1), unlike the
    8-bit DHCPv4 option codes the 'ProtoOptionType' marker base
    defaults to. The two byte-width hooks are overridden below so
    'from_bytes' / 'bytes()' read and write the 2-byte wire form.
    """

    CLIENT_ID = 1  # Client Identifier (RFC 8415 §21.2).
    SERVER_ID = 2  # Server Identifier (RFC 8415 §21.3).
    IA_NA = 3  # Identity Association for Non-temporary Addresses (RFC 8415 §21.4).
    IA_ADDR = 5  # IA Address (RFC 8415 §21.6).
    ORO = 6  # Option Request (RFC 8415 §21.7).
    PREFERENCE = 7  # Preference (RFC 8415 §21.8).
    ELAPSED_TIME = 8  # Elapsed Time (RFC 8415 §21.9).
    STATUS_CODE = 13  # Status Code (RFC 8415 §21.13).
    RAPID_COMMIT = 14  # Rapid Commit (RFC 8415 §21.14).
    DNS_SERVERS = 23  # DNS Recursive Name Server (RFC 3646 §3).

    @override
    def __bytes__(self) -> bytes:
        """
        Get the enum value as bytes.
        """

        return int(self).to_bytes(2)

    @override
    @classmethod
    def from_bytes(cls, data: Buffer, /) -> Self:
        """
        Extract the enum value from the provided bytes.
        """

        return cls._from_bytes(data, size=2)


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6Option(ProtoOption):
    """
    The DHCPv6 option support class.
    """
