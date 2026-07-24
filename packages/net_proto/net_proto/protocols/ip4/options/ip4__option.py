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
This module contains the IPv4 option support code.

net_proto/protocols/ip4/options/ip4__option.py

ver 3.0.8
"""

from dataclasses import dataclass

from net_proto.lib.proto_option import ProtoOption, ProtoOptionType

# RFC 791 §3.1 — IPv4 option TLV fixed prefix (single-byte EOL / NOP
# options carry no Length / Data octets). The Type octet itself
# decomposes as copied-flag(1) | class(2) | number(5):
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |     Length    |  Option Data...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP4__OPTION__STRUCT = "! BB"
IP4__OPTION__LEN = 2


class Ip4OptionType(ProtoOptionType):
    """
    The IPv4 option 'type' field values.
    """

    EOL = 0  # End of Option List - RFC 791 §3.1
    NOP = 1  # No Operation - RFC 791 §3.1
    RR = 7  # Record Route - RFC 791
    TIMESTAMP = 68  # Timestamp - RFC 791
    CIPSO = 134  # Commercial IP Security Option - FIPS-188 / Linux NetLabel
    LSRR = 131  # Loose Source and Record Route - RFC 791
    SSRR = 137  # Strict Source and Record Route - RFC 791
    ROUTER_ALERT = 148  # Router Alert - RFC 2113


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip4Option(ProtoOption):
    """
    The IPv4 option support class.
    """

    @property
    def copy_flag(self) -> bool:
        """
        Get the RFC 791 §3.1 'copy on fragmentation' flag — bit 7
        (high bit) of the option-type byte. Options with copy_flag
        set MUST be propagated onto every fragment when a datagram
        is fragmented; options with copy_flag clear appear only on
        the first fragment.
        """

        return bool(int(self.type) >> 7 & 1)
