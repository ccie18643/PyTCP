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
This module contains the ICMPv6 ND option base class and
the Icmp6NdOptionType codepoint enum. ND options are
defined in RFC 4861 §4.6 (TLV format common to RS / RA /
NS / NA / Redirect); per-codepoint authority lives in the
RFC cited next to each enum member, with the canonical
registry at IANA "Internet Control Message Protocol
version 6 (ICMPv6) Parameters > IPv6 Neighbor Discovery
Option Formats".

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__option.py

ver 3.0.10
"""

from dataclasses import dataclass

from net_proto.lib.proto_option import ProtoOption, ProtoOptionType

# RFC 4861 §4.6 — ND option TLV fixed prefix common to all ND options
# (RS / RA / NS / NA / Redirect). Length is in units of 8 octets and
# includes the Type + Length octets (so the whole option is a multiple
# of 8 octets):
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |     Length    |  Option Data...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__ND__OPTION__STRUCT = "! BB"
ICMP6__ND__OPTION__LEN = 2


class Icmp6NdOptionType(ProtoOptionType):
    """
    The ICMPv6 ND option 'type' field values.
    """

    SLLA = 1  # Source Link-Layer Address (RFC 4861 §4.6.1).
    TLLA = 2  # Target Link-Layer Address (RFC 4861 §4.6.1).
    PI = 3  # Prefix Information (RFC 4861 §4.6.2).
    REDIRECTED_HEADER = 4  # Redirected Header (RFC 4861 §4.6.3).
    MTU = 5  # MTU (RFC 4861 §4.6.4).
    NONCE = 14  # Nonce (RFC 3971 §5.3.2).
    ROUTE_INFO = 24  # Route Information (RFC 4191 §2.3).
    RDNSS = 25  # Recursive DNS Server (RFC 8106 §5.1).
    RA_FLAGS_EXTENSION = 26  # RA Flags Extension (RFC 5175 §4).
    DNSSL = 31  # DNS Search List (RFC 8106 §5.2).


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOption(ProtoOption):
    """
    The ICMPv6 ND option support class.
    """
