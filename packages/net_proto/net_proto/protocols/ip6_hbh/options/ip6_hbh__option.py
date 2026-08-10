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
This module contains the IPv6 Hop-by-Hop Options option base class.

net_proto/protocols/ip6_hbh/options/ip6_hbh__option.py

ver 3.0.10
"""

from dataclasses import dataclass
from enum import IntEnum

from net_proto.lib.proto_option import ProtoOption, ProtoOptionType

# RFC 8200 §4.2 — TLV-encoded option fixed prefix:
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Type  |  Opt Data Len |  Option Data...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Pad1 is the special exception: the single 0x00 byte stands alone
# (no length, no data) so a header can be padded to a multiple of
# 8 octets without a wasted length byte.

IP6_HBH__OPTION__STRUCT = "! BB"
IP6_HBH__OPTION__LEN = 2


class Ip6HbhOptionType(ProtoOptionType):
    """
    The IPv6 Hop-by-Hop Options option 'type' field values.
    """

    PAD1 = 0x00  # RFC 8200 §4.2: Pad1 (one-byte zero, no length/data).
    PADN = 0x01  # RFC 8200 §4.2: PadN (zero-fill padding).
    ROUTER_ALERT = 0x05  # RFC 2711: IPv6 Router Alert (intercept-and-process hint).
    CALIPSO = 0x07  # RFC 5570: Common Architecture Label IPv6 Security Option.
    JUMBO_PAYLOAD = 0xC2  # RFC 2675: IPv6 Jumbogram payload-length extension (>= 65536).


class Ip6HbhOptionAction(IntEnum):
    """
    RFC 8200 §4.2 action-on-unrecognized codes encoded in the high
    two bits of an option's Type byte. Receivers must consult these
    bits when an option type is unknown:

      00 — skip the option, continue processing.
      01 — discard the packet silently.
      10 — discard the packet and send Param Problem code 2.
      11 — discard the packet and send Param Problem code 2 unless
           the destination is multicast (then discard silently).
    """

    SKIP = 0b00
    DISCARD = 0b01
    DISCARD_PARAM_PROBLEM = 0b10
    DISCARD_PARAM_PROBLEM_UNICAST = 0b11


def ip6_hbh__option_action(option_type: int, /) -> Ip6HbhOptionAction:
    """
    Extract the RFC 8200 §4.2 action-on-unrecognized code from the
    high two bits of an option's Type byte.
    """

    return Ip6HbhOptionAction((option_type >> 6) & 0b11)


@dataclass(frozen=True, kw_only=True, slots=True)
class Ip6HbhOption(ProtoOption):
    """
    The IPv6 Hop-by-Hop Options option support class.
    """
