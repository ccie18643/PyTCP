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
This module contains the TCP option base class and the
TcpOptionType codepoint enum. TCP option semantics are
defined in RFC 9293 §3.1 (header layout) and §3.2 (option
TLV format); per-codepoint authority lives in the
RFC cited next to each enum member, with the canonical
registry at IANA "Transmission Control Protocol (TCP)
Parameters > TCP Option Kind Numbers".

net_proto/protocols/tcp/options/tcp__option.py

ver 3.0.8
"""

from dataclasses import dataclass

from net_proto.lib.proto_option import ProtoOption, ProtoOptionType

# RFC 9293 §3.1 — TCP option TLV fixed prefix (single-byte EOL / NOP
# options carry no Length / Data octets):
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Kind     |     Length    |  Option Data...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__STRUCT = "! BB"
TCP__OPTION__LEN = 2


class TcpOptionType(ProtoOptionType):
    """
    The TCP option 'type' field values.
    """

    EOL = 0  # End of Option List (RFC 9293 §3.2).
    NOP = 1  # No-Operation (RFC 9293 §3.2; padding to a 4-byte boundary).
    MSS = 2  # Maximum Segment Size (RFC 9293 §3.7.1).
    WSCALE = 3  # Window Scale (RFC 7323 §2).
    SACKPERM = 4  # SACK-Permitted (RFC 2018 §2).
    SACK = 5  # Selective Acknowledgement (RFC 2018 §3).
    TIMESTAMPS = 8  # Timestamps (RFC 7323 §3).
    FASTOPEN = 34  # TCP Fast Open Cookie (RFC 7413 §4).
    ACCECN0 = 172  # Accurate ECN order-0 (RFC 9768 §3.2.3).
    ACCECN1 = 174  # Accurate ECN order-1 (RFC 9768 §3.2.3).


@dataclass(frozen=True, kw_only=True, slots=True)
class TcpOption(ProtoOption):
    """
    The TCP option support class.
    """
