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
This module contains the DHCPv4 option base class and the
Dhcp4OptionType codepoint enum. DHCPv4 option semantics are
defined in RFC 2131 §3 (option carriage) and RFC 2132
(per-option formats); per-codepoint authority lives in the
RFC cited next to each enum member, with the canonical
registry at IANA "Dynamic Host Configuration Protocol
(DHCP) and Bootstrap Protocol (BOOTP) Parameters > BOOTP
Vendor Extensions and DHCP Options".

net_proto/protocols/dhcp4/options/dhcp4__option.py

ver 3.0.8
"""

from dataclasses import dataclass

from net_proto.lib.proto_option import ProtoOption, ProtoOptionType

# RFC 2132 §2 — DHCPv4 option TLV fixed prefix (the single-byte Pad
# (0) and End (255) options carry no Len / Data octets):
#
#  Code  Len   Option Data...
# +-----+-----+-----+-----+--
# | Code| Len | d1  | d2  | ...
# +-----+-----+-----+-----+--

DHCP4__OPTION__STRUCT = "! BB"
DHCP4__OPTION__LEN = 2


class Dhcp4OptionType(ProtoOptionType):
    """
    DHCPv4 option types.
    """

    PAD = 0  # Pad (RFC 2132 §3.1).
    SUBNET_MASK = 1  # Subnet Mask (RFC 2132 §3.3).
    ROUTER = 3  # Router (RFC 2132 §3.5).
    HOST_NAME = 12  # Host Name (RFC 2132 §3.14).
    REQ_IP_ADDR = 50  # Requested IP Address (RFC 2132 §9.1).
    LEASE_TIME = 51  # IP Address Lease Time (RFC 2132 §9.2).
    OPTION_OVERLOAD = 52  # Option Overload (RFC 2132 §9.3).
    MESSAGE_TYPE = 53  # DHCP Message Type (RFC 2132 §9.6).
    SERVER_ID = 54  # Server Identifier (RFC 2132 §9.7).
    PARAM_REQ_LIST = 55  # Parameter Request List (RFC 2132 §9.8).
    MAX_MSG_SIZE = 57  # Maximum DHCP Message Size (RFC 2132 §9.10).
    RENEWAL_TIME = 58  # Renewal (T1) Time Value (RFC 2132 §9.11).
    REBINDING_TIME = 59  # Rebinding (T2) Time Value (RFC 2132 §9.12).
    CLIENT_ID = 61  # Client-identifier (RFC 2132 §9.14).
    CLASSLESS_STATIC_ROUTE = 121  # Classless Static Route (RFC 3442).
    END = 255  # End (RFC 2132 §3.2).


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Option(ProtoOption):
    """
    The DHCPv4 option support class.
    """
