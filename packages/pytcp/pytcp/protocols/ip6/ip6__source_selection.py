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
This module contains pure helpers backing the RFC 6724 default
source-address selection algorithm.

The two helpers exposed here are scope-extraction
('ip6_address_scope') and common-prefix-length
('common_prefix_len'), the data PyTCP's selector consumes when
applying RFC 6724 §5 rules 2 and 8. The selector itself lives on
the IPv6 TX mixin because it needs the runtime address book
('_ip6_ifaddr', '_icmp6_slaac_addresses', '_icmp6_temp_addresses').

pytcp/protocols/ip6/ip6__source_selection.py

ver 3.0.9
"""

from net_addr import Ip6Address
from pytcp.protocols.ip.ip_scope import IpScope


def ip6_address_scope(address: Ip6Address, /) -> IpScope | int:
    """
    Return the RFC 4007 §5 / RFC 4291 §2.7 scope value for the
    given IPv6 address. Multicast addresses report their 'scop'
    nibble verbatim (as an int — multicast scope encoding can
    include codepoints outside the IpScope enum, e.g.
    site-local 0x5); unicast addresses are categorised as
    interface-local (loopback ::1), link-local (fe80::/10), or
    global (everything else, including ULA and the unspecified
    address). The unspecified address is reported as global so
    the rule-2 comparison stays well-defined when it appears as
    a destination key.
    """

    if address.is_multicast:
        return (int(address) >> 112) & 0xF
    if address.is_loopback:
        return IpScope.INTERFACE_LOCAL
    if address.is_link_local:
        return IpScope.LINK_LOCAL
    return IpScope.GLOBAL


def common_prefix_len(a: Ip6Address, b: Ip6Address, /) -> int:
    """
    Return the number of leading bits the two IPv6 addresses
    share. Identical addresses share 128 bits; addresses that
    disagree at bit position N share N bits. The function is
    symmetric in its arguments.
    """

    xor = int(a) ^ int(b)
    if xor == 0:
        return 128
    return 128 - xor.bit_length()
