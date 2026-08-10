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
This module contains pure helpers backing the RFC 6724 §6
default source-address selection algorithm applied to IPv4.

The IPv4 family has no SLAAC PREFERRED/DEPRECATED state, no
temporary-address machinery, and no §10.3 policy table, so
only rules 1, 2, and 8 of the §5 algorithm apply. The
helpers exposed here mirror the IPv6 ones in
'pytcp/protocols/ip6/ip6__source_selection.py': scope extraction
('ip4_address_scope') and 32-bit common-prefix-length
('common_prefix_len'). The selector itself lives on the
IPv4 TX mixin because it needs the runtime address book.

pytcp/protocols/ip4/ip4__source_selection.py

ver 3.0.9
"""

from net_addr import Ip4Address
from pytcp.protocols.ip.ip_scope import IpScope


def ip4_address_scope(address: Ip4Address, /) -> IpScope:
    """
    Return the RFC 4007-style scope value for the given IPv4
    address. Loopback (127.0.0.0/8) is interface-local;
    link-local (169.254.0.0/16) is link-local; everything else
    — including RFC 1918 private space and public addresses —
    reports as global.
    """

    if address.is_loopback:
        return IpScope.INTERFACE_LOCAL
    if address.is_link_local:
        return IpScope.LINK_LOCAL
    return IpScope.GLOBAL


def common_prefix_len(a: Ip4Address, b: Ip4Address, /) -> int:
    """
    Return the number of leading bits the two IPv4 addresses
    share. Identical addresses share 32 bits; addresses that
    disagree at bit position N share N bits. Symmetric in its
    arguments.
    """

    xor = int(a) ^ int(b)
    if xor == 0:
        return 32
    return 32 - xor.bit_length()
