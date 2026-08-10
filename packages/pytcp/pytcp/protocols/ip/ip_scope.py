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
RFC 4007 §5 / RFC 4291 §2.7 address-scope enum shared by the
IPv4 and IPv6 source-selection helpers
('pytcp/protocols/ip4/ip4__source_selection.py' and
'pytcp/protocols/ip6/ip6__source_selection.py'). The numeric values are
the same across families so the RFC 6724 §5 rule-2
'same-scope' comparison stays a plain integer compare
regardless of address family.

pytcp/protocols/ip/ip_scope.py

ver 3.0.9
"""

from enum import IntEnum


class IpScope(IntEnum):
    """
    RFC 4007 §5 / RFC 4291 §2.7 scope codepoints, shared
    across IPv4 and IPv6. PyTCP's source-selection helpers
    return this for cross-family scope comparison; the int
    values match Linux's IPv6 scope codepoints so
    cross-family rule-2 ordering is a plain integer compare.

    INTERFACE_LOCAL covers IPv4 loopback (127.0.0.0/8) and
    IPv6 loopback (::1); LINK_LOCAL covers IPv4 link-local
    (169.254.0.0/16) and IPv6 link-local (fe80::/10); GLOBAL
    is everything else, including RFC 1918 private and
    routable public addresses.
    """

    INTERFACE_LOCAL = 0x1
    LINK_LOCAL = 0x2
    GLOBAL = 0xE
