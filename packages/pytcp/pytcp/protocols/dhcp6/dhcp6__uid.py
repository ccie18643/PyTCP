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
This module contains the DHCPv6 (RFC 8415) DUID / IAID helpers.

A host has a single DUID, shared between the DHCPv4 Client
Identifier (RFC 4361, option 61) and the DHCPv6 Client/Server
Identifier options (RFC 8415 §11). The canonical derivation and
the operator override (the 'dhcp.duid' sysctl) live in
'pytcp.protocols.dhcp4.dhcp4__uid'; this module is the thin
DHCPv6-facing surface over them. DHCPv6 differs from DHCPv4 in
two ways: it carries the *bare* DUID in the Client Identifier
option (DHCPv4 wraps it in the RFC 4361 type=0xff + IAID + DUID
form), and its IA_NA option carries the IAID as a 32-bit integer
field rather than 4 opaque octets.

pytcp/protocols/dhcp6/dhcp6__uid.py

ver 3.0.8
"""

from net_addr import MacAddress
from pytcp.protocols.dhcp4 import dhcp4__uid


def get_client_duid(mac_address: MacAddress, /) -> bytes:
    """
    Return the host DUID for the DHCPv6 Client Identifier option
    (RFC 8415 §21.2). This is the bare DUID — the 'dhcp.duid'
    operator override, or the MAC-derived DUID-LL when unset — not
    the RFC 4361 Client-Identifier wrapper the DHCPv4 client emits.
    """

    return dhcp4__uid.get_duid(mac_address)


def get_iaid(*, interface_idx: int = 0) -> int:
    """
    Return the IAID as a 32-bit integer for the DHCPv6 IA_NA option
    (RFC 8415 §21.4). Single-interface PyTCP deployments use the
    default 'interface_idx=0' which yields IAID 0 — the canonical
    "first interface" identifier — shared with the DHCPv4 client's
    IAID so a dual-stack host presents a consistent identity.
    """

    return int.from_bytes(dhcp4__uid.get_iaid(interface_idx=interface_idx))
