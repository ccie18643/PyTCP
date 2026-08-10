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
This module contains DHCP DUID (RFC 3315 §9) / IAID (RFC 3315 §10)
/ Client Identifier (RFC 4361 §6.1) helpers shared by the DHCPv4
client (and, eventually, by a future DHCPv6 client). The DUID is
derived from the host MAC by default (DUID-LL form) and overridable
via the 'dhcp.duid' sysctl for operator-managed stable identity.

pytcp/protocols/dhcp4/dhcp4__uid.py

ver 3.0.10
"""

from net_addr import MacAddress
from pytcp.protocols.dhcp4 import dhcp4__constants

# RFC 3315 §9.1 DUID-Type values. PyTCP defaults to DUID-LL
# (link-layer address) for simplicity and because the host MAC is
# the most readily available stable identifier in a typical
# single-interface PyTCP deployment.
_DUID_TYPE__LL: bytes = b"\x00\x03"

# IANA Hardware Type — 1 = "Ethernet (10Mb)" per RFC 3315 §9.4 /
# RFC 826 (ARP). The DUID-LL hardware-type field embeds this
# alongside the link-layer address bytes.
_HARDWARE_TYPE__ETHERNET: bytes = b"\x00\x01"

# RFC 4361 §6.1 Client Identifier type-prefix byte. The legacy
# RFC 2131 form used type=1 (Ethernet hardware address); the
# RFC 4361 form uses 0xff and embeds IAID + DUID after the type
# byte. New clients SHOULD emit the 0xff form.
_CLIENT_ID_TYPE__RFC4361: bytes = b"\xff"


def build_duid_ll(mac_address: MacAddress, /) -> bytes:
    """
    Build the canonical RFC 3315 §9.4 DUID-LL byte sequence —
    DUID-Type=3 + hardware-type=1 (Ethernet) + 6-byte MAC = 8
    bytes total.
    """

    return _DUID_TYPE__LL + _HARDWARE_TYPE__ETHERNET + bytes(mac_address)


def get_iaid(*, interface_idx: int = 0) -> bytes:
    """
    Build a 4-byte RFC 3315 §10 IAID for the given interface
    index. Single-interface PyTCP deployments use the default
    'interface_idx=0' which yields four zero bytes — the
    canonical "first interface" identifier.
    """

    return interface_idx.to_bytes(4, "big")


def get_duid(mac_address: MacAddress, /) -> bytes:
    """
    Return the active DUID — operator override via the 'dhcp.duid'
    sysctl takes precedence; empty sysctl falls back to the
    MAC-derived DUID-LL form. The override accepts both
    compact-hex ("0003000102...") and colon-separated
    ("00:03:00:01:02:...") representations.
    """

    override = dhcp4__constants.DHCP4__DUID
    if override:
        return bytes.fromhex(override.replace(":", ""))
    return build_duid_ll(mac_address)


def build_client_id(mac_address: MacAddress, /, *, interface_idx: int = 0) -> bytes:
    """
    Build the RFC 4361 §6.1 Client Identifier byte sequence —
    type=0xff + IAID + DUID. Used by DHCPv4 (in option 61) and by
    DHCPv6 (in the Client Identifier option).
    """

    return _CLIENT_ID_TYPE__RFC4361 + get_iaid(interface_idx=interface_idx) + get_duid(mac_address)
