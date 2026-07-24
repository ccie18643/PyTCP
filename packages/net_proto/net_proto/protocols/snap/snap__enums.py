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
This module contains the SNAP (Sub-Network Access
Protocol, RFC 1042 §"Header Format") protocol enums —
well-known SNAP OUI codepoints from the IEEE OUI registry
plus the Cisco-proprietary protocol-ID values that appear
on switched-Ethernet links as 802.3+LLC+SNAP frames.

net_proto/protocols/snap/snap__enums.py

ver 3.0.9
"""

from enum import IntEnum


class SnapOui(IntEnum):
    """
    The IEEE OUI (Organizationally Unique Identifier)
    values that appear in the SNAP OUI field. Stored as
    24-bit integers (3 octets). PyTCP recognises the
    canonical 'encapsulated EtherType' OUI (0x000000)
    and the most common Cisco / 802.1 SNAP variants seen
    on enterprise networks.
    """

    ENCAP_ETHERTYPE = 0x000000  # RFC 1042 §"Header Format": OUI 0 → 16-bit EtherType follows.
    CISCO = 0x00000C  # Cisco Systems (CDP, VTP, DTP, PVST+, UDLD, etc.).
    IEEE_802_1 = 0x0080C2  # IEEE 802.1 bridge/spanning-tree management.
    APPLE = 0x080007  # Apple Computer (AppleTalk over Ethernet, legacy).


class SnapCiscoProtocol(IntEnum):
    """
    Cisco-proprietary 16-bit protocol IDs that appear in
    the SNAP EtherType field when OUI = 0x00000C. These
    are not EtherTypes in the IEEE sense — they belong to
    the Cisco-managed sub-space anchored by Cisco's OUI.
    PyTCP recognises the common ones for logging purposes;
    none are processed beyond the log-and-drop stats path.
    """

    PVST_PLUS_BPDU = 0x010B  # Per-VLAN STP+ BPDU (Cisco's per-VLAN spanning tree).
    VLAN_BRIDGE = 0x010C  # Cisco VLAN Bridge.
    UDLD = 0x0111  # Unidirectional Link Detection.
    CDP = 0x2000  # Cisco Discovery Protocol.
    CGMP = 0x2001  # Cisco Group Management Protocol.
    VTP = 0x2003  # VLAN Trunking Protocol.
    DTP = 0x2004  # Dynamic Trunking Protocol.
