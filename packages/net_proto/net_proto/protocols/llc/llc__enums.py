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
This module contains the IEEE 802.2 LLC (Logical Link
Control) protocol enums — well-known SAP (Service Access
Point) codepoints from the IEEE 802 SAP registry and the
common LLC Control field values for U-frames (Unnumbered
commands).

net_proto/protocols/llc/llc__enums.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.proto_enum import ProtoEnumByte


class LlcSap(ProtoEnumByte):
    """
    The IEEE 802.2 LLC SAP (Service Access Point) values.
    DSAP and SSAP are 8-bit fields where the LSB carries
    the I/G (DSAP) or C/R (SSAP) indicator and the upper
    seven bits identify the SAP. PyTCP exposes the
    canonical 8-bit value (LSB = 0); recognise-and-route
    consumers can mask the LSB themselves if they need
    to distinguish individual vs group / command vs response.
    """

    NULL = 0x00  # Null SAP (LLC management; RFC 1042 reserved).
    LLC_MGMT = 0x02  # Individual LLC sublayer management function.
    SNA_PATH_CONTROL = 0x04  # IBM SNA Path Control.
    TCP_IP_OVER_LLC = 0x06  # TCP/IP over IEEE 802.2 LLC (deprecated; RFC 1042 §"Description").
    PROWAY_NM = 0x0E  # ProWay-LAN Network Management.
    LAYER_MGMT = 0x42  # IEEE 802.1 Bridge Spanning Tree Protocol (STP / RSTP / MSTP BPDUs).
    SNA_2 = 0x08  # IBM SNA secondary.
    SNAP = 0xAA  # Sub-Network Access Protocol (RFC 1042 §"Header Format").
    BANYAN_VINES = 0xBC  # Banyan VINES.
    NOVELL_IPX = 0xE0  # Novell NetWare IPX over IEEE 802.2.
    NETBIOS = 0xF0  # IBM NetBIOS over IEEE 802.2.
    ISO_NETWORK = 0xFE  # ISO 8473 CLNP / IS-IS / ES-IS Network Layer.
    GLOBAL = 0xFF  # Global DSAP (Novell raw-802.3 marker; not strictly per IEEE).

    @override
    def __str__(self) -> str:
        """
        Get the LLC SAP value as a string.
        """

        match self:
            case LlcSap.NULL:
                name = "Null"
            case LlcSap.LLC_MGMT:
                name = "LLC-Mgmt"
            case LlcSap.SNA_PATH_CONTROL:
                name = "SNA-PathCtrl"
            case LlcSap.TCP_IP_OVER_LLC:
                name = "TCP/IP-over-LLC"
            case LlcSap.PROWAY_NM:
                name = "ProWay-NM"
            case LlcSap.LAYER_MGMT:
                name = "STP"
            case LlcSap.SNA_2:
                name = "SNA-2"
            case LlcSap.SNAP:
                name = "SNAP"
            case LlcSap.BANYAN_VINES:
                name = "Banyan-VINES"
            case LlcSap.NOVELL_IPX:
                name = "Novell-IPX"
            case LlcSap.NETBIOS:
                name = "NetBIOS"
            case LlcSap.ISO_NETWORK:
                name = "ISO-Network"
            case LlcSap.GLOBAL:
                name = "Global"
            case _:
                name = f"0x{self.value:02x}"

        return name


class LlcControl(ProtoEnumByte):
    """
    Well-known IEEE 802.2 LLC U-frame Control field values
    (1-byte form). PyTCP focuses on the connectionless
    Type 1 service per RFC 1042 §"IEEE 802.2 Details" —
    UI (Unnumbered Information) is the only command that
    appears in modern IP-bearing traffic. XID and TEST
    commands are listed for completeness; PyTCP recognises
    them in inbound logs but does not generate them.
    """

    UI = 0x03  # Unnumbered Information (RFC 1042 SNAP, STP BPDUs).
    XID_POLL_OFF = 0xAF  # eXchange IDentification, poll bit off.
    XID_POLL_ON = 0xBF  # eXchange IDentification, poll bit on.
    TEST_POLL_OFF = 0xE3  # TEST link, poll bit off.
    TEST_POLL_ON = 0xF3  # TEST link, poll bit on.

    @override
    def __str__(self) -> str:
        """
        Get the LLC Control value as a string.
        """

        match self:
            case LlcControl.UI:
                name = "UI"
            case LlcControl.XID_POLL_OFF:
                name = "XID"
            case LlcControl.XID_POLL_ON:
                name = "XID/P"
            case LlcControl.TEST_POLL_OFF:
                name = "TEST"
            case LlcControl.TEST_POLL_ON:
                name = "TEST/P"
            case _:
                name = f"0x{self.value:02x}"

        return name
