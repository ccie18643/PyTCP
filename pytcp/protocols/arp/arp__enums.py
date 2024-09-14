#!/usr/bin/env python3

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
This module contains the ARP protocol enum classes.

pytcp/protocols/arp/arp__enums.py

ver 3.0.2
"""


from __future__ import annotations

from pytcp.lib.proto_enum import ProtoEnumWord


class ArpHardwareType(ProtoEnumWord):
    """
    The ARP header 'hrtype' field values.
    """

    ETHERNET = 0x0001


class ArpOperation(ProtoEnumWord):
    """
    The ARP header 'oper' field values.
    """

    REQUEST = 0x0001
    REPLY = 0x0002


ARP__HARDWARE_LEN__ETHERNET = 6
ARP__PROTOCOL_LEN__IP4 = 4
