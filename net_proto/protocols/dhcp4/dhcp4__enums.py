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
This module contains the DHCPv4 protocol enum classes.

net_proto/protocols/dhcp4/dhcp4__enums.py

ver 3.0.4
"""


from net_proto.lib.proto_enum import ProtoEnumWord


class Dhcp4Operation(ProtoEnumWord):
    """
    The DHCPv4 header 'oper' field values.
    """

    REQUEST = 0x01
    REPLY = 0x02


class Dhcp4HardwareType(ProtoEnumWord):
    """
    The DHCPv4 header 'htype' field values.
    """

    ETHERNET = 0x01


DHCP4__HARDWARE_LEN__ETHERNET = 6


class Dhcp4MessageType(ProtoEnumWord):
    """
    The DHCPv4 message type option values.
    """

    DISCOVER = 0x01
    OFFER = 0x02
    REQUEST = 0x03
    DECLINE = 0x04
    ACK = 0x05
    NAK = 0x06
    RELEASE = 0x07
    INFORM = 0x08
