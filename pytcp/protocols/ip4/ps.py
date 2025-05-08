#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
Module contains packet structure information for the IPv4 protocol.

pytcp/protocols/ip4/ps.py

ver 2.7
"""


from __future__ import annotations

# IPv4 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |   DSCP    |ECN|          Packet length        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to live |    Protocol   |         Header checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP4_HEADER_LEN = 20

IP4_PROTO_ICMP4 = 1
IP4_PROTO_TCP = 6
IP4_PROTO_UDP = 17
IP4_PROTO_RAW = 255

IP4_PROTO_TABLE = {
    IP4_PROTO_ICMP4: "ICMPv4",
    IP4_PROTO_TCP: "TCP",
    IP4_PROTO_UDP: "UDP",
    IP4_PROTO_RAW: "raw_data",
}


#
#   IPv4 options
#


# IPv4 option - End of Option Linst

IP4_OPT_EOL = 0
IP4_OPT_EOL_LEN = 1


# IPv4 option - No Operation (1)

IP4_OPT_NOP = 1
IP4_OPT_NOP_LEN = 1
