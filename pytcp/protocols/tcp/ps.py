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
Module contains packet structure information for the TCP protocol.

pytcp/protocols/tcp/ps.py

ver 2.7
"""


from __future__ import annotations

# TCP packet header (RFC 793)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hlen | Res |N|C|E|U|A|P|R|S|F|            Window             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP_HEADER_LEN = 20


#
# TCP options
#


# TCP option - End of Option List (0)

TCP_OPT_EOL = 0
TCP_OPT_EOL_LEN = 1


# TCP option - No Operation (1)

TCP_OPT_NOP = 1
TCP_OPT_NOP_LEN = 1


# TCP option - Maximum Segment Size (2)

TCP_OPT_MSS = 2
TCP_OPT_MSS_LEN = 4


# TCP option - Window Scale (3)

TCP_OPT_WSCALE = 3
TCP_OPT_WSCALE_LEN = 3


# TCP option - Sack Permit (4)

TCP_OPT_SACKPERM = 4
TCP_OPT_SACKPERM_LEN = 2


# TCP option - Timestamp

TCP_OPT_TIMESTAMP = 8
TCP_OPT_TIMESTAMP_LEN = 10
