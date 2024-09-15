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
Module contains global configuration parameters.

pytcp/config.py

ver 3.0.2
"""


from __future__ import annotations

# TCP/UDP ephemeral port range to be used by outbound connections.
EPHEMERAL_PORT_RANGE = range(32168, 60700, 2)

# TCP session related settings.
TCP__MIN_MSS = (
    536  # The minimum recommended value of the  Maximum Segment Size (RFC 879).
)
TCP__LOCAL_MSS = 1460  # Maximum segment peer can send to us.
TCP__LOCAL_WIN = (
    65535  # Maximum amount of data peer can send to us without confirmation.
)
