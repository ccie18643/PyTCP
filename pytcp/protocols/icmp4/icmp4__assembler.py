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
This module contains the ICMPv4 packet assembler.

pytcp/protocols/icmp4/icmp4__assembler.py

ver 3.0.3
"""


from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp4.icmp4__base import Icmp4
from pytcp.protocols.icmp4.message.icmp4_message import Icmp4Message


class Icmp4Assembler(Icmp4, ProtoAssembler):
    """
    The ICMPv4 packet assembler.
    """

    def __init__(
        self,
        *,
        icmp4__message: Icmp4Message,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the ICMPv4 packet assembler.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._message = icmp4__message
