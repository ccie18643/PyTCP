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
Module contains the ICMPv6 packet assembler.

pytcp/protocols/icmp6/icmp6__assembler.py

ver 3.0.2
"""


from __future__ import annotations

from pytcp.lib.proto_assembler import ProtoAssembler
from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp6.icmp6__base import Icmp6
from pytcp.protocols.icmp6.message.icmp6_message import Icmp6Message


class Icmp6Assembler(Icmp6, ProtoAssembler):
    """
    The ICMPv6 packet assembler.
    """

    def __init__(
        self,
        *,
        icmp6__message: Icmp6Message,
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the ICMPv6 packet assembler.
        """

        self._tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._message = icmp6__message
