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
Module contains tests for the ICMPv4 packet assembler miscellaneous functions.

tests/pytcp/unit/protocols/icmp4/test__icmp4__assembler__misc.py

ver 3.0.2
"""


from testslide import TestCase

from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp4.icmp4__assembler import Icmp4Assembler
from pytcp.protocols.icmp4.message.icmp4_message__echo_reply import (
    Icmp4EchoReplyMessage,
)


class TestIcmp4AssemblerMisc(TestCase):
    """
    The ICMPv4 packet assembler miscellaneous functions tests.
    """

    def test__icmp4__assembler__echo_tracker(self) -> None:
        """
        Ensure the ICMPv4 packet assembler 'tracker' property returns
        a correct value.
        """

        echo_tracker = Tracker(prefix="RX")

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4EchoReplyMessage(),
            echo_tracker=echo_tracker,
        )

        self.assertEqual(
            icmp4__assembler.tracker.echo_tracker,
            echo_tracker,
        )
