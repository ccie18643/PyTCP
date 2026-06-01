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
This module contains tests for the ICMPv6 Echo Reply emission gate.

pytcp/tests/unit/protocols/icmp6/test__icmp6__echo_gate.py

ver 3.0.8
"""

from unittest import TestCase

from pytcp.protocols.icmp6.icmp6__echo_gate import should_emit_echo_reply


class TestShouldEmitEchoReply__AlwaysPermitted(TestCase):
    """
    The ICMPv6 'should_emit_echo_reply()' permit-path tests.
    """

    def test__icmp6__echo_gate__permits_unconditionally(self) -> None:
        """
        Ensure that the ICMPv6 Echo Reply emission gate always
        permits emission. ICMPv6 deliberately diverges from the
        ICMPv4 Smurf-mitigation rule: replies to multicast Echo
        Requests are explicitly permitted, with appropriate src-
        address selection performed by the TX path.

        Reference: RFC 4443 §4.2 (ICMPv6 Echo Reply MAY be sent in
        response to a multicast Echo Request).
        """

        self.assertTrue(
            should_emit_echo_reply(),
            msg="ICMPv6 Echo Reply emission must be unconditionally permitted.",
        )
