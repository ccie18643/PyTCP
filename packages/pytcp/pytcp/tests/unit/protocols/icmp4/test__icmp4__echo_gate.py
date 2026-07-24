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
This module contains tests for the ICMPv4 Echo Reply emission gate.

pytcp/tests/unit/protocols/icmp4/test__icmp4__echo_gate.py

ver 3.0.9
"""

from typing import Any
from unittest import TestCase

from pytcp.protocols.icmp4.icmp4__echo_gate import should_emit_echo_reply
from pytcp.stack import sysctl
from pytcp.tests.lib.parameterized import parameterized_class


class TestShouldEmitEchoReply__Permit(TestCase):
    """
    The ICMPv4 'should_emit_echo_reply()' permit-path tests.
    """

    def test__icmp4__echo_gate__clean_unicast_permits(self) -> None:
        """
        Ensure that an Echo Request whose destination is a unicast IP
        address (neither broadcast nor multicast) permits the Echo
        Reply emission.

        Reference: RFC 1122 §3.2.2.6 (host SHOULD reply to unicast
        Echo Request).
        """

        permitted = should_emit_echo_reply(
            dst_is_broadcast=False,
            dst_is_multicast=False,
        )

        self.assertTrue(
            permitted,
            msg="Clean unicast destination must permit Echo Reply emission.",
        )


@parameterized_class(
    [
        {
            "_description": "Broadcast destination (Smurf vector).",
            "_kwargs": {"dst_is_broadcast": True, "dst_is_multicast": False},
        },
        {
            "_description": "Multicast destination.",
            "_kwargs": {"dst_is_broadcast": False, "dst_is_multicast": True},
        },
        {
            "_description": "Both broadcast and multicast flagged (defensive).",
            "_kwargs": {"dst_is_broadcast": True, "dst_is_multicast": True},
        },
    ]
)
class TestShouldEmitEchoReply__Block(TestCase):
    """
    The ICMPv4 'should_emit_echo_reply()' Smurf-mitigation tests.
    """

    _description: str
    _kwargs: dict[str, Any]

    def test__icmp4__echo_gate__bcast_or_mcast_blocks(self) -> None:
        """
        Ensure that an Echo Request whose destination is a broadcast
        or multicast IPv4 address blocks the Echo Reply emission.

        Reference: RFC 1122 §3.2.2.6 (host MUST NOT reply to Echo
        Request received on a broadcast/multicast destination).
        Reference: RFC 1812 §4.3.3.6 (analogous router rule, applies
        to hosts via RFC 1122).
        """

        permitted = should_emit_echo_reply(**self._kwargs)

        self.assertFalse(
            permitted,
            msg=f"Echo Reply must be blocked for case: {self._description}",
        )


class TestShouldEmitEchoReply__SysctlOverride(TestCase):
    """
    The ICMPv4 'should_emit_echo_reply()' 'icmp4.echo_ignore_broadcasts'
    knob tests.
    """

    def test__icmp4__echo_gate__knob_zero_permits_broadcast_and_multicast(self) -> None:
        """
        Ensure that with 'icmp4.echo_ignore_broadcasts' set to 0 a
        broadcast or multicast Echo Request is permitted to reply, while
        the default value of 1 keeps it blocked.

        Reference: Linux 'net.ipv4.icmp_echo_ignore_broadcasts' (0 answers broadcast/multicast echo).
        """

        with sysctl.override("icmp4.echo_ignore_broadcasts", 0):
            self.assertTrue(
                should_emit_echo_reply(dst_is_broadcast=True, dst_is_multicast=False),
                msg="With the knob 0, a broadcast Echo Request must be permitted.",
            )
            self.assertTrue(
                should_emit_echo_reply(dst_is_broadcast=False, dst_is_multicast=True),
                msg="With the knob 0, a multicast Echo Request must be permitted.",
            )

        self.assertFalse(
            should_emit_echo_reply(dst_is_broadcast=False, dst_is_multicast=True),
            msg="With the default knob (1), a multicast Echo Request must stay blocked.",
        )
