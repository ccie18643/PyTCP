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
This module contains the IGMP / MLD membership state-change non-blocking
send tests — pinning that a join / leave emits its state-change report
through the fire-and-forget TX path, never the blocking one, so the
mutating thread cannot deadlock against the TX worker over the interface
multicast lock while it holds that lock.

packages/pytcp/pytcp/tests/integration/packet_handler/test__packet_handler__multicast_send_nonblocking.py

ver 3.0.9
"""

from typing import cast, override
from unittest.mock import MagicMock

from net_addr import Ip4Address, Ip6Address
from pytcp import stack
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_IP4_GROUP = Ip4Address("239.7.7.7")
_IP6_GROUP = Ip6Address("ff05::7")


_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class TestMulticastStateChangeSendNonBlocking(IcmpTestCase):
    """
    The IGMP / MLD membership state-change non-blocking-send tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and pin both robustness values to 1 so a join
        emits a single state-change report with no retransmit train.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.robustness", 1))
        self.enterContext(sysctl.override("mld.robustness", 1))

    def test__igmp__state_change_report_dispatched_fire_and_forget(self) -> None:
        """
        Ensure an IPv4 multicast join dispatches its IGMP state-change
        report through the fire-and-forget TX path and never the blocking
        one — the mutating thread holds the interface multicast lock while
        emitting, and the TX worker re-enters that lock to validate the
        report source, so a blocking dispatch would deadlock the two.

        Reference: RFC 3376 §5.1 (unsolicited state-change report on join).
        """

        tx_ring = cast(MagicMock, self._packet_handler._tx_ring)
        sync_before = tx_ring.dispatch.call_count
        async_before = tx_ring.dispatch_async.call_count

        self._packet_handler._assign_ip4_multicast(_IP4_GROUP)

        self.assertEqual(
            tx_ring.dispatch.call_count - sync_before,
            0,
            msg=(
                "The IGMP join report must not use the blocking dispatch "
                "(it deadlocks the TX worker under the multicast lock)."
            ),
        )
        self.assertGreaterEqual(
            tx_ring.dispatch_async.call_count - async_before,
            1,
            msg="The IGMP join state-change report must be dispatched fire-and-forget.",
        )

    def test__mld__state_change_report_dispatched_fire_and_forget(self) -> None:
        """
        Ensure an IPv6 multicast join dispatches its MLD state-change
        report through the fire-and-forget TX path and never the blocking
        one — the mutating thread holds the interface multicast lock while
        emitting, and the TX worker re-enters that lock to validate the
        report source, so a blocking dispatch would deadlock the two.

        Reference: RFC 3810 §6.1 (unsolicited state-change report on join).
        """

        tx_ring = cast(MagicMock, self._packet_handler._tx_ring)
        sync_before = tx_ring.dispatch.call_count
        async_before = tx_ring.dispatch_async.call_count

        self._packet_handler.assign_ip6_multicast(_IP6_GROUP)

        self.assertEqual(
            tx_ring.dispatch.call_count - sync_before,
            0,
            msg=(
                "The MLD join report must not use the blocking dispatch "
                "(it deadlocks the TX worker under the multicast lock)."
            ),
        )
        self.assertGreaterEqual(
            tx_ring.dispatch_async.call_count - async_before,
            1,
            msg="The MLD join state-change report must be dispatched fire-and-forget.",
        )
