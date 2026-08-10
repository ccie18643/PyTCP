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
This module contains the MLDv2 / IPv6-multicast query-response
thread-safety tests — pinning that the per-interface MLDv2
query-response timer state is mutated only while holding the
interface multicast lock, so the RX query handler and the
timer-thread deferred-send cannot corrupt it on a free-threaded
build.

packages/pytcp/pytcp/tests/integration/protocols/icmp6/test__mld__thread_safety.py

ver 3.0.10
"""

import threading
from typing import override

from net_addr import MacAddress
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


def _build_mldv2_general_query_frame() -> bytes:
    """
    Build an Ethernet/IPv6/ICMPv6 MLDv2 General Query (type 130)
    from a link-local router to ff02::1, MRC 10000 ms.
    """

    mldv2_query_body = (
        b"\x27\x10"  # MRC = 10000 ms
        b"\x00\x00"  # Reserved
        + b"\x00" * 16  # Multicast Address = :: (General Query)
        + b"\x02"  # Resv|S|QRV
        + b"\x7d"  # QQIC = 125
        + b"\x00\x00"  # Number of Sources = 0
    )
    icmp6_packet = b"\x82\x00\x00\x00" + mldv2_query_body

    ip6_src = bytes.fromhex("fe800000000000000000000000000001")
    ip6_dst = bytes.fromhex("ff020000000000000000000000000001")
    icmp6_len = len(icmp6_packet)
    pseudo_header = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"
    cksum = inet_cksum(pseudo_header + icmp6_packet)
    icmp6_packet = icmp6_packet[:2] + cksum.to_bytes(2, "big") + icmp6_packet[4:]

    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a\x01" + ip6_src + ip6_dst
    ethernet_header = b"\x33\x33\x00\x00\x00\x01" b"\x02\x00\x00\x00\x00\x91" b"\x86\xdd"

    return ethernet_header + ip6_header + icmp6_packet


class _TrackingRLock:
    """
    A reentrant lock that records the maximum hold depth reached so
    a test can assert a critical section was entered around a given
    operation and released afterwards.
    """

    def __init__(self) -> None:
        """
        Wrap a real reentrant lock and start at zero hold depth.
        """

        self._lock = threading.RLock()
        self.depth = 0
        self.max_depth = 0

    def __enter__(self) -> "_TrackingRLock":
        """
        Acquire the underlying lock and record the deeper hold.
        """

        self._lock.acquire()
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        return self

    def __exit__(self, *_: object) -> None:
        """
        Record the shallower hold and release the underlying lock.
        """

        self.depth -= 1
        self._lock.release()


class TestMldQueryResponseStateLocking(IcmpTestCase):
    """
    The IPv6 MLDv2 query-response state lock-discipline tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and pin a deterministic non-zero response
        delay so an inbound Query arms a pending timer rather than
        responding inline.
        """

        super().setUp()
        # The harness fixture does not auto-subscribe to the IPv6
        # all-nodes multicast MAC the way a real stack does on joining
        # ff02::1, so the Ethernet RX filter would drop the General
        # Query without this.
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))
        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: 500
        )

    def test__mld__query_scheduling_holds_the_multicast_lock(self) -> None:
        """
        Ensure the RX MLDv2 Query handler arms its pending-response
        timer state while holding the interface multicast lock, so it
        cannot corrupt that state against the timer-thread
        deferred-send on a free-threaded build.

        Reference: RFC 3810 §5.1.10 (listener-side Query processing).
        """

        handler = self._packet_handler
        tracking = _TrackingRLock()
        setattr(handler, "_lock__multicast", tracking)

        self._drive_rx(frame=_build_mldv2_general_query_frame())

        self.assertGreaterEqual(
            tracking.max_depth,
            1,
            msg="The MLDv2 Query handler must acquire the interface multicast lock.",
        )
        self.assertEqual(
            tracking.depth,
            0,
            msg="The MLDv2 Query handler must release the interface multicast lock.",
        )

    def test__mld__deferred_send_holds_the_multicast_lock(self) -> None:
        """
        Ensure the timer-thread MLDv2 deferred-send clears its
        pending-response timer state while holding the interface
        multicast lock, so it cannot corrupt that state against a
        concurrent RX Query on a free-threaded build.

        Reference: RFC 3810 §5.1.10 (listener-side Query processing).
        """

        handler = self._packet_handler
        tracking = _TrackingRLock()
        setattr(handler, "_lock__multicast", tracking)

        handler._icmp6_rx._mld2_query__deferred_send()

        self.assertGreaterEqual(
            tracking.max_depth,
            1,
            msg="The MLDv2 deferred-send must acquire the interface multicast lock.",
        )
        self.assertEqual(
            tracking.depth,
            0,
            msg="The MLDv2 deferred-send must release the interface multicast lock.",
        )
