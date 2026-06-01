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
This module contains the IGMP / IPv4-multicast thread-safety tests —
pinning that the per-interface multicast reception state is mutated only
while holding the interface multicast lock, so concurrent application-
thread membership changes cannot corrupt it on a free-threaded build.

packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__thread_safety.py

ver 3.0.8
"""

import threading
from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import IpProto
from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.runtime.socket import (
    AF_INET,
    IP_ADD_SOURCE_MEMBERSHIP,
    IPPROTO_IP,
    SOCK_DGRAM,
    socket,
)
from pytcp.stack import sysctl
from pytcp.stack.membership import MembershipApi
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip4Address("239.7.7.7")
_SOURCE = Ip4Address("10.0.0.5")
_QUERY_GROUP = Ip4Address("239.8.8.8")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")
_ROUTER_IP = Ip4Address("10.0.1.1")


_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _group_specific_query_frame(group: Ip4Address, /) -> bytes:
    """
    Build an Ethernet/IPv4 frame carrying an IGMPv3 Group-Specific Query
    for 'group' (Max Resp Code 100 = 10 s, no source list).
    """

    body = b"\x11" + bytes([100]) + b"\x00\x00" + bytes(group) + b"\x02\x7d" + b"\x00\x00"
    body = body[:2] + inet_cksum(body).to_bytes(2, "big") + body[4:]
    ethernet = EthernetAssembler(
        ethernet__src=_ROUTER_MAC,
        ethernet__dst=group.multicast_mac,
        ethernet__payload=Ip4Assembler(
            ip4__src=_ROUTER_IP,
            ip4__dst=group,
            ip4__ttl=1,
            ip4__payload=RawAssembler(raw__payload=body, ip_proto=IpProto.IGMP),
        ),
    )
    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buf) for buf in buffers)


class _TrackingRLock:
    """
    A reentrant lock that exposes its current hold depth so a test can
    assert a critical section was entered around a given operation.
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


class _LockAssertingDict[K, V](dict[K, V]):
    """
    A dict that records, on every structural mutation, whether the
    tracking lock was held at the moment of the write.
    """

    def __init__(self, lock: _TrackingRLock, observed: list[bool], source: dict[K, V], /) -> None:
        """
        Seed from 'source' and remember where to record observations.
        """

        super().__init__(source)
        self._lock = lock
        self._observed = observed

    @override
    def __setitem__(self, key: K, value: V) -> None:
        """
        Record the lock-held state, then insert / replace the key.
        """

        self._observed.append(self._lock.depth > 0)
        super().__setitem__(key, value)

    @override
    def __delitem__(self, key: K) -> None:
        """
        Record the lock-held state, then delete the key.
        """

        self._observed.append(self._lock.depth > 0)
        super().__delitem__(key)


class TestIgmpMulticastReceptionStateLocking(IcmpTestCase):
    """
    The IPv4 multicast reception-state lock-discipline tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and pin robustness to 1 so a membership change
        emits a single report without a lingering retransmit train.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.robustness", 1))

    def test__igmp__reception_state_mutations_hold_the_multicast_lock(self) -> None:
        """
        Ensure every structural mutation of the IPv4 multicast reception
        state — the joined-group filter map and the per-group contributor
        registry — happens while the interface multicast lock is held, so
        concurrent application-thread join / leave / source-filter changes
        cannot corrupt the reference-counted state on a free-threaded
        build.

        Reference: RFC 3376 §3.2 (interface reception state is the merge of per-socket filters).
        """

        handler = self._packet_handler
        tracking = _TrackingRLock()
        observed: list[bool] = []

        # Install the depth-tracking lock in place of the real multicast
        # lock and wrap the two reception-state dicts so each set / del
        # records whether the lock was held. 'setattr' keeps mypy strict
        # clean without re-typing the production attributes.
        setattr(handler, "_lock__multicast", tracking)
        setattr(
            handler,
            "_ip4_multicast_filters",
            _LockAssertingDict(tracking, observed, handler._ip4_multicast_filters),
        )
        setattr(
            handler,
            "_ip4_multicast_refs",
            _LockAssertingDict(tracking, observed, handler._ip4_multicast_refs),
        )

        membership = MembershipApi(packet_handler=handler)

        # Drive every reception-state mutator: an operator join (filter
        # map insert), a per-socket source-filter change (merge update),
        # and a leave (filter map + contributor registry delete).
        membership.join(group=_GROUP)
        membership.set_socket_filter(
            group=_GROUP,
            token=1,
            source_filter=Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset({_SOURCE})),
        )
        membership.clear_socket_filter(group=_GROUP, token=1)
        membership.leave(group=_GROUP)

        self.assertTrue(
            observed,
            msg="The membership changes must mutate the reception-state dicts.",
        )
        self.assertTrue(
            all(observed),
            msg="Every reception-state mutation must occur while the interface multicast lock is held.",
        )


class TestIgmpQueryResponseStateLocking(IcmpTestCase):
    """
    The IPv4 IGMP query-response state lock-discipline tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness, join a group, and pin robustness to 1 so the
        join's state-change report leaves no retransmit train behind.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.robustness", 1))
        self._packet_handler._mac_multicast.append(_QUERY_GROUP.multicast_mac)
        self._packet_handler._assign_ip4_multicast(_QUERY_GROUP)

    def test__igmp__group_query_scheduling_holds_the_multicast_lock(self) -> None:
        """
        Ensure scheduling a Group-Specific Query's pending response
        mutates the per-group pending-response map while holding the
        interface multicast lock, so the RX query handler and the
        timer-thread deferred-send cannot corrupt the IGMP query-response
        state on a free-threaded build.

        Reference: RFC 3376 §5.2 (Group-Specific Query per-group response timer).
        """

        handler = self._packet_handler
        tracking = _TrackingRLock()
        observed: list[bool] = []

        # A deterministic non-zero response delay so the Query arms a
        # pending per-group timer (a zero delay would respond inline).
        handler._igmp_rx._igmp_query__pick_response_delay_ms = lambda max_resp_ms: 500  # type: ignore[method-assign]
        setattr(handler, "_lock__multicast", tracking)
        setattr(
            handler,
            "_igmp_group_query__pending",
            _LockAssertingDict(tracking, observed, handler._igmp_group_query__pending),
        )

        self._drive_rx(frame=_group_specific_query_frame(_QUERY_GROUP))

        self.assertTrue(
            observed,
            msg="The Group-Specific Query must arm a pending per-group response.",
        )
        self.assertTrue(
            all(observed),
            msg="The pending per-group response must be armed while the interface multicast lock is held.",
        )


class TestIgmpStateChangeRetransmitLocking(IcmpTestCase):
    """
    The IPv4 IGMP state-change retransmit-timer lock-discipline tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and pin robustness to 2 so a join leaves exactly
        one pending state-change retransmission for the timer-thread fire
        to act on.
        """

        super().setUp()
        self.enterContext(sysctl.override("igmp.robustness", 2))

    def test__igmp__state_change_retransmit_holds_the_multicast_lock(self) -> None:
        """
        Ensure the timer-thread state-change retransmit fire mutates the
        pending per-group change map while holding the interface multicast
        lock, so it cannot corrupt the map or read a torn Host
        Compatibility Mode against a concurrent application-thread
        membership change on a free-threaded build.

        Reference: RFC 3376 §5.1 (unsolicited state-change retransmission).
        Reference: RFC 3376 §7.2.1 (Host Compatibility Mode).
        """

        handler = self._packet_handler
        tracking = _TrackingRLock()
        observed: list[bool] = []

        # A join (under the real lock) seeds the pending state-change map
        # so the timer-thread fire has an entry to retransmit and delete.
        handler._mac_multicast.append(_GROUP.multicast_mac)
        handler._assign_ip4_multicast(_GROUP)

        setattr(handler, "_lock__multicast", tracking)
        setattr(
            handler._igmp_tx,
            "_igmp_state_change__pending",
            _LockAssertingDict(tracking, observed, handler._igmp_tx._igmp_state_change__pending),
        )

        handler._igmp_tx._fire_state_change_retransmit()

        self.assertTrue(
            observed,
            msg="The retransmit fire must mutate the pending state-change map.",
        )
        self.assertTrue(
            all(observed),
            msg="The pending state-change map must be mutated while the interface multicast lock is held.",
        )


class TestSocketSourceFilterLocking(IcmpTestCase):
    """
    The per-socket IPv4 multicast source-filter lock-discipline tests.
    """

    def test__socket__source_filter_write_holds_the_lock(self) -> None:
        """
        Ensure an application-thread source-membership setsockopt mutates
        the per-socket source-filter map while holding the per-socket
        source-filter lock, so two threads racing setsockopt on one
        socket cannot lose an update or tear the map on a free-threaded
        build.

        Reference: RFC 3376 §3.1 (per-socket source filter).
        """

        sock = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(sock.close)
        tracking = _TrackingRLock()
        observed: list[bool] = []
        setattr(sock, "_lock__ip4_source_filters", tracking)
        setattr(
            sock,
            "_ip4_source_filters",
            _LockAssertingDict(tracking, observed, sock._ip4_source_filters),
        )

        sock.setsockopt(
            IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, bytes(_GROUP) + bytes(_SOURCE) + bytes(Ip4Address("0.0.0.0"))
        )

        self.assertTrue(
            observed,
            msg="The source-membership setsockopt must mutate the source-filter map.",
        )
        self.assertTrue(
            all(observed),
            msg="The source-filter map must be mutated while the per-socket source-filter lock is held.",
        )

    def test__socket__source_admit_read_holds_the_lock(self) -> None:
        """
        Ensure the RX data-plane source-admit gate reads the per-socket
        source-filter map while holding the per-socket source-filter
        lock, so a concurrent application-thread setsockopt cannot tear
        the read on a free-threaded build.

        Reference: RFC 3376 §3.1 (data-plane source-delivery gate).
        """

        sock = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(sock.close)
        tracking = _TrackingRLock()
        setattr(sock, "_lock__ip4_source_filters", tracking)

        sock._ip4_multicast_source_admits(ifindex=1, group=_GROUP, source=_SOURCE)

        self.assertGreaterEqual(
            tracking.max_depth,
            1,
            msg="The RX source-admit gate must acquire the per-socket source-filter lock.",
        )
        self.assertEqual(
            tracking.depth,
            0,
            msg="The RX source-admit gate must release the per-socket source-filter lock.",
        )
