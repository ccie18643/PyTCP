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
This module contains tests for the address-control API
('AddressApi') in 'pytcp/stack/address.py'.

pytcp/tests/unit/stack/test__stack__address.py

ver 3.0.8
"""

import inspect
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr
from pytcp import stack
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.socket import AddressFamily
from pytcp.stack.address import (
    AddressApi,
)

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class _FakePacketHandler:
    """
    Minimal packet-handler stand-in for 'AddressApi' tests — exposes the
    public 'assign_*_ifaddr' / 'remove_*_ifaddr' mutators (lock + COW
    internalized, the no-GIL N1 guard) and 'ip4_ifaddr' / 'ip6_ifaddr'
    read snapshots the API consumes, plus the IPv6 solicited-node-
    multicast join/leave hooks. Using a hand-rolled class avoids the
    autospec ceremony for a 50-attribute production class.
    """

    def __init__(self) -> None:
        self._ip4_ifaddr: list[Ip4IfAddr] = []
        self._ip6_ifaddr: list[Ip6IfAddr] = []
        # The mutators rebind the ifaddr lists copy-on-write under the
        # interface address-config lock (the no-GIL N1 guard); the
        # stand-in supplies a real reentrant lock so the context-managed
        # mutation runs.
        self._lock__addr_config = threading.RLock()
        # Record the solicited-node-multicast groups the API joins /
        # leaves so the v6 tests can assert on SNM management.
        self.joined_snm: list[Ip6Address] = []
        self.left_snm: list[Ip6Address] = []
        # Record DAD-checked claims the API delegates here so the
        # 'dad_conflict_callback' delegation can be asserted.
        self.dad_claims: list[tuple[Ip6IfAddr, Callable[[Ip6Address], None] | None]] = []

    @property
    def ip4_ifaddr(self) -> tuple[Ip4IfAddr, ...]:
        return tuple(self._ip4_ifaddr)

    @property
    def ip6_ifaddr(self) -> tuple[Ip6IfAddr, ...]:
        return tuple(self._ip6_ifaddr)

    def assign_ip4_ifaddr(self, ifaddr: Ip4IfAddr, /) -> None:
        with self._lock__addr_config:
            self._ip4_ifaddr = [*self._ip4_ifaddr, ifaddr]

    def remove_ip4_ifaddr(self, address: Ip4Address, /) -> int:
        with self._lock__addr_config:
            before = len(self._ip4_ifaddr)
            self._ip4_ifaddr = [host for host in self._ip4_ifaddr if host.address != address]
            return before - len(self._ip4_ifaddr)

    def assign_ip6_ifaddr(self, ifaddr: Ip6IfAddr, /) -> None:
        with self._lock__addr_config:
            self._ip6_ifaddr = [*self._ip6_ifaddr, ifaddr]
        self.joined_snm.append(ifaddr.address.solicited_node_multicast)

    def remove_ip6_ifaddr(self, address: Ip6Address, /) -> list[Ip6IfAddr]:
        with self._lock__addr_config:
            removed_hosts = [host for host in self._ip6_ifaddr if host.address == address]
            self._ip6_ifaddr = [host for host in self._ip6_ifaddr if host.address != address]
        for host in removed_hosts:
            self.left_snm.append(host.address.solicited_node_multicast)
        return removed_hosts

    def set_ifindex(self, ifindex: int, /) -> None:
        self._ifindex = ifindex

    def claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        on_conflict: Callable[[Ip6Address], None] | None = None,
    ) -> None:
        self.dad_claims.append((ip6_host, on_conflict))


class TestAddressApiAddHost(TestCase):
    """
    'AddressApi.add' installs an Ip4IfAddr on the stack's
    address list.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler for the API to mutate.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__add_host_appends_to_packet_handler_list(self) -> None:
        """
        Ensure 'add' appends the supplied 'Ip4IfAddr' to the
        packet handler's '_ip4_ifaddr' list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("10.0.0.5/24")

        self._api.add(ifaddr=host)

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [host],
            msg="add must append the supplied Ip4IfAddr to the packet handler list.",
        )

    def test__ip4_address_api__add_host_preserves_existing_hosts(self) -> None:
        """
        Ensure 'add' is additive — pre-existing hosts on the
        packet handler list survive an add call. Mirrors
        Linux RTM_NEWADDR semantics (additive, not replacing).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        existing = Ip4IfAddr("10.0.0.4/24")
        self._packet_handler._ip4_ifaddr.append(existing)

        new = Ip4IfAddr("10.0.0.5/24")
        self._api.add(ifaddr=new)

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [existing, new],
            msg="add must preserve pre-existing hosts.",
        )

    def test__ip4_address_api__add_host_atomically_rebinds_list(self) -> None:
        """
        Ensure 'add' rebinds '_ip4_ifaddr' to a fresh list
        object rather than mutating the existing list in place, so the
        TX worker iterating the list during source-address selection
        always reads a consistent snapshot (Phase 4 single-writer-safe
        read — control-plane mutation must not be observable mid-update
        by the reading TX thread).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original_list = self._packet_handler._ip4_ifaddr

        self._api.add(ifaddr=Ip4IfAddr("10.0.0.5/24"))

        self.assertIsNot(
            self._packet_handler._ip4_ifaddr,
            original_list,
            msg="add must rebind _ip4_ifaddr to a new list, not mutate the existing one in place.",
        )


class TestAddressApiRemoveHost(TestCase):
    """
    'AddressApi.remove' removes hosts keyed by address and
    optionally ABORTs bound TCP sessions per the RFC 5227 §2.4-final
    SHOULD (deliberate deviation from Linux's silent-rot).
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's log line and stand up a fake packet
        handler pre-populated with a single host.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._target_host = Ip4IfAddr("10.0.0.5/24")
        self._other_host = Ip4IfAddr("10.0.0.6/24")
        self._packet_handler._ip4_ifaddr = [self._target_host, self._other_host]
        self._api = AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__remove_host_drops_matching_address(self) -> None:
        """
        Ensure 'remove' filters out every Ip4IfAddr whose
        '.address' equals the supplied 'ip4_address' and leaves
        other hosts intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove(address=Ip4Address("10.0.0.5"))

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [self._other_host],
            msg="remove must drop only the host matching the supplied address.",
        )

    def test__ip4_address_api__remove_host_default_aborts_bound_sessions(self) -> None:
        """
        Ensure 'remove' defaults to ABORTing TCP sessions
        bound to the address — the deliberate deviation from
        Linux's silent-rot behaviour.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset existing connections).
        """

        with patch.object(AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove(address=Ip4Address("10.0.0.5"))

        mock_abort.assert_called_once_with(Ip4Address("10.0.0.5"))

    def test__ip4_address_api__remove_host_abort_false_skips_abort(self) -> None:
        """
        Ensure 'remove(abort_bound_sessions=False)' performs
        the address removal without aborting TCP sessions —
        Linux-parity "silent rot" semantic for diagnostics or
        for callers with their own teardown discipline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove(
                address=Ip4Address("10.0.0.5"),
                abort_bound_sessions=False,
            )

        mock_abort.assert_not_called()
        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [self._other_host],
            msg="remove(abort=False) must still remove the address from the host list.",
        )

    def test__ip4_address_api__remove_host_unknown_address_is_noop(self) -> None:
        """
        Ensure 'remove' for an address not present on the
        packet handler list is a no-op (still aborts any matching
        TCP sessions, but the list filter naturally leaves
        everything intact).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove(address=Ip4Address("10.0.0.99"))

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [self._target_host, self._other_host],
            msg="remove for an unknown address must leave the host list unchanged.",
        )


class TestAddressApiReplaceHost(TestCase):
    """
    'AddressApi.replace' atomically swaps an old address
    for a new Ip4IfAddr — RTM_NEWADDR-before-RTM_DELADDR ordering.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake packet handler with one host installed
        that the test will swap out.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._old_host = Ip4IfAddr("10.0.0.5/24")
        self._packet_handler._ip4_ifaddr = [self._old_host]
        self._api = AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__replace_host_installs_new_and_removes_old(self) -> None:
        """
        Ensure 'replace' ends with the new host installed
        and the old address removed — net effect equivalent to
        'remove(old) + add(new)' but with the install-
        before-remove ordering Linux RTNETLINK guarantees.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_host = Ip4IfAddr("10.0.0.7/24")

        with patch.object(AddressApi, "_abort_bound_tcp_sessions"):
            self._api.replace(
                old_address=Ip4Address("10.0.0.5"),
                new_ifaddr=new_host,
            )

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [new_host],
            msg="replace must leave only the new host installed; the old address is removed.",
        )

    def test__ip4_address_api__replace_host_installs_new_before_removing_old(self) -> None:
        """
        Ensure 'replace' installs the new host BEFORE
        removing the old (matching Linux RTM_NEWADDR →
        RTM_DELADDR ordering). The transient overlap is observable
        by stubbing '_abort_bound_tcp_sessions' to capture the
        host-list state at the moment of the abort.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_host = Ip4IfAddr("10.0.0.7/24")
        snapshot_at_abort: list[Ip4IfAddr] = []

        def _snapshot(_: Ip4Address) -> None:
            snapshot_at_abort.extend(self._packet_handler._ip4_ifaddr)

        with patch.object(AddressApi, "_abort_bound_tcp_sessions", side_effect=_snapshot):
            self._api.replace(
                old_address=Ip4Address("10.0.0.5"),
                new_ifaddr=new_host,
            )

        # At the moment '_abort_bound_tcp_sessions' fired (during
        # the remove half of the swap), BOTH old and new must
        # have been present on the list.
        self.assertIn(
            new_host,
            snapshot_at_abort,
            msg="replace must install the new host BEFORE the abort-and-remove of the old.",
        )
        self.assertIn(
            self._old_host,
            snapshot_at_abort,
            msg="replace must NOT have removed the old host before the abort fired.",
        )


class TestAddressApiListIp4Hosts(TestCase):
    """
    'AddressApi.list_ifaddrs' returns a read-only snapshot of
    the stack's IPv4 address list.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake packet handler with two hosts installed
        so the snapshot test has something to read.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._packet_handler._ip4_ifaddr = [Ip4IfAddr("10.0.0.5/24"), Ip4IfAddr("10.0.0.6/24")]
        self._api = AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__list_returns_tuple_copy(self) -> None:
        """
        Ensure 'list_ifaddrs' returns a tuple (immutable) snapshot
        — the caller cannot mutate stack state through it. Matches
        the Phase-3 "introspection is read-only / copy-by-value"
        contract from CLAUDE.md.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = self._api.list_ifaddrs()

        self.assertIsInstance(
            snapshot,
            tuple,
            msg="list_ifaddrs must return a tuple (immutable snapshot).",
        )
        self.assertEqual(
            len(snapshot),
            2,
            msg="Snapshot must contain every host installed on the packet handler.",
        )

    def test__ip4_address_api__list_decouples_from_underlying_list(self) -> None:
        """
        Ensure mutating the underlying packet handler list AFTER
        calling 'list_ifaddrs' does NOT mutate the returned
        snapshot — the tuple is a copy, not a view.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = self._api.list_ifaddrs()
        before_len = len(snapshot)

        self._packet_handler._ip4_ifaddr.clear()

        self.assertEqual(
            len(snapshot),
            before_len,
            msg="The returned snapshot must be decoupled from subsequent stack mutations.",
        )


class TestAddressApiIp6(TestCase):
    """
    The 'AddressApi' IPv6 dispatch arm — 'add' / 'remove' /
    'replace' / 'list_ifaddrs' route Ip6IfAddr / Ip6Address through
    the '_ip6_ifaddr' list and the solicited-node-multicast join /
    leave hooks, with the same atomic-rebind discipline as IPv4.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's log line and stand up a fake packet
        handler the API mutates.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__address_api__add_ip6_with_dad_false_appends_and_joins_solicited_node_multicast(self) -> None:
        """
        Ensure 'add(dad=False)' with an Ip6IfAddr installs it directly on
        '_ip6_ifaddr' and joins the address's solicited-node multicast
        group, leaving '_ip4_ifaddr' untouched and running no DAD.

        Reference: RFC 4291 §2.7.1 (solicited-node multicast address).
        """

        host = Ip6IfAddr("2001:db8::5/64")

        self._api.add(ifaddr=host, dad=False)

        self.assertEqual(
            self._packet_handler._ip6_ifaddr,
            [host],
            msg="add(Ip6IfAddr, dad=False) must append the host to '_ip6_ifaddr'.",
        )
        self.assertEqual(
            self._packet_handler.dad_claims,
            [],
            msg="add(Ip6IfAddr, dad=False) must not run DAD.",
        )
        self.assertEqual(
            self._packet_handler.joined_snm,
            [host.address.solicited_node_multicast],
            msg="add(Ip6IfAddr, dad=False) must join the host's solicited-node multicast group.",
        )
        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [],
            msg="add(Ip6IfAddr) must not touch the IPv4 address list.",
        )

    def test__address_api__add_ip6_with_dad_callback_delegates_to_dad_claim(self) -> None:
        """
        Ensure 'add' with a 'dad_conflict_callback' runs DAD via the
        packet handler's claim engine (passing the callback through as
        'on_conflict') instead of installing the address directly.

        Reference: RFC 8415 §18.2.8 (DHCPv6 address must pass DAD before use).
        """

        host = Ip6IfAddr("2001:db8::5/128")

        def _on_conflict(_: Ip6Address) -> None:
            pass

        self._api.add(ifaddr=host, dad_conflict_callback=_on_conflict)

        self.assertEqual(
            self._packet_handler.dad_claims,
            [(host, _on_conflict)],
            msg="add with a DAD callback must delegate to the claim engine with the callback as on_conflict.",
        )
        self.assertEqual(
            self._packet_handler._ip6_ifaddr,
            [],
            msg="A DAD-checked add must not install the address directly (the claim worker does on success).",
        )

    def test__address_api__add_ip6_defaults_to_dad(self) -> None:
        """
        Ensure a bare IPv6 'add' (no flag) runs DAD by default via the
        claim engine with a default conflict handler, instead of
        installing the address directly — DAD is mandatory for every IPv6
        unicast address.

        Reference: RFC 4862 §5.4 (Duplicate Address Detection — mandatory on all unicast addresses).
        """

        host = Ip6IfAddr("2001:db8::5/128")

        self._api.add(ifaddr=host)

        self.assertEqual(
            len(self._packet_handler.dad_claims), 1, msg="A bare IPv6 add must delegate to the claim engine (DAD)."
        )
        claimed_host, on_conflict = self._packet_handler.dad_claims[0]
        self.assertEqual(claimed_host, host, msg="The claimed host must be the supplied address.")
        self.assertIsNotNone(on_conflict, msg="A default IPv6 add must supply a default DAD-conflict handler.")
        self.assertEqual(
            self._packet_handler._ip6_ifaddr,
            [],
            msg="A DAD-checked add must not install the address directly.",
        )

    def test__address_api__add_ip4_ignores_dad_default(self) -> None:
        """
        Ensure a bare IPv4 'add' installs directly — IPv4 has no DAD (the
        dad default never applies; RFC 5227 ACD is the per-protocol
        engine's concern).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("10.0.0.5/24")

        self._api.add(ifaddr=host)

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [host],
            msg="An IPv4 add must install directly regardless of the dad default.",
        )
        self.assertEqual(self._packet_handler.dad_claims, [], msg="An IPv4 add must not run DAD.")

    def test__address_api__add_ip6_with_dad_false_atomically_rebinds_list(self) -> None:
        """
        Ensure a direct ('dad=False') IPv6 'add' rebinds '_ip6_ifaddr' to
        a fresh list object rather than mutating in place, so the TX
        worker reading the list on another thread always sees a
        consistent snapshot.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original_list = self._packet_handler._ip6_ifaddr

        self._api.add(ifaddr=Ip6IfAddr("2001:db8::5/64"), dad=False)

        self.assertIsNot(
            self._packet_handler._ip6_ifaddr,
            original_list,
            msg="add(Ip6IfAddr) must rebind '_ip6_ifaddr' to a new list, not mutate in place.",
        )

    def test__address_api__remove_ip6_drops_address_and_leaves_multicast(self) -> None:
        """
        Ensure 'remove' with an Ip6Address drops every matching host
        from '_ip6_ifaddr' and leaves the solicited-node multicast
        group, rebinding the list.

        Reference: RFC 4291 §2.7.1 (solicited-node multicast address).
        """

        target = Ip6IfAddr("2001:db8::5/64")
        other = Ip6IfAddr("2001:db8::6/64")
        self._packet_handler._ip6_ifaddr = [target, other]
        original_list = self._packet_handler._ip6_ifaddr

        with patch.object(AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove(address=Ip6Address("2001:db8::5"))

        self.assertEqual(
            self._packet_handler._ip6_ifaddr,
            [other],
            msg="remove(Ip6Address) must drop only the matching host.",
        )
        self.assertEqual(
            self._packet_handler.left_snm,
            [target.address.solicited_node_multicast],
            msg="remove(Ip6Address) must leave the removed host's solicited-node multicast group.",
        )
        self.assertIsNot(
            self._packet_handler._ip6_ifaddr,
            original_list,
            msg="remove(Ip6Address) must rebind '_ip6_ifaddr' to a new list.",
        )

    def test__address_api__remove_ip6_aborts_bound_sessions_by_default(self) -> None:
        """
        Ensure 'remove' with an Ip6Address defaults to ABORTing TCP
        sessions bound to the address — the same abort policy the
        IPv4 arm applies, via the family-agnostic abort helper.

        Reference: RFC 5227 §2.4 final paragraph (reset existing connections).
        """

        with patch.object(AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove(address=Ip6Address("2001:db8::5"))

        mock_abort.assert_called_once_with(Ip6Address("2001:db8::5"))

    def test__address_api__replace_ip6_installs_new_before_removing_old(self) -> None:
        """
        Ensure 'replace' with IPv6 arguments installs the new host
        and then removes the old one — the family-agnostic verb
        dispatches both legs through the IPv6 arm.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        old = Ip6IfAddr("2001:db8::5/64")
        new = Ip6IfAddr("2001:db8::9/64")
        self._packet_handler._ip6_ifaddr = [old]

        with patch.object(AddressApi, "_abort_bound_tcp_sessions"):
            self._api.replace(old_address=Ip6Address("2001:db8::5"), new_ifaddr=new)

        self.assertEqual(
            self._packet_handler._ip6_ifaddr,
            [new],
            msg="replace must end with only the new IPv6 host installed.",
        )

    def test__address_api__list_ifaddrs_no_family_returns_both(self) -> None:
        """
        Ensure 'list_ifaddrs()' with no family filter returns every
        host of both families — IPv4 first, then IPv6.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        v4 = Ip4IfAddr("10.0.0.5/24")
        v6 = Ip6IfAddr("2001:db8::5/64")
        self._packet_handler._ip4_ifaddr = [v4]
        self._packet_handler._ip6_ifaddr = [v6]

        self.assertEqual(
            self._api.list_ifaddrs(),
            (v4, v6),
            msg="list_ifaddrs() must return both families, IPv4 first.",
        )

    def test__address_api__list_ifaddrs_family_filters(self) -> None:
        """
        Ensure 'list_ifaddrs(family=...)' returns only the hosts of
        the requested family.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        v4 = Ip4IfAddr("10.0.0.5/24")
        v6 = Ip6IfAddr("2001:db8::5/64")
        self._packet_handler._ip4_ifaddr = [v4]
        self._packet_handler._ip6_ifaddr = [v6]

        self.assertEqual(
            self._api.list_ifaddrs(family=AddressFamily.INET4),
            (v4,),
            msg="list_ifaddrs(INET4) must return only the IPv4 hosts.",
        )
        self.assertEqual(
            self._api.list_ifaddrs(family=AddressFamily.INET6),
            (v6,),
            msg="list_ifaddrs(INET6) must return only the IPv6 hosts.",
        )


class TestAddressApiAbortBoundSessions(TestCase):
    """
    '_abort_bound_tcp_sessions' issues SysCall.ABORT to every TCP
    session whose local_address matches the supplied IPv4 address.
    """

    def test__ip4_address_api__abort_dispatches_abort_syscall_to_matching_sessions(self) -> None:
        """
        Ensure '_abort_bound_tcp_sessions' walks every session in
        'stack.sockets' and issues 'SysCall.ABORT' against the
        ones whose 'local_address' equals the target IPv4
        address. Sessions on other addresses are left alone.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset existing connections).
        Reference: RFC 9293 §3.10.7.4 (ABORT emits RST and tears the session down).
        """

        from pytcp import stack
        from pytcp.protocols.tcp.tcp__enums import SysCall

        target_addr = Ip4Address("10.0.0.5")
        other_addr = Ip4Address("10.0.0.99")

        match_session = MagicMock(name="MatchingTcpSession")
        other_session = MagicMock(name="OtherTcpSession")
        match_sock = MagicMock(name="MatchingSocket", _tcp_session=match_session)
        other_sock = MagicMock(name="OtherSocket", _tcp_session=other_session)

        match_socket_id = MagicMock(local_address=target_addr)
        other_socket_id = MagicMock(local_address=other_addr)

        fake_sockets = {match_socket_id: match_sock, other_socket_id: other_sock}

        with patch.object(stack, "sockets", fake_sockets):
            AddressApi._abort_bound_tcp_sessions(target_addr)

        match_session.tcp_fsm.assert_called_once_with(syscall=SysCall.ABORT)
        other_session.tcp_fsm.assert_not_called()

    def test__ip4_address_api__abort_skips_non_tcp_sockets(self) -> None:
        """
        Ensure '_abort_bound_tcp_sessions' silently skips sockets
        whose '_tcp_session' attribute is None (UDP / raw sockets)
        — only TCP sessions need explicit ABORT.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp import stack

        target_addr = Ip4Address("10.0.0.5")
        udp_sock = MagicMock(name="UdpSocket", _tcp_session=None)
        udp_socket_id = MagicMock(local_address=target_addr)
        fake_sockets = {udp_socket_id: udp_sock}

        with patch.object(stack, "sockets", fake_sockets):
            AddressApi._abort_bound_tcp_sessions(target_addr)

        # No assertion needed beyond "doesn't raise" — the UDP
        # socket has no '_tcp_session.tcp_fsm' attribute, so a
        # naive call would AttributeError. The implementation
        # must gate on the None check.


class TestAddressApiInterfaceSelector(TestCase):
    """
    The 'AddressApi.interface(ifindex)' device-selector tests.
    """

    @override
    def setUp(self) -> None:
        """
        Register two fake interfaces in a fresh 'stack.interfaces'
        table; bind the API singleton to interface 1.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._iface_1 = _FakePacketHandler()
        self._iface_2 = _FakePacketHandler()
        table = InterfaceTable()
        table[1] = cast("PacketHandlerL2", self._iface_1)
        table[2] = cast("PacketHandlerL2", self._iface_2)
        self.enterContext(patch.object(stack, "interfaces", table))
        self._api = AddressApi(packet_handler=cast("PacketHandlerL2", self._iface_1))

    def test__address_api__interface__add_lands_on_named_interface(self) -> None:
        """
        Ensure 'interface(ifindex).add' installs the address on
        that interface's own '_ip4_ifaddr' list, leaving other
        interfaces' address lists untouched.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        host = Ip4IfAddr("10.0.2.7/24")
        self._api.interface(2).add(ifaddr=host)

        self.assertEqual(
            self._iface_2._ip4_ifaddr,
            [host],
            msg="interface(2).add must install on interface 2's address list.",
        )
        self.assertEqual(
            self._iface_1._ip4_ifaddr,
            [],
            msg="interface 1's address list must be untouched.",
        )

    def test__address_api__interface__list_reads_named_interface(self) -> None:
        """
        Ensure 'interface(ifindex).list_ifaddrs' reads that
        interface's own address list.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        host = Ip4IfAddr("10.0.2.7/24")
        self._iface_2._ip4_ifaddr = [host]

        self.assertEqual(
            self._api.interface(2).list_ifaddrs(),
            (host,),
            msg="interface(2).list_ifaddrs must read interface 2's address list.",
        )

    def test__address_api__interface__unknown_ifindex_raises(self) -> None:
        """
        Ensure 'interface(ifindex)' on an unregistered ifindex raises
        KeyError — the registry has no such device.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        with self.assertRaises(KeyError):
            self._api.interface(99)


class TestAddressApiUnboundTool(TestCase):
    """
    The 'AddressApi' unbound userspace-tool tests — an
    'AddressApi()' built with no handler is the device-independent
    tool ('ip addr'); it has no default device, so every per-interface
    read / mutation MUST select one via '.interface(ifindex)' (Linux
    'ip addr ... dev <ifX>'), and a bare per-interface operation raises
    regardless of how many interfaces are registered.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line.
        """

        self.enterContext(patch("pytcp.stack.address.log"))

    def _install(self, count: int) -> list[_FakePacketHandler]:
        """
        Register 'count' fake interfaces in a fresh 'stack.interfaces'
        table and return them.
        """

        ifaces = [_FakePacketHandler() for _ in range(count)]
        table = InterfaceTable()
        for iface in ifaces:
            table.add(cast("PacketHandlerL2", iface))
        self.enterContext(patch.object(stack, "interfaces", table))
        return ifaces

    def test__address_api__unbound_tool__bare_read_raises_with_sole_interface(self) -> None:
        """
        Ensure a bare read on the unbound tool raises even when exactly
        one interface is registered — there is no sole-interface
        default; the caller must select a device, like Linux
        'ip addr ... dev <ifX>'.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        (iface,) = self._install(1)
        iface._ip4_ifaddr = [Ip4IfAddr("10.0.0.5/24")]
        tool = AddressApi()

        with self.assertRaises(RuntimeError):
            tool.list_ifaddrs()

    def test__address_api__unbound_tool__bare_mutation_raises_with_sole_interface(self) -> None:
        """
        Ensure a bare mutation on the unbound tool raises even when
        exactly one interface is registered, and leaves that interface
        untouched — there is no sole-interface default.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        (iface,) = self._install(1)
        host = Ip4IfAddr("10.0.0.5/24")
        tool = AddressApi()

        with self.assertRaises(RuntimeError):
            tool.add(ifaddr=host)

        self.assertEqual(
            iface._ip4_ifaddr,
            [],
            msg="A bare mutation on the unbound tool must not touch any interface.",
        )

    def test__address_api__unbound_tool__bare_read_raises_when_no_interface(self) -> None:
        """
        Ensure a bare read on the unbound tool raises when no interface
        is registered — there is no device to report on.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        self._install(0)
        tool = AddressApi()

        with self.assertRaises(RuntimeError):
            tool.list_ifaddrs()

    def test__address_api__unbound_tool__bare_read_raises_when_ambiguous(self) -> None:
        """
        Ensure a bare read on the unbound tool raises when more than one
        interface is registered — the caller must select a device via
        'interface(ifindex)'.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        self._install(2)
        tool = AddressApi()

        with self.assertRaises(RuntimeError):
            tool.list_ifaddrs()

    def test__address_api__unbound_tool__interface_selector_works_when_ambiguous(self) -> None:
        """
        Ensure explicit 'interface(ifindex)' selection on the unbound
        tool reads the named device even when several interfaces are
        registered (where a bare read would be ambiguous).

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        ifaces = self._install(3)
        host = Ip4IfAddr("10.0.2.7/24")
        ifaces[1]._ip4_ifaddr = [host]
        tool = AddressApi()

        self.assertEqual(
            tool.interface(2).list_ifaddrs(),
            (host,),
            msg="interface(2) on the unbound tool must read interface 2's address list.",
        )


class TestAddressApi__KeywordOnlySignatures(TestCase):
    """
    Pin the keyword-only parameters on every AddressApi method so the
    '*'→'/' separator mutation is caught.
    """

    def test__address__api_methods_are_keyword_only(self) -> None:
        """
        Ensure each AddressApi mutation/query method keeps its
        parameters keyword-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected = {
            "add": {"ifaddr", "dad_conflict_callback", "dad"},
            "list_ifaddrs": {"family"},
            "remove": {"address", "abort_bound_sessions"},
            "replace": {"old_address", "new_ifaddr", "abort_bound_sessions"},
        }
        for method, names in expected.items():
            params = inspect.signature(getattr(AddressApi, method)).parameters
            kw_only = {name for name, param in params.items() if param.kind is inspect.Parameter.KEYWORD_ONLY}
            self.assertEqual(
                kw_only,
                names,
                msg=f"AddressApi.{method} must keep keyword-only parameters {names}.",
            )
