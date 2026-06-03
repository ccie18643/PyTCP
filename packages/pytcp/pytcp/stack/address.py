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
This module contains the address-control API ('AddressApi') — the
kernel/userspace boundary surface that the DHCPv4 client, the RFC 3927
link-local client and (eventually) operator-config tools use to add /
remove / replace host addresses on the stack. The Linux equivalents are
'RTM_NEWADDR' / 'RTM_DELADDR' (rtnetlink) and 'ip addr'. The verbs are
family-agnostic by design; the IPv6 dispatch arm lands in step 2 of the
unification (docs/refactor/address_api_unification.md).

pytcp/stack/address.py

ver 3.0.8
"""

from collections.abc import Callable
from typing import TYPE_CHECKING

from net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr
from pytcp.lib.logger import log
from pytcp.runtime.socket import AddressFamily

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


def _log_dad_conflict(address: Ip6Address, /) -> None:
    """
    The default DAD-conflict handler for an operator 'add(dad=True)' —
    log that the IPv6 host failed Duplicate Address Detection and so was
    not installed.
    """

    log("stack", f"<lg>Address API</>: IPv6 host {address} failed DAD (duplicate); not installed")


class AddressApi:
    """
    The address-control surface — mirrors Linux RTNETLINK
    'RTM_NEWADDR' / 'RTM_DELADDR' / 'ip addr' semantics. The verbs
    ('add' / 'remove' / 'replace' / 'list_ifaddrs') are family-
    agnostic by design (Linux carries the family as a field, not a
    verb); the IPv6 dispatch arm lands in step 2 of the unification
    (docs/refactor/address_api_unification.md), so today the
    implementation handles IPv4 only.

    Implementation: thin wrapper around 'PacketHandler._ip4_ifaddr'
    mutations plus active TCP-session abort via 'SysCall.ABORT'
    (RFC 5227 §2.4-final SHOULD — deliberately stricter than
    Linux's "silent rot" behaviour).

    Consumer code — DHCPv4 client, RFC 3927 link-local client,
    future operator-config CLI — uses ONLY this surface. Never
    reaches into 'packet_handler._ip4_ifaddr' directly. This is the
    architectural seam the Phase-3 north-star turns into a real
    IPC channel; the wrapper internals swap from direct
    attribute mutation to RTNETLINK-equivalent message bus
    routing without any consumer change.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> None:
        """
        Construct the address-control API. With no 'packet_handler'
        this is the unbound, device-independent TOOL (the 'ip addr'
        equivalent) — operate on a specific interface via
        'interface(ifindex)'. With a 'packet_handler' (as returned by
        'interface(ifindex)') it is a VIEW bound to that one interface;
        its reads / mutations operate on that interface's '_ip4_ifaddr'
        list only.
        """

        self._packet_handler = packet_handler

    def _resolve_handler(self) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface this API operates on — the handler bound by
        'interface(ifindex)'. The unbound tool has no default device:
        every per-interface operation MUST select one first, mirroring
        Linux 'ip addr ... dev <ifX>' / RTNETLINK requiring an explicit
        interface index (there is no sole-interface shortcut, even at
        N=1). Raises 'RuntimeError' when called on the unbound tool.
        """

        if self._packet_handler is not None:
            return self._packet_handler

        raise RuntimeError(
            "The bare address tool has no default device; select one via "
            "'stack.address.interface(ifindex)' (Linux 'ip addr ... dev <ifX>')."
        )

    def interface(self, ifindex: int, /) -> "AddressApi":
        """
        Return an 'AddressApi' bound to the interface registered
        under 'ifindex' — the device selector, Linux 'ip addr … dev
        <ifX>' equivalent. Every read / mutation on the returned
        binding operates on that interface's address list. Raises
        'KeyError' when no interface is registered under 'ifindex'.
        """

        from pytcp import stack

        return AddressApi(packet_handler=stack.interfaces[ifindex])

    def add(
        self,
        *,
        ifaddr: Ip4IfAddr | Ip6IfAddr,
        dad_conflict_callback: Callable[[Ip6Address], None] | None = None,
        dad: bool = False,
    ) -> None:
        """
        Install 'ifaddr' on the stack's address list — Linux
        'RTM_NEWADDR' / 'ip addr add' equivalent. The family is
        inferred from the value type. Idempotent against
        duplicate-address installs (the caller's responsibility;
        this method does not de-dup).

        An IPv6 host additionally joins its solicited-node multicast
        group (RFC 4291 §2.7.1; on L2 that also adds the derived
        multicast MAC + an MLD report). By default this verb installs
        the address directly — it does NOT run DAD; DAD is the SLAAC /
        boot path's concern, the same way ARP ACD is the per-protocol
        engine's concern, not an address-plane verb.

        Two opt-ins run an IPv6 address through Duplicate Address
        Detection before it is installed, via the canonical ND DAD
        engine (the claim worker installs the address only once DAD
        passes; on a duplicate the conflict handler is invoked):

        - 'dad_conflict_callback' — a per-protocol engine (the DHCPv6
          client, mirroring the kernel's tentative install of a
          DHCPv6-leased address) supplies its own handler so it can
          react to a duplicate (DECLINE it).
        - 'dad=True' — the operator path (Linux 'ip addr add' for
          IPv6): DAD runs with a default handler that logs a duplicate.

        Both are ignored for an IPv4 'ifaddr' (IPv4 has no DAD; RFC 5227
        ACD is the per-protocol engine's concern).
        """

        handler = self._resolve_handler()
        # Atomic-rebind rather than in-place '.append', under the
        # interface address-config lock: the TX worker iterates the
        # address list during source-address selection on a different
        # thread, so control-plane mutation swaps a fresh list reference
        # (the reader sees the old or new list whole, never a
        # mid-append state) while the lock serializes this writer
        # against the RX / SLAAC / DAD writers. Mirrors 'remove' below.
        if isinstance(ifaddr, Ip6IfAddr):
            on_conflict = (
                dad_conflict_callback if dad_conflict_callback is not None else (_log_dad_conflict if dad else None)
            )
            if on_conflict is not None:
                # DAD-checked install: the claim worker runs DAD and,
                # on success, performs the '_ip6_ifaddr' + solicited-node
                # multicast assignment itself; on a duplicate it invokes
                # the callback. Reuses the canonical ND DAD engine rather
                # than duplicating DAD in the address plane.
                handler._claim_ip6_address_async(ip6_host=ifaddr, on_conflict=on_conflict)
                __debug__ and log("stack", f"<lg>Address API</>: claiming IPv6 host {ifaddr} via DAD")
                return
            with handler._lock__addr_config:
                handler._ip6_ifaddr = [*handler._ip6_ifaddr, ifaddr]
            handler._assign_ip6_multicast(ifaddr.address.solicited_node_multicast)
            __debug__ and log("stack", f"<lg>Address API</>: added IPv6 host {ifaddr}")
            return
        with handler._lock__addr_config:
            handler._ip4_ifaddr = [*handler._ip4_ifaddr, ifaddr]
        __debug__ and log("stack", f"<lg>Address API</>: added IPv4 host {ifaddr}")

    def remove(
        self,
        *,
        address: Ip4Address | Ip6Address,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Remove every host whose '.address' equals 'address' from the
        stack's address list — Linux 'RTM_DELADDR' / 'ip addr del'
        equivalent. The family is inferred from the value type; an
        IPv6 host additionally leaves its solicited-node multicast
        group.

        'abort_bound_sessions=True' (the default) actively
        ABORTs every TCP session bound to the removed address
        per RFC 5227 §2.4-final SHOULD — a deliberate deviation
        from Linux's "silent rot" behaviour. Pass False for
        diagnostics or where the caller has its own
        teardown discipline.
        """

        if abort_bound_sessions:
            self._abort_bound_tcp_sessions(address)

        handler = self._resolve_handler()
        if isinstance(address, Ip6Address):
            with handler._lock__addr_config:
                removed_hosts = [host for host in handler._ip6_ifaddr if host.address == address]
                handler._ip6_ifaddr = [host for host in handler._ip6_ifaddr if host.address != address]
            for host in removed_hosts:
                handler._remove_ip6_multicast(host.address.solicited_node_multicast)
            __debug__ and log(
                "stack",
                f"<lg>Address API</>: removed IPv6 address {address} "
                f"({len(removed_hosts)} host(s); abort_bound_sessions={abort_bound_sessions})",
            )
            return
        with handler._lock__addr_config:
            before = len(handler._ip4_ifaddr)
            handler._ip4_ifaddr = [host for host in handler._ip4_ifaddr if host.address != address]
            removed = before - len(handler._ip4_ifaddr)
        __debug__ and log(
            "stack",
            f"<lg>Address API</>: removed IPv4 address {address} "
            f"({removed} host(s); abort_bound_sessions={abort_bound_sessions})",
        )

    def replace(
        self,
        *,
        old_address: Ip4Address | Ip6Address,
        new_ifaddr: Ip4IfAddr | Ip6IfAddr,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Atomic-ish swap: install 'new_ifaddr' BEFORE removing the
        host(es) keyed by 'old_address'. The transient overlap
        parallels Linux's 'RTM_NEWADDR' → 'RTM_DELADDR' ordering
        (RTNETLINK guarantees the kernel processes them in the
        order received; a brief window with both addresses present
        is normal).

        TCP sessions bound to 'old_address' are aborted per
        'abort_bound_sessions' once the new address is installed,
        matching the RFC 5227 §2.4-final SHOULD policy 'remove'
        already applies.
        """

        self.add(ifaddr=new_ifaddr)
        self.remove(
            address=old_address,
            abort_bound_sessions=abort_bound_sessions,
        )

    def list_ifaddrs(
        self,
        *,
        family: AddressFamily | None = None,
    ) -> tuple[Ip4IfAddr | Ip6IfAddr, ...]:
        """
        Return a read-only copy-by-value snapshot of the stack's
        host-address list — Linux 'ip addr show' equivalent. With no
        'family' the snapshot covers both families (IPv4 first, then
        IPv6); pass 'AddressFamily.INET4' / 'INET6' to filter (the
        Linux 'ip -4' / 'ip -6' selectors). The returned tuple is
        immutable; the caller cannot mutate stack state through it
        (matches the Phase-3 north-star "introspection is read-only"
        constraint from CLAUDE.md).
        """

        handler = self._resolve_handler()
        ifaddrs: list[Ip4IfAddr | Ip6IfAddr] = []
        if family in (None, AddressFamily.INET4):
            ifaddrs.extend(handler._ip4_ifaddr)
        if family in (None, AddressFamily.INET6):
            ifaddrs.extend(handler._ip6_ifaddr)
        return tuple(ifaddrs)

    @staticmethod
    def _abort_bound_tcp_sessions(address: Ip4Address | Ip6Address) -> None:
        """
        Issue 'SysCall.ABORT' to every TCP session whose local
        address equals 'address'. The ABORT syscall emits RST and
        tears the session down per RFC 9293 §3.10.7.4. Family-
        agnostic — 'socket_id.local_address' matches either an
        Ip4Address or an Ip6Address.
        """

        from pytcp import stack
        from pytcp.protocols.tcp.tcp__enums import SysCall

        # 'items()' flattens every cohort member (so each socket of a
        # SO_REUSEPORT cohort bound to 'address' is visited, not just
        # the first) and returns a detached snapshot, safe to iterate
        # while the ABORT-driven teardown unregisters sockets.
        for socket_id, sock in stack.sockets.items():
            if socket_id.local_address == address:
                session = getattr(sock, "_tcp_session", None)
                if session is not None:
                    session.tcp_fsm(syscall=SysCall.ABORT)
