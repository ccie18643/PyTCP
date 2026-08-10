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
This module contains the IPv6 multicast-membership-control API
('Membership6Api') — the kernel/userspace boundary surface for joining
and leaving IPv6 multicast groups on an interface. The Linux
equivalents are the 'IPV6_JOIN_GROUP' / 'IPV6_LEAVE_GROUP' /
'MCAST_JOIN_SOURCE_GROUP' family socket options (which dispatch here)
and 'ip maddr'. The MLD host state machine (signalling membership to
routers) layers on top of the group state this API maintains. The IPv6
(MLDv2) analogue of 'MembershipApi'.

pytcp/stack/membership6.py

ver 3.0.9
"""

from typing import TYPE_CHECKING

from net_addr import Ip6Address
from pytcp.lib.ip6_multicast_filter import Ip6MulticastFilter
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# The IPv6 all-nodes group every host joins permanently and never leaves
# (RFC 4291 §2.7.1); the membership API refuses to drop it. The v6
# analogue of the IPv4 all-systems group 224.0.0.1.
IP6__MULTICAST__ALL_NODES = Ip6Address("ff02::1")


class Membership6Api:
    """
    The IPv6 multicast-membership-control surface — joins / leaves IPv6
    multicast groups on an interface and exposes the current group set.
    Mirrors the Linux 'IPV6_JOIN_GROUP' / 'IPV6_LEAVE_GROUP' /
    'MCAST_JOIN_SOURCE_GROUP' family socket options and 'ip maddr'. The
    IPv6 (MLDv2) analogue of 'MembershipApi'.

    Consumer code — the BSD socket facade's membership options, the
    example apps, future operator-config tools — uses ONLY this surface.
    It never reaches into the packet handler's multicast reception state
    directly; that is the Phase-3 architectural seam.

    Two contributor kinds drive a group's interface reception state: the
    operator hold ('join' / 'leave', a set-once any-source EXCLUDE{}
    contributor) and the per-socket source filters ('set_socket_filter'
    / 'clear_socket_filter', keyed by an opaque socket token, carrying
    RFC 3810 §4.1 INCLUDE / EXCLUDE source lists). The interface filter
    is the RFC 3810 §4.2 merge of all contributors; the group stays
    joined while that merge has reception state. Unlike the IPv4 surface,
    there is no group-count cap — Linux has no IPv6 analogue of
    'igmp_max_memberships'.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> None:
        """
        Construct the membership-control API. With no 'packet_handler'
        this is the unbound, device-independent TOOL — operate on a
        specific interface via 'interface(ifindex)'. With a
        'packet_handler' (as returned by 'interface(ifindex)') it is a
        VIEW bound to that one interface.
        """

        self._packet_handler = packet_handler

    def _resolve_handler(self) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface this API operates on — the handler bound by
        'interface(ifindex)'. The unbound tool has no default device;
        every operation MUST select one first, mirroring Linux requiring
        an explicit interface. Raises 'RuntimeError' on the unbound tool.
        """

        if self._packet_handler is not None:
            return self._packet_handler

        raise RuntimeError(
            "The bare membership tool has no default device; select one via " "'stack.membership6.interface(ifindex)'."
        )

    def interface(self, ifindex: int, /) -> Membership6Api:
        """
        Return a 'Membership6Api' bound to the interface registered under
        'ifindex' — the device selector. Raises 'KeyError' when no
        interface is registered under 'ifindex'.
        """

        from pytcp import stack

        return Membership6Api(packet_handler=stack.interfaces[ifindex])

    def join(self, *, group: Ip6Address) -> None:
        """
        Join the IPv6 multicast 'group' on the bound interface as the
        operator hold ('ip maddr' / the operator surface). The actual
        join + MLD Report fires only when the group crosses the
        not-joined→joined edge; the operator hold is idempotent. The
        per-socket source-filter holds (the BSD socket options) go
        through 'set_socket_filter' instead. Raises 'ValueError' for a
        non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        handler = self._resolve_handler()
        handler.mc6_ref_acquire(group)
        __debug__ and log("stack", f"<lg>Membership6 API</>: joined IPv6 group {group} (operator)")

    def leave(self, *, group: Ip6Address) -> None:
        """
        Release the operator hold on the IPv6 multicast 'group' on the
        bound interface ('ip maddr' / the operator surface). The actual
        leave + MLD Leave Report fires only when the last contributor
        (operator or socket) is dropped (the joined→not-joined edge).
        Idempotent. Refuses to drop the all-nodes group ff02::1, which a
        host belongs to permanently (RFC 4291 §2.7.1). Raises
        'ValueError' for a non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        if group == IP6__MULTICAST__ALL_NODES:
            raise ValueError("The all-nodes group ff02::1 is joined permanently and cannot be left (RFC 4291 §2.7.1).")

        handler = self._resolve_handler()
        handler.mc6_ref_release(group)
        __debug__ and log("stack", f"<lg>Membership6 API</>: left IPv6 group {group} (operator)")

    def set_socket_filter(self, *, group: Ip6Address, token: int, source_filter: Ip6MulticastFilter) -> None:
        """
        Register / replace the per-socket source filter (RFC 3810 §4.1)
        that the socket identified by the opaque 'token' holds on the
        IPv6 multicast 'group', then re-derive the merged interface
        filter (§4.2). This is the surface the BSD socket facade's
        'IPV6_JOIN_GROUP' / 'MCAST_JOIN_SOURCE_GROUP' /
        'MCAST_BLOCK_SOURCE' family dispatches to; the per-option state
        machine + errno mapping live in the facade.
        """

        handler = self._resolve_handler()
        handler.mc6_set_socket_filter(group, token=token, source_filter=source_filter)

    def clear_socket_filter(self, *, group: Ip6Address, token: int) -> None:
        """
        Drop the per-socket source filter the socket identified by 'token'
        held on the IPv6 multicast 'group' (the socket left — RFC 3810
        §4.1 INCLUDE{} delete) and re-derive the merged interface filter
        (§4.2). The surface the BSD socket facade's 'IPV6_LEAVE_GROUP' /
        'MCAST_LEAVE_SOURCE_GROUP'-to-empty paths and socket close
        dispatch to. Idempotent.
        """

        handler = self._resolve_handler()
        handler.mc6_clear_socket_filter(group, token=token)

    def list_memberships(self) -> tuple[Ip6Address, ...]:
        """
        Return a read-only copy-by-value snapshot of the IPv6 multicast
        groups the bound interface listens on — Linux 'ip maddr show'
        equivalent. The returned tuple is immutable; the caller cannot
        mutate stack state through it.
        """

        handler = self._resolve_handler()

        return tuple(handler.ip6_multicast)
