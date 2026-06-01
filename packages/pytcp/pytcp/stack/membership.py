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
This module contains the multicast-membership-control API
('MembershipApi') — the kernel/userspace boundary surface for joining
and leaving IPv4 multicast groups on an interface. The Linux
equivalents are the 'IP_ADD_MEMBERSHIP' / 'IP_DROP_MEMBERSHIP' socket
options (which dispatch here) and 'ip maddr'. The IGMP host state
machine (signalling membership to routers) layers on top of the group
state this API maintains.

pytcp/stack/membership.py

ver 3.0.8
"""

from typing import TYPE_CHECKING

from net_addr import Ip4Address
from pytcp.lib.ip4_multicast_filter import Ip4MulticastFilter
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# The IPv4 all-systems group every host joins permanently and never
# leaves (RFC 1112 §4); the membership API refuses to drop it.
IP4__MULTICAST__ALL_SYSTEMS = Ip4Address("224.0.0.1")


class MembershipLimitError(ValueError):
    """
    Raised by 'MembershipApi.join' when joining a new group would exceed
    'igmp.max_memberships'. Subclasses 'ValueError' so existing
    'except ValueError' callers still catch it; the BSD socket facade
    catches this specific type to map it to 'ENOBUFS' (Linux
    'IP_ADD_MEMBERSHIP' over 'igmp_max_memberships'), distinct from the
    'EINVAL' it returns for other membership errors.
    """


class MembershipApi:
    """
    The multicast-membership-control surface — joins / leaves IPv4
    multicast groups on an interface and exposes the current group
    set. Mirrors the Linux 'IP_ADD_MEMBERSHIP' / 'IP_DROP_MEMBERSHIP'
    socket options and 'ip maddr'.

    Consumer code — the BSD socket facade's membership options, the
    example apps, future operator-config tools — uses ONLY this
    surface. It never reaches into 'packet_handler._ip4_multicast'
    directly; that is the Phase-3 architectural seam.

    Two contributor kinds drive a group's interface reception state: the
    operator hold ('join' / 'leave', a set-once any-source EXCLUDE{}
    contributor) and the per-socket source filters ('set_socket_filter'
    / 'clear_socket_filter', keyed by an opaque socket token, carrying
    RFC 3376 §3.1 INCLUDE / EXCLUDE source lists). The interface filter
    is the RFC 3376 §3.2 merge of all contributors; the group stays
    joined while that merge has reception state.
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
            "The bare membership tool has no default device; select one via " "'stack.membership.interface(ifindex)'."
        )

    def interface(self, ifindex: int, /) -> "MembershipApi":
        """
        Return a 'MembershipApi' bound to the interface registered under
        'ifindex' — the device selector. Raises 'KeyError' when no
        interface is registered under 'ifindex'.
        """

        from pytcp import stack

        return MembershipApi(packet_handler=stack.interfaces[ifindex])

    def _enforce_membership_cap(
        self,
        handler: "PacketHandlerL2 | PacketHandlerL3",
        group: Ip4Address,
    ) -> None:
        """
        Enforce the Linux 'net.ipv4.igmp_max_memberships' cap on the
        number of joined IPv4 multicast groups. The cap applies only when
        the requested operation would newly join 'group'; the implicit
        all-systems group 224.0.0.1 does not count. Qualified module
        access so an operator override of 'igmp.max_memberships' resolves
        on every call. Raises 'MembershipLimitError' over the cap.
        """

        if handler._mc_is_joined(group):
            return

        joined = sum(1 for member in handler._ip4_multicast if member != IP4__MULTICAST__ALL_SYSTEMS)
        if joined >= igmp__constants.IGMP__MAX_MEMBERSHIPS:
            raise MembershipLimitError(
                f"The multicast-membership limit ({igmp__constants.IGMP__MAX_MEMBERSHIPS}) is reached "
                f"(sysctl 'igmp.max_memberships'); cannot join {group}."
            )

    def join(self, *, group: Ip4Address) -> None:
        """
        Join the IPv4 multicast 'group' on the bound interface as the
        operator hold ('ip maddr' / Linux 'IP_ADD_MEMBERSHIP' from the
        operator surface). The actual join + state-change Report fires
        only when the group crosses the not-joined→joined edge; the
        operator hold is idempotent. The per-socket source-filter holds
        (the BSD socket options) go through 'set_socket_filter' instead.
        Raises 'ValueError' for a non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        handler = self._resolve_handler()
        self._enforce_membership_cap(handler, group)
        handler._mc_ref_acquire(group)
        __debug__ and log("stack", f"<lg>Membership API</>: joined IPv4 group {group} (operator)")

    def leave(self, *, group: Ip4Address) -> None:
        """
        Release the operator hold on the IPv4 multicast 'group' on the
        bound interface ('ip maddr' / Linux 'IP_DROP_MEMBERSHIP' from the
        operator surface). The actual leave + state-change Leave Report
        fires only when the last contributor (operator or socket) is
        dropped (the joined→not-joined edge). Idempotent. Refuses to drop
        the all-systems group 224.0.0.1, which a host belongs to
        permanently (RFC 1112 §4). Raises 'ValueError' for a non-multicast
        address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            raise ValueError("The all-systems group 224.0.0.1 is joined permanently and cannot be left (RFC 1112 §4).")

        handler = self._resolve_handler()
        handler._mc_ref_release(group)
        __debug__ and log("stack", f"<lg>Membership API</>: left IPv4 group {group} (operator)")

    def set_socket_filter(self, *, group: Ip4Address, token: int, source_filter: Ip4MulticastFilter) -> None:
        """
        Register / replace the per-socket source filter (RFC 3376 §3.1)
        that the socket identified by the opaque 'token' holds on the
        IPv4 multicast 'group', then re-derive the merged interface
        filter (§3.2). This is the surface the BSD socket facade's
        'IP_ADD_MEMBERSHIP' / 'IP_ADD_SOURCE_MEMBERSHIP' /
        'IP_BLOCK_SOURCE' family dispatches to; the per-option state
        machine + errno mapping live in the facade. Raises
        'MembershipLimitError' when a newly-joined group would exceed the
        'igmp.max_memberships' cap.
        """

        handler = self._resolve_handler()
        self._enforce_membership_cap(handler, group)
        handler._mc_set_socket_filter(group, token=token, source_filter=source_filter)

    def clear_socket_filter(self, *, group: Ip4Address, token: int) -> None:
        """
        Drop the per-socket source filter the socket identified by 'token'
        held on the IPv4 multicast 'group' (the socket left — RFC 3376
        §3.1 INCLUDE{} delete) and re-derive the merged interface filter
        (§3.2). The surface the BSD socket facade's 'IP_DROP_MEMBERSHIP' /
        'IP_DROP_SOURCE_MEMBERSHIP'-to-empty paths and socket close
        dispatch to. Idempotent.
        """

        handler = self._resolve_handler()
        handler._mc_clear_socket_filter(group, token=token)

    def list_memberships(self) -> tuple[Ip4Address, ...]:
        """
        Return a read-only copy-by-value snapshot of the IPv4 multicast
        groups the bound interface listens on — Linux 'ip maddr show'
        equivalent. The returned tuple is immutable; the caller cannot
        mutate stack state through it.
        """

        handler = self._resolve_handler()

        return tuple(handler._ip4_multicast)
