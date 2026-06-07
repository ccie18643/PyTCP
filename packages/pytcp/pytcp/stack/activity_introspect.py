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
This module contains the per-interface activity introspection API.

'ActivityIntrospectApi' is the stack's "what is going on right now"
observation surface: per interface it reports the DHCPv4 client's FSM
state (the 'acquiring DHCP' indicator) and the IPv6 addresses still in
Duplicate Address Detection (the 'autoconfiguring addresses' indicator).
'list_activity' returns a tuple of immutable 'InterfaceActivity' values
(copy-by-value, so the caller cannot mutate stack state through them —
the Phase-3 "introspection is read-only" north-star constraint).
'build_interface_activity' is the pure mapping core, so it is testable
without a running stack.

pytcp/stack/activity_introspect.py

ver 3.0.8
"""

from collections.abc import Iterable
from dataclasses import dataclass

from net_addr import Ip6Address
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DadState

# The DAD phases that mean the address is still autoconfiguring — not yet
# verified on the link (TENTATIVE) or in use but unverified (OPTIMISTIC).
# A VALID address has passed DAD and is steady state.
_DAD_IN_PROGRESS: frozenset[Icmp6DadState] = frozenset({Icmp6DadState.TENTATIVE, Icmp6DadState.OPTIMISTIC})


@dataclass(frozen=True, kw_only=True, slots=True)
class InterfaceActivity:
    """
    Immutable point-in-time view of one interface's ongoing autoconfig
    activity — the DHCPv4 FSM state ('None' when the interface runs no
    DHCPv4 client) and the IPv6 addresses still in Duplicate Address
    Detection. Copy-by-value: the caller cannot mutate stack state
    through it.
    """

    ifindex: int
    name: str
    dhcp4_state: str | None
    tentative_ip6: tuple[Ip6Address, ...]


def _dhcp4_state(handler: object, /) -> str | None:
    """
    Return the DHCPv4 client's FSM-state name for an interface, or None
    when the interface runs no DHCPv4 client.
    """

    client = getattr(handler, "dhcp4_client", None)
    if client is None:
        return None
    state = getattr(client, "state", None)
    return str(state.value) if state is not None else None


def _tentative_ip6(handler: object, /) -> tuple[Ip6Address, ...]:
    """
    Return the IPv6 addresses on an interface still in Duplicate Address
    Detection (TENTATIVE / OPTIMISTIC) — the ones still autoconfiguring.
    """

    dad_states: dict[Ip6Address, Icmp6DadState] = getattr(handler, "dad_states", {})
    return tuple(address for address, state in dad_states.items() if state in _DAD_IN_PROGRESS)


def build_interface_activity(interfaces: Iterable[tuple[int, object]]) -> tuple[InterfaceActivity, ...]:
    """
    Map the live interfaces to an ifindex-sorted tuple of per-interface
    activity snapshots.
    """

    activities = [
        InterfaceActivity(
            ifindex=ifindex,
            name=getattr(handler, "interface_name", None) or "?",
            dhcp4_state=_dhcp4_state(handler),
            tentative_ip6=_tentative_ip6(handler),
        )
        for ifindex, handler in interfaces
    ]
    return tuple(sorted(activities, key=lambda activity: activity.ifindex))


class ActivityIntrospectApi:
    """
    The per-interface activity introspection API ("what is the stack
    doing right now").
    """

    def list_activity(self) -> tuple[InterfaceActivity, ...]:
        """
        Return a read-only copy-by-value snapshot of each interface's
        ongoing autoconfig activity (DHCPv4 state, DAD-in-progress IPv6
        addresses).
        """

        import pytcp.stack as _stack

        return build_interface_activity(list(_stack.interfaces.items()))
