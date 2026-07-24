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
This module contains the IPv6 Neighbor Discovery state PyTCP
maintains across RA RX events: default-router list (§11) and
SLAAC per-address lifetime + state-machine tracking (§12a/b).
Mirrors the conceptual data structures of RFC 4861 §6.3.4
('Default Router List') and RFC 4862 §5.5.3 / §5.5.4 (SLAAC
address-lifetime state).

Future Tier-3 phases will grow this module with the RA-header
mirror state (§13: cur-hop-limit / reachable-time / retrans-timer)
and the Prf field on Icmp6DefaultRouter once §14 lands the
RA-header parser extension. RFC 6724 source-address-selection
integration (the consumer of the per-address state machine) is a
separate phase tracked outside §12.

pytcp/protocols/icmp6/nd/nd__router_state.py

ver 3.0.9
"""

from dataclasses import dataclass
from enum import Enum

from net_addr import Ip6Address, Ip6Network
from net_proto import Icmp6NdRoutePreference


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6DefaultRouter:
    """
    A single entry in the host's default-router list per
    RFC 4861 §6.3.4. 'expires_at' is a 'time.monotonic()'
    deadline; the accessor on the packet handler filters out
    entries whose deadline has passed (lazy ageing). 'prf'
    captures the router's RFC 4191 Default Router Preference;
    the accessor sorts entries by 'prf' so consumers
    naturally pick the most-preferred router.
    """

    address: Ip6Address
    lifetime: int
    expires_at: float
    prf: Icmp6NdRoutePreference = Icmp6NdRoutePreference.MEDIUM


class Icmp6SlaacAddressState(Enum):
    """
    The lifecycle phase of an SLAAC-derived address per
    RFC 4862 §5.5.4. PREFERRED is the steady state during
    preferred_lifetime; DEPRECATED is the post-preferred but
    pre-valid window where the address is usable for established
    flows but should not be selected for new ones (RFC 6724 source-
    address selection consumes this distinction). REMOVED is
    represented in PyTCP by the absence of the entry from the
    accessor — there is no explicit 'REMOVED' member.
    """

    PREFERRED = "PREFERRED"
    DEPRECATED = "DEPRECATED"


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6SlaacAddress:
    """
    A single SLAAC-derived address learned from an RA's Prefix-
    Information option per RFC 4862 §5.5.3. 'address' is the
    EUI-64-derived host address; 'prefix' is the on-link prefix
    the address came from. Both deadlines are 'time.monotonic()'
    offsets of the advertised Valid / Preferred Lifetime values.
    'router_address' is the link-local source of the RA that
    carried the PI — used by RFC 8028 §3 first-hop selection
    (nd_linux_parity §23) to pick the default router whose
    advertised prefix covers an outbound source address.
    """

    address: Ip6Address
    prefix: Ip6Network
    preferred_until: float
    valid_until: float
    router_address: Ip6Address

    def state(self, now: float) -> Icmp6SlaacAddressState | None:
        """
        Compute the address's lifecycle state at the given
        'time.monotonic()' value. Returns None when 'now' has
        crossed valid_until (the entry is REMOVED — accessors
        filter it out).
        """

        if now >= self.valid_until:
            return None
        if now >= self.preferred_until:
            return Icmp6SlaacAddressState.DEPRECATED
        return Icmp6SlaacAddressState.PREFERRED


class Icmp6DadState(Enum):
    """
    The per-address Duplicate Address Detection state. TENTATIVE
    is the strict RFC 4862 §5.4 lifecycle phase: the address is
    not in '_ip6_ifaddr' yet, and DAD probes are in flight.
    OPTIMISTIC (RFC 4429 §3.1) is the relaxed lifecycle phase the
    'icmp6.optimistic_dad' sysctl unlocks: the address is already
    in '_ip6_ifaddr' and usable as outbound source, but Neighbor
    Advertisements emitted while OPTIMISTIC clear the Override
    flag per §3.3 so peers do not overwrite a possibly-existing
    cache entry on the basis of an unverified address. VALID is
    the steady state. Failed DAD removes the entry (no FAILED
    member — accessors filter it out).
    """

    TENTATIVE = "TENTATIVE"
    OPTIMISTIC = "OPTIMISTIC"
    VALID = "VALID"


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6TempAddress:
    """
    A temporary SLAAC-derived address per RFC 8981. 'address'
    is the random-IID-derived host address; 'prefix' is the
    on-link /64 it came from. 'preferred_until' / 'valid_until'
    are 'time.monotonic()' deadlines clamped at creation time
    to TEMP_PREFERRED_LIFETIME / TEMP_VALID_LIFETIME (RFC 8981
    §3.4 / §3.8). 'created_at' is the 'time.monotonic()' value
    at which the address was generated — the §18c regeneration
    subsystem will use it to schedule rotation before
    preferred_lifetime expires. 'router_address' captures the
    RA source so the address remains tied to the gateway that
    advertised the prefix, mirroring 'Icmp6SlaacAddress' for
    RFC 8028 first-hop selection consumers.
    """

    address: Ip6Address
    prefix: Ip6Network
    preferred_until: float
    valid_until: float
    created_at: float
    router_address: Ip6Address


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6RaParameters:
    """
    Host-parameter values learned from RA-header fields per
    RFC 4861 §6.3.4. Each field is None until the host has
    observed at least one RA carrying a non-zero advertisement
    of that field — RFC 4861 §4.2 reserves zero as "unspecified
    by this router" so a zero advertisement must not overwrite
    a previously-captured value.

    Phase 2: TX-side / NUD / DAD consumers will fall back to
    these values when set, otherwise to the operator-configured
    sysctl defaults.
    """

    cur_hop_limit: int | None
    reachable_time_ms: int | None
    retrans_timer_ms: int | None
