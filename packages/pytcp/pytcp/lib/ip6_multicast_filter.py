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
This module contains the IPv6 multicast source-filter value type and the
RFC 3810 §4.2 per-interface state merge. A filter is a mode
(INCLUDE / EXCLUDE) plus a source set; the merge derives the per-interface
reception state from the set of per-socket filters. This is the IPv6
(MLDv2) analogue of the IPv4 (IGMPv3) 'ip4_multicast_filter'.

pytcp/lib/ip6_multicast_filter.py

ver 3.0.9
"""

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum, auto

from net_addr import Ip6Address


class Ip6MulticastFilterMode(Enum):
    """
    The IPv6 multicast source-filter mode (RFC 3810 §4.2). INCLUDE
    listens only to the listed sources; EXCLUDE listens to every source
    except the listed ones (so EXCLUDE{} is an any-source join).
    """

    INCLUDE = auto()
    EXCLUDE = auto()


@dataclass(frozen=True, slots=True)
class Ip6MulticastFilter:
    """
    An IPv6 multicast source filter — a mode plus a source set. The
    per-socket filter and the merged per-interface filter (RFC 3810 §4.2)
    share this shape.
    """

    mode: Ip6MulticastFilterMode
    sources: frozenset[Ip6Address] = field(default=frozenset())

    @property
    def has_reception(self) -> bool:
        """
        Get whether the filter represents any reception state. Every
        EXCLUDE filter receives (EXCLUDE{} is any-source); an INCLUDE
        filter receives only when its source set is non-empty — INCLUDE{}
        is the "not a member" state (RFC 3810 §4.2).
        """

        return self.mode is Ip6MulticastFilterMode.EXCLUDE or bool(self.sources)

    def allows(self, source: Ip6Address, /) -> bool:
        """
        Get whether a datagram from 'source' passes this filter for
        delivery (RFC 3810 §4.2): an INCLUDE filter delivers only its
        listed sources, an EXCLUDE filter delivers every source except
        its listed ones. This is the data-plane source-delivery gate
        (the IPv6 analogue of Linux 'ip_mc_sf_allow').
        """

        if self.mode is Ip6MulticastFilterMode.INCLUDE:
            return source in self.sources
        return source not in self.sources

    @classmethod
    def merge(cls, filters: Iterable[Ip6MulticastFilter], /) -> Ip6MulticastFilter:
        """
        Merge the per-socket 'filters' into the per-interface filter per
        RFC 3810 §4.2: if any filter is EXCLUDE the interface is EXCLUDE
        with the intersection of the EXCLUDE source lists minus the union
        of the INCLUDE source lists; otherwise the interface is INCLUDE
        with the union of the INCLUDE source lists. Merging no filters
        yields INCLUDE{} (no reception).
        """

        include_sources: set[Ip6Address] = set()
        exclude_lists: list[frozenset[Ip6Address]] = []

        for filter_ in filters:
            match filter_.mode:
                case Ip6MulticastFilterMode.INCLUDE:
                    include_sources |= filter_.sources
                case Ip6MulticastFilterMode.EXCLUDE:
                    exclude_lists.append(filter_.sources)

        if exclude_lists:
            excluded = set(exclude_lists[0]).intersection(*exclude_lists[1:])
            excluded -= include_sources
            return cls(mode=Ip6MulticastFilterMode.EXCLUDE, sources=frozenset(excluded))

        return cls(mode=Ip6MulticastFilterMode.INCLUDE, sources=frozenset(include_sources))
