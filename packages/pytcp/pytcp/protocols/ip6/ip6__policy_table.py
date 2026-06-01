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
This module contains the RFC 6724 §10.3 default address-
selection policy table and the longest-prefix-match 'lookup'
function the source-selection rule-6 score consumes.

The table is a frozen tuple of 'PolicyEntry' records. The
order is most-specific-first so 'lookup' can stop at the
first hit. The default contents match the RFC §10.3 figure
verbatim and Linux's /etc/gai.conf default preset.

A future Phase §12c.3.b may add a sysctl-driven runtime
override, but the default table is sufficient for the §5
rule-6 consumer to stop being a no-op.

pytcp/protocols/ip6/ip6__policy_table.py

ver 3.0.8
"""

from dataclasses import dataclass

from net_addr import Ip6Address, Ip6Network


@dataclass(frozen=True, kw_only=True, slots=True)
class PolicyEntry:
    """
    A single row of the RFC 6724 §10.3 policy table: an
    IPv6 prefix with its precedence and label values.
    Higher precedence is preferred for destination ordering;
    the label is matched between source and destination by
    rule-6 of the source-selection algorithm.
    """

    network: Ip6Network
    precedence: int
    label: int


# RFC 6724 §10.3 default policy table. The order matters —
# 'lookup' walks the tuple in declared order and the entries
# are arranged most-specific-prefix-first so the first hit is
# the longest match. The values mirror the figure in §10.3
# and Linux's gai.conf default.
DEFAULT_POLICY_TABLE: tuple[PolicyEntry, ...] = (
    PolicyEntry(network=Ip6Network("::1/128"), precedence=50, label=0),
    PolicyEntry(network=Ip6Network("::ffff:0:0/96"), precedence=35, label=4),
    PolicyEntry(network=Ip6Network("::/96"), precedence=1, label=3),
    PolicyEntry(network=Ip6Network("2001::/32"), precedence=5, label=5),
    PolicyEntry(network=Ip6Network("2002::/16"), precedence=30, label=2),
    PolicyEntry(network=Ip6Network("3ffe::/16"), precedence=1, label=12),
    PolicyEntry(network=Ip6Network("fec0::/10"), precedence=1, label=11),
    PolicyEntry(network=Ip6Network("fc00::/7"), precedence=3, label=13),
    PolicyEntry(network=Ip6Network("::/0"), precedence=40, label=1),
)


def lookup(address: Ip6Address, /) -> tuple[int, int]:
    """
    Return the (precedence, label) pair from the most-specific
    policy-table entry that contains the given IPv6 address.
    The table's terminating ::/0 entry guarantees a hit for
    every address, so the function is total.
    """

    for entry in DEFAULT_POLICY_TABLE:
        if address in entry.network:
            return (entry.precedence, entry.label)
    # Unreachable because of the ::/0 catch-all; the assert
    # makes the invariant explicit for static analysis.
    raise AssertionError("RFC 6724 §10.3 policy table missing ::/0 catch-all")
