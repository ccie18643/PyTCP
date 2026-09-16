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
This module contains the client-side mirror of the RFC 6724 policy-table
control API.

The policy table carries one precedence and one label per IPv6 prefix,
driving destination ordering and the rule-6 source/destination label
match of the source-selection algorithm. Linux exposes the label half of
the same idea through 'ip addrlabel' (netlink), so this is a control API
rather than a sysctl — a whole precedence/label table is not a scalar.

pytcp/client/client__policy_table.py

ver 3.0.10
"""

from typing import cast

from pytcp.client.client__base import _ClientApiProxy
from pytcp.protocols.ip6.ip6__policy_table import PolicyEntry


class ClientPolicyTable(_ClientApiProxy):
    """
    The client-side mirror of the RFC 6724 policy-table control API.
    """

    _api_name = "policy_table"

    def get_policy_table(self) -> tuple[PolicyEntry, ...]:
        """
        Get the active policy table, most-specific prefix first.
        """

        return cast(tuple[PolicyEntry, ...], self._call("get_policy_table", {}))

    def set_policy_table(self, entries: tuple[PolicyEntry, ...], /) -> None:
        """
        Replace the whole policy table with 'entries'.

        The table is replaced wholesale rather than edited row by row:
        'lookup' walks it in declared order and takes the first hit, so
        ordering is part of the value and a per-row edit would leave the
        caller guessing where its row landed.
        """

        self._call("set_policy_table", {"entries": entries})

    def reset_policy_table(self) -> None:
        """
        Restore the RFC 6724 §10.3 default policy table.
        """

        self._call("reset_policy_table", {})
