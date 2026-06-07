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
This module contains tests for the 'TxStatus' enum.

pytcp/tests/unit/lib/test__lib__tx_status.py

ver 3.0.8
"""

from enum import IntEnum
from typing import Any
from unittest import TestCase

from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.parameterized import parameterized_class

# The canonical roster of TxStatus members in declaration order. If a
# member is added, removed, or reordered in 'pytcp/lib/tx_status.py'
# this list must be updated in lockstep so the 'exact_roster' test
# catches silent drift.
_EXPECTED_MEMBERS: tuple[str, ...] = (
    "PASSED__ETHERNET__TO_TX_RING",
    "DROPPED__ETHERNET__DST_ARP_CACHE_MISS",
    "DROPPED__ETHERNET__DST_ND_CACHE_MISS",
    "DROPPED__ETHERNET__DST_NO_GATEWAY_IP4",
    "DROPPED__ETHERNET__DST_NO_GATEWAY_IP6",
    "DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS",
    "DROPPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS",
    "DROPPED__ETHERNET__DST_RESOLUTION_FAIL",
    "PASSED__ETHERNET_802_3__TO_TX_RING",
    "DROPPED__ETHERNET_802_3__DST_RESOLUTION_FAIL",
    "DROPPED__ARP__NO_PROTOCOL_SUPPORT",
    "PASSED__IP4__TO_TX_RING",
    "DROPPED__IP4__NO_PROTOCOL_SUPPORT",
    "DROPPED__IP4__SRC_NOT_OWNED",
    "DROPPED__IP4__SRC_MULTICAST",
    "DROPPED__IP4__SRC_LIMITED_BROADCAST",
    "DROPPED__IP4__SRC_NETWORK_BROADCAST",
    "DROPPED__IP4__SRC_UNSPECIFIED",
    "DROPPED__IP4__DST_UNSPECIFIED",
    "DROPPED__IP4__MTU_EXCEED_DF",
    "DROPPED__IP4__UNKNOWN",
    "PASSED__IP6__TO_TX_RING",
    "DROPPED__IP6__NO_PROTOCOL_SUPPORT",
    "DROPPED__IP6__SRC_NOT_OWNED",
    "DROPPED__IP6__SRC_MULTICAST",
    "DROPPED__IP6__SRC_LIMITED_BROADCAST",
    "DROPPED__IP6__SRC_NETWORK_BROADCAST",
    "DROPPED__IP6__SRC_UNSPECIFIED",
    "DROPPED__IP6__SRC_SCOPE_MISMATCH",
    "DROPPED__IP6__DST_UNSPECIFIED",
    "DROPPED__IP6__UNKNOWN",
    "DROPPED__IP6__EXT_FRAG_UNKNOWN",
    "DROPPED__IP6__ND_FRAGMENTATION_FORBIDDEN",
    "DROPPED__UDP__UNKNOWN",
    "DROPPED__TCP__UNKNOWN",
    "DROPPED__ICMP4__UNKNOWN",
    "DROPPED__ICMP6__UNKNOWN",
    "DROPPED__IP4__DST_BROADCAST_DISALLOWED",
    "DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH",
)


class TestTxStatusClass(TestCase):
    """
    The 'TxStatus' class-level invariants tests.
    """

    def test__tx_status__is_int_enum_subclass(self) -> None:
        """
        Ensure 'TxStatus' derives from 'IntEnum' so its members retain
        integer semantics for logging and comparison.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(TxStatus, IntEnum),
            msg="TxStatus must derive from enum.IntEnum.",
        )

    def test__tx_status__exact_roster(self) -> None:
        """
        Ensure the full declared member set matches '_EXPECTED_MEMBERS' in
        order. Locks the enum against accidental additions, removals, or
        reorderings (which would silently shift every auto() value).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            tuple(member.name for member in TxStatus),
            _EXPECTED_MEMBERS,
            msg="TxStatus member roster or ordering does not match the "
            "canonical list. If this change is intentional, update "
            "'_EXPECTED_MEMBERS' in this test module in lockstep.",
        )

    def test__tx_status__values_are_dense_sequential(self) -> None:
        """
        Ensure every 'auto()'-generated value forms the dense 1..N sequence
        expected from 'IntEnum + auto()'. Regressions that insert a custom
        integer value would break tests that rely on the dense mapping.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        expected_values = list(range(1, len(_EXPECTED_MEMBERS) + 1))

        self.assertEqual(
            [int(member) for member in TxStatus],
            expected_values,
            msg="TxStatus values must be the dense 1..N IntEnum auto() " "sequence in declaration order.",
        )

    def test__tx_status__all_values_unique(self) -> None:
        """
        Ensure no two members share the same integer value. 'IntEnum'
        would otherwise alias them and silently hide one branch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        values = [int(member) for member in TxStatus]

        self.assertEqual(
            len(set(values)),
            len(values),
            msg="TxStatus members must all carry distinct integer values.",
        )


@parameterized_class(
    [
        {
            "_description": "First member: PASSED__ETHERNET__TO_TX_RING.",
            "_member": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_results": {
                "name": "PASSED__ETHERNET__TO_TX_RING",
                "value": 1,
                "__str__": "PASSED__ETHERNET__TO_TX_RING",
            },
        },
        {
            "_description": "Middle member: DROPPED__IP4__UNKNOWN.",
            "_member": TxStatus.DROPPED__IP4__UNKNOWN,
            "_results": {
                "name": "DROPPED__IP4__UNKNOWN",
                "value": 21,
                "__str__": "DROPPED__IP4__UNKNOWN",
            },
        },
        {
            "_description": "Last member: DROPPED__ICMP6__UNKNOWN.",
            "_member": TxStatus.DROPPED__ICMP6__UNKNOWN,
            "_results": {
                "name": "DROPPED__ICMP6__UNKNOWN",
                "value": 37,
                "__str__": "DROPPED__ICMP6__UNKNOWN",
            },
        },
        {
            "_description": "Nested Ethernet drop: DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS.",
            "_member": TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            "_results": {
                "name": "DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS",
                "value": 6,
                "__str__": "DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS",
            },
        },
        {
            "_description": "IPv6 frag drop: DROPPED__IP6__EXT_FRAG_UNKNOWN.",
            "_member": TxStatus.DROPPED__IP6__EXT_FRAG_UNKNOWN,
            "_results": {
                "name": "DROPPED__IP6__EXT_FRAG_UNKNOWN",
                "value": 32,
                "__str__": "DROPPED__IP6__EXT_FRAG_UNKNOWN",
            },
        },
    ]
)
class TestTxStatusMember(TestCase):
    """
    The 'TxStatus' per-member attribute tests.
    """

    _description: str
    _member: TxStatus
    _results: dict[str, Any]

    def test__tx_status__name(self) -> None:
        """
        Ensure the member's 'name' matches the declaration label.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._member.name,
            self._results["name"],
            msg=f"Unexpected .name for case: {self._description}",
        )

    def test__tx_status__value(self) -> None:
        """
        Ensure the member's integer value matches the position it holds
        in the 1..N auto() sequence.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._member.value,
            self._results["value"],
            msg=f"Unexpected .value for case: {self._description}",
        )

    def test__tx_status__str(self) -> None:
        """
        Ensure 'TxStatus.__str__()' returns only the member name, not the
        stdlib 'ClassName.MEMBER' form.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._member),
            self._results["__str__"],
            msg=f"Unexpected str() output for case: {self._description}",
        )


class TestTxStatusStrAcrossAllMembers(TestCase):
    """
    The 'TxStatus.__str__()' coverage-across-all-members tests.
    """

    def test__tx_status__str_equals_name_for_every_member(self) -> None:
        """
        Ensure 'str(member)' equals 'member.name' for every declared
        member. This single sweep covers the custom '__str__()' body once
        per member and guards against any member that might silently
        inherit the stdlib default in a future Python release.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for member in TxStatus:
            with self.subTest(member=member.name):
                self.assertEqual(
                    str(member),
                    member.name,
                    msg=f"str({member.name}) must equal its .name attribute.",
                )

    def test__tx_status__str_never_contains_qualified_form(self) -> None:
        """
        Ensure no member's 'str()' contains a '.' separator, which would
        indicate the stdlib 'ClassName.MEMBER' form had leaked through.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for member in TxStatus:
            with self.subTest(member=member.name):
                self.assertNotIn(
                    ".",
                    str(member),
                    msg=f"str({member.name}) must not contain '.' separator.",
                )
