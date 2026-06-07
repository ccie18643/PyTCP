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
This module contains unit tests for the IPv4 multicast source-filter
value type and the RFC 3376 §3.2 per-interface state merge.

pytcp/tests/unit/lib/test__lib__ip4_multicast_filter.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.tests.lib.parameterized import parameterized_class

_A = Ip4Address("10.0.0.1")
_B = Ip4Address("10.0.0.2")
_C = Ip4Address("10.0.0.3")
_D = Ip4Address("10.0.0.4")
_E = Ip4Address("10.0.0.5")
_F = Ip4Address("10.0.0.6")


def _include(*sources: Ip4Address) -> Ip4MulticastFilter:
    """Build an INCLUDE-mode filter over the given sources."""

    return Ip4MulticastFilter(Ip4MulticastFilterMode.INCLUDE, frozenset(sources))


def _exclude(*sources: Ip4Address) -> Ip4MulticastFilter:
    """Build an EXCLUDE-mode filter over the given sources."""

    return Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE, frozenset(sources))


@parameterized_class(
    [
        {
            "_description": "No contributing filters yields INCLUDE{} (no reception).",
            "_filters": [],
            "_expected": _include(),
        },
        {
            "_description": "A single EXCLUDE{} (any-source join) stays EXCLUDE{}.",
            "_filters": [_exclude()],
            "_expected": _exclude(),
        },
        {
            "_description": "A single INCLUDE{a} stays INCLUDE{a}.",
            "_filters": [_include(_A)],
            "_expected": _include(_A),
        },
        {
            "_description": "All-INCLUDE merges to the union of the include lists.",
            "_filters": [_include(_A, _B, _C), _include(_B, _C, _D), _include(_E, _F)],
            "_expected": _include(_A, _B, _C, _D, _E, _F),
        },
        {
            "_description": "Any-EXCLUDE merges to the EXCLUDE intersection minus the INCLUDE union.",
            "_filters": [_exclude(_A, _B, _C, _D), _exclude(_B, _C, _D, _E), _include(_D, _E, _F)],
            "_expected": _exclude(_B, _C),
        },
        {
            "_description": "Adding an EXCLUDE{} socket collapses the EXCLUDE intersection to EXCLUDE{}.",
            "_filters": [_exclude(_A, _B, _C, _D), _exclude(_B, _C, _D, _E), _include(_D, _E, _F), _exclude()],
            "_expected": _exclude(),
        },
        {
            "_description": "A mixed EXCLUDE+INCLUDE pair yields EXCLUDE minus the included sources.",
            "_filters": [_exclude(_A, _B), _include(_B, _C)],
            "_expected": _exclude(_A),
        },
        {
            "_description": "Several EXCLUDE{} contributors (the Phase-1 live case) merge to EXCLUDE{}.",
            "_filters": [_exclude(), _exclude(), _exclude()],
            "_expected": _exclude(),
        },
    ]
)
class TestIp4MulticastFilterMerge(TestCase):
    """
    The RFC 3376 §3.2 per-interface multicast filter merge tests.
    """

    _description: str
    _filters: list[Ip4MulticastFilter]
    _expected: Ip4MulticastFilter

    def test__ip4_multicast_filter__merge(self) -> None:
        """
        Ensure merging the per-socket filters yields the per-interface
        filter dictated by the §3.2 rules — INCLUDE union when all
        sockets are INCLUDE, EXCLUDE intersection minus the INCLUDE
        union when any socket is EXCLUDE.

        Reference: RFC 3376 §3.2 (deriving per-interface state from per-socket state).
        """

        self.assertEqual(
            Ip4MulticastFilter.merge(self._filters),
            self._expected,
            msg=f"Unexpected merged interface filter for case: {self._description}",
        )


class TestIp4MulticastFilterReception(TestCase):
    """
    The IPv4 multicast filter reception-state predicate tests.
    """

    def test__ip4_multicast_filter__has_reception(self) -> None:
        """
        Ensure a filter reports reception state for every mode except
        INCLUDE with an empty source set, which is the "not a member"
        state.

        Reference: RFC 3376 §3.2 (INCLUDE{} represents no reception).
        """

        for filter_, expected in [
            (_exclude(), True),
            (_exclude(_A), True),
            (_include(_A), True),
            (_include(), False),
        ]:
            with self.subTest(filter=filter_):
                self.assertEqual(
                    filter_.has_reception,
                    expected,
                    msg=f"Unexpected has_reception for {filter_!r}",
                )

    def test__ip4_multicast_filter__allows(self) -> None:
        """
        Ensure the per-source delivery predicate accepts a source only
        when an INCLUDE filter lists it or an EXCLUDE filter does not —
        the data-plane source-delivery gate.

        Reference: RFC 3376 §3.1 (INCLUDE delivers listed sources, EXCLUDE delivers all but listed).
        """

        for filter_, source, expected in [
            (_include(_A, _B), _A, True),
            (_include(_A, _B), _C, False),
            (_include(), _A, False),
            (_exclude(_A), _A, False),
            (_exclude(_A), _B, True),
            (_exclude(), _A, True),
        ]:
            with self.subTest(filter=filter_, source=source):
                self.assertEqual(
                    filter_.allows(source),
                    expected,
                    msg=f"Unexpected allows({source!r}) for {filter_!r}",
                )
