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
This module contains integration tests for the RFC 3810 §4.2 IPv6
multicast source-filter model — a plain (any-source) join materializes
an EXCLUDE{} interface filter, the flat joined-group list is a derived
view over the filter map, and the per-socket merge drives the join /
leave edge with the same observable MLD Reports as before. The IPv6
(MLDv2) analogue of the shipped IGMPv3 source-filter model.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld__source_filter_model.py

ver 3.0.9
"""

from typing import override

from net_addr import Ip6Address
from pytcp.lib.ip6_multicast_filter import (
    Ip6MulticastFilter,
    Ip6MulticastFilterMode,
)
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP = Ip6Address("ff05::abcd")
_ALL_NODES = Ip6Address("ff02::1")
_SRC_A = Ip6Address("2001:db8::1")
_SRC_B = Ip6Address("2001:db8::2")
_EXCLUDE_ANY = Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE)
# Opaque per-socket tokens (the handler keys filters by 'id(socket)').
_TOKEN_A = 1
_TOKEN_B = 2


class TestIcmp6MldSourceFilterModel(IcmpTestCase):
    """
    The RFC 3810 §4.2 IPv6 multicast source-filter model tests.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._handler = self._packet_handler

    def test__source_filter__plain_join_materializes_exclude_empty(self) -> None:
        """
        Ensure an any-source join materializes an EXCLUDE{} interface
        filter for the group and exposes the group in the derived
        joined-group view.

        Reference: RFC 3810 §4.2 (an EXCLUDE{} record represents an any-source join).
        """

        self._handler.mc6_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)

        self.assertEqual(
            self._handler._ip6_multicast_filters[_GROUP],
            Ip6MulticastFilter(Ip6MulticastFilterMode.EXCLUDE, frozenset()),
            msg="A plain join must materialize an EXCLUDE{} interface filter.",
        )
        self.assertIn(
            _GROUP,
            self._handler._ip6_multicast,
            msg="The derived joined-group view must contain a plainly-joined group.",
        )

    def test__source_filter__derived_view_mirrors_filter_map(self) -> None:
        """
        Ensure the flat joined-group list is a derived view exactly
        equal to the keys of the materialized filter map, and that the
        permanent all-nodes group remains in the view.

        Reference: RFC 3810 §4.2 (per-interface reception state is the source of truth).
        """

        self._handler.mc6_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)

        self.assertEqual(
            self._handler._ip6_multicast,
            list(self._handler._ip6_multicast_filters),
            msg="The derived joined-group view must equal the filter-map keys.",
        )
        self.assertIn(
            _ALL_NODES,
            self._handler._ip6_multicast,
            msg="The permanent all-nodes group must remain in the derived view.",
        )

    def test__source_filter__include_filter_materializes_sources(self) -> None:
        """
        Ensure a source-specific INCLUDE join materializes an INCLUDE
        filter carrying exactly the requested sources and joins the
        group (a non-empty INCLUDE list has reception).

        Reference: RFC 3810 §4.2 (INCLUDE with a non-empty source list has reception).
        """

        source_filter = Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_SRC_A, _SRC_B}))
        self._handler.mc6_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=source_filter)

        self.assertEqual(
            self._handler._ip6_multicast_filters[_GROUP],
            Ip6MulticastFilter(Ip6MulticastFilterMode.INCLUDE, frozenset({_SRC_A, _SRC_B})),
            msg="A source-specific INCLUDE join must materialize INCLUDE{sources}.",
        )
        self.assertTrue(
            self._handler.mc6_is_joined(_GROUP),
            msg="A non-empty INCLUDE join must join the group.",
        )

    def test__source_filter__mc6_is_joined_reflects_filter_map(self) -> None:
        """
        Ensure 'mc6_is_joined' reports membership straight from the
        materialized filter map — False before any contributor, True
        once a filter is set.

        Reference: RFC 3810 §4.2 (interface reception state governs membership).
        """

        self.assertFalse(
            self._handler.mc6_is_joined(_GROUP),
            msg="A group with no contributor must not be joined.",
        )

        self._handler.mc6_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)

        self.assertTrue(
            self._handler.mc6_is_joined(_GROUP),
            msg="A group with a reception-bearing filter must be joined.",
        )

    def test__source_filter__merge_holds_reception_until_last_ref(self) -> None:
        """
        Ensure the §4.2 merge over the per-socket and operator
        contributors keeps the group joined until the last reference is
        released, emitting one MLD Report on the first join and one MLD
        leave only on the final release — additional references on an
        already-joined group cross no reception edge and emit nothing.

        Reference: RFC 3810 §4.2 (interface state derived from the merge of socket records).
        Reference: RFC 3810 §6.1 (state-change Report only on a reception-state edge).
        """

        # First socket join crosses into reception — one MLD Report.
        before = len(self._frames_tx)
        self._handler.mc6_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)
        self.assertEqual(
            len(self._frames_tx[before:]),
            1,
            msg="The first join must emit exactly one MLD Report.",
        )

        # A second socket and the operator hold merge to the same
        # EXCLUDE{} reception state — no edge crossed, so no further Report.
        before = len(self._frames_tx)
        self._handler.mc6_set_socket_filter(_GROUP, token=_TOKEN_B, source_filter=_EXCLUDE_ANY)
        self._handler.mc6_ref_acquire(_GROUP)
        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="Additional references on an already-joined group must emit no Report.",
        )
        self.assertIn(_GROUP, self._handler._ip6_multicast)

        # Releasing all but the last reference keeps reception — no Report.
        before = len(self._frames_tx)
        self._handler.mc6_clear_socket_filter(_GROUP, token=_TOKEN_A)
        self._handler.mc6_ref_release(_GROUP)
        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="Releasing a non-final reference must emit no Report.",
        )
        self.assertIn(_GROUP, self._handler._ip6_multicast)

        # The final release drops reception — one MLD leave, group gone.
        before = len(self._frames_tx)
        self._handler.mc6_clear_socket_filter(_GROUP, token=_TOKEN_B)
        self.assertEqual(
            len(self._frames_tx[before:]),
            1,
            msg="The final release must emit exactly one MLD leave.",
        )
        self.assertNotIn(
            _GROUP,
            self._handler._ip6_multicast,
            msg="The group must leave the derived view once the last reference drops.",
        )

    def test__source_filter__operator_hold_join_and_release(self) -> None:
        """
        Ensure the operator hold ('ip maddr'-style set-once EXCLUDE{}
        contributor) crosses the group into reception on acquire and out
        of reception on release, mirroring a per-socket any-source join.

        Reference: RFC 3810 §4.2 (the operator hold is an EXCLUDE{} contributor).
        """

        self._handler.mc6_ref_acquire(_GROUP)
        self.assertTrue(
            self._handler.mc6_is_joined(_GROUP),
            msg="Acquiring the operator hold must join the group.",
        )

        self._handler.mc6_ref_release(_GROUP)
        self.assertFalse(
            self._handler.mc6_is_joined(_GROUP),
            msg="Releasing the last (operator) hold must leave the group.",
        )

    def test__source_filter__all_nodes_join_is_permanent_noop(self) -> None:
        """
        Ensure a socket / operator join of the permanent all-nodes group
        (ff02::1) is a no-op that neither creates a contributor entry nor
        disturbs the group's permanent membership.

        Reference: RFC 3810 §6 (the all-nodes group ff02::1 is never MLD-managed).
        """

        self._handler.mc6_ref_acquire(_ALL_NODES)
        self._handler.mc6_set_socket_filter(_ALL_NODES, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)

        self.assertNotIn(
            _ALL_NODES,
            self._handler._ip6_multicast_refs,
            msg="The all-nodes group must never gain a contributor registry entry.",
        )
        self.assertIn(
            _ALL_NODES,
            self._handler._ip6_multicast,
            msg="The all-nodes group must stay permanently joined.",
        )

        self._handler.mc6_ref_release(_ALL_NODES)
        self._handler.mc6_clear_socket_filter(_ALL_NODES, token=_TOKEN_A)
        self.assertIn(
            _ALL_NODES,
            self._handler._ip6_multicast,
            msg="Releasing an all-nodes hold must not drop its permanent membership.",
        )
