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
This module contains integration tests for the RFC 3376 §3.2 IPv4
multicast source-filter model — a plain (any-source) join materializes
an EXCLUDE{} interface filter, the flat joined-group list is a derived
view over the filter map, and the per-socket merge drives the join /
leave edge with the same observable state-change Reports as before.

pytcp/tests/integration/protocols/igmp/test__igmp__source_filter_model.py

ver 3.0.10
"""

from types import SimpleNamespace

from net_addr import Ip4Address
from net_proto import IgmpV3RecordType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from pytcp import stack
from pytcp.lib.ip4_multicast_filter import (
    Ip4MulticastFilter,
    Ip4MulticastFilterMode,
)
from pytcp.tests.lib.network_testcase import NetworkTestCase

_GROUP = Ip4Address("239.1.1.1")
_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_EXCLUDE_ANY = Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE)
# Opaque per-socket tokens (the handler keys filters by 'id(socket)').
_TOKEN_A = 1
_TOKEN_B = 2

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / igmp log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _parse_igmp_from_ethernet(frame: bytes) -> IgmpMessageV3Report:
    """Decode the IGMPv3 Report carried in an Ethernet/IPv4 frame."""

    ihl = (frame[14] & 0x0F) * 4
    igmp_bytes = frame[14 + ihl :]

    packet_rx = PacketRx(igmp_bytes)
    packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
    IgmpParser(packet_rx)

    message = packet_rx.igmp.message
    assert isinstance(message, IgmpMessageV3Report)

    return message


class TestIgmpSourceFilterModel(NetworkTestCase):
    """
    The RFC 3376 §3.2 IPv4 multicast source-filter model tests.
    """

    def test__source_filter__plain_join_materializes_exclude_empty(self) -> None:
        """
        Ensure an any-source join materializes an EXCLUDE{} interface
        filter for the group and exposes the group in the derived
        joined-group view.

        Reference: RFC 3376 §3.2 (an EXCLUDE{} record represents an any-source join).
        """

        self._packet_handler.mc_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)

        self.assertEqual(
            self._packet_handler._ip4_multicast_filters[_GROUP],
            Ip4MulticastFilter(Ip4MulticastFilterMode.EXCLUDE, frozenset()),
            msg="A plain join must materialize an EXCLUDE{} interface filter.",
        )
        self.assertIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="The derived joined-group view must contain a plainly-joined group.",
        )

    def test__source_filter__derived_view_mirrors_filter_map(self) -> None:
        """
        Ensure the flat joined-group list is a derived view exactly
        equal to the keys of the materialized filter map.

        Reference: RFC 3376 §3.2 (per-interface reception state is the source of truth).
        """

        self._packet_handler.mc_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)

        self.assertEqual(
            self._packet_handler._ip4_multicast,
            list(self._packet_handler._ip4_multicast_filters),
            msg="The derived joined-group view must equal the filter-map keys.",
        )
        self.assertIn(
            _ALL_SYSTEMS,
            self._packet_handler._ip4_multicast,
            msg="The permanent all-systems group must remain in the derived view.",
        )

    def test__source_filter__join_emits_unchanged_change_to_exclude(self) -> None:
        """
        Ensure a plain join emits a single state-change Report carrying a
        CHANGE_TO_EXCLUDE_MODE record for the group — the observable
        behaviour is unchanged from the pre-filter-model join path.

        Reference: RFC 3376 §5.1 (unsolicited state-change Report on join).
        """

        before = len(self._frames_tx)
        self._packet_handler.mc_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)
        tx = self._frames_tx[before:]

        self.assertEqual(len(tx), 1, msg="A join must emit exactly one state-change Report.")
        report = _parse_igmp_from_ethernet(tx[0])
        self.assertEqual(
            [(record.type, record.multicast_address) for record in report.records],
            [(IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE, _GROUP)],
            msg="A join must report CHANGE_TO_EXCLUDE_MODE for the joined group.",
        )

    def test__source_filter__merge_holds_reception_until_last_ref(self) -> None:
        """
        Ensure the §3.2 merge over the per-socket and operator
        contributors keeps the group joined until the last reference is
        released, emitting one CHANGE_TO_EXCLUDE on the first join and
        one CHANGE_TO_INCLUDE only on the final leave.

        Reference: RFC 3376 §3.2 (interface state derived from the merge of socket records).
        Reference: RFC 3376 §5.1 (state-change Report only on a reception-state edge).
        """

        # First socket join crosses into reception — one CHANGE_TO_EXCLUDE.
        before = len(self._frames_tx)
        self._packet_handler.mc_set_socket_filter(_GROUP, token=_TOKEN_A, source_filter=_EXCLUDE_ANY)
        self.assertEqual(len(self._frames_tx[before:]), 1, msg="The first join must emit a Report.")

        # A second socket and the operator hold merge to the same
        # EXCLUDE{} reception state — no edge crossed, so no further Report.
        before = len(self._frames_tx)
        self._packet_handler.mc_set_socket_filter(_GROUP, token=_TOKEN_B, source_filter=_EXCLUDE_ANY)
        self._packet_handler.mc_ref_acquire(_GROUP)
        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="Additional references on an already-joined group must emit no Report.",
        )
        self.assertIn(_GROUP, self._packet_handler._ip4_multicast)

        # Releasing all but the last reference keeps reception — no Report.
        before = len(self._frames_tx)
        self._packet_handler.mc_clear_socket_filter(_GROUP, token=_TOKEN_A)
        self._packet_handler.mc_ref_release(_GROUP)
        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="Releasing a non-final reference must emit no Report.",
        )
        self.assertIn(_GROUP, self._packet_handler._ip4_multicast)

        # The final release drops reception — one CHANGE_TO_INCLUDE leave.
        before = len(self._frames_tx)
        self._packet_handler.mc_clear_socket_filter(_GROUP, token=_TOKEN_B)
        tx = self._frames_tx[before:]
        self.assertEqual(len(tx), 1, msg="The final release must emit one Leave Report.")
        report = _parse_igmp_from_ethernet(tx[0])
        self.assertEqual(
            [(record.type, record.multicast_address) for record in report.records],
            [(IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE, _GROUP)],
            msg="The final leave must report CHANGE_TO_INCLUDE_MODE for the group.",
        )
        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="The group must leave the derived view once the last reference drops.",
        )
