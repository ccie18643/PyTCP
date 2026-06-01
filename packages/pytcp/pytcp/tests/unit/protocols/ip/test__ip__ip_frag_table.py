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
This module contains tests for the 'IpFragTable' shared flow store.

pytcp/tests/unit/protocols/ip/test__ip__ip_frag_table.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import IpProto
from pytcp.protocols.ip.ip_frag import (
    ECN__CE,
    ECN__ECT_0,
    ECN__ECT_1,
    ECN__NOT_ECT,
    IpFragFlowId,
)
from pytcp.protocols.ip.ip_frag_table import IpFragAddOutcome, IpFragTable

_HOST_A__IP4 = Ip4Address("10.0.0.1")
_HOST_B__IP4 = Ip4Address("10.0.0.2")
_HOST_A__IP6 = Ip6Address("2001:db8::1")
_HOST_B__IP6 = Ip6Address("2001:db8::2")


class TestIpFragTableConstruction(TestCase):
    """
    The 'IpFragTable' construction tests.
    """

    def test__ip_frag_table__starts_empty(self) -> None:
        """
        Ensure a freshly built 'IpFragTable' exposes an empty flow
        store, regardless of timeout value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = IpFragTable(timeout=5.0)

        self.assertEqual(
            table.flows,
            {},
            msg="A freshly constructed IpFragTable must hold no flows.",
        )

    def test__ip_frag_table__flows_property_returns_live_dict(self) -> None:
        """
        Ensure 'IpFragTable.flows' returns the live underlying dict
        rather than a copy, so callers (and tests) can observe and
        mutate the store.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        table = IpFragTable(timeout=5.0)

        self.assertIs(
            table.flows,
            table._flows,  # pylint: disable=protected-access
            msg="IpFragTable.flows must be a live view, not a snapshot.",
        )


class TestIpFragTableAddFragmentIp4(TestCase):
    """
    The 'IpFragTable.add_fragment' tests for the IPv4-shaped flow.
    """

    def setUp(self) -> None:
        """
        Build a fresh table per test so flow state cannot leak.
        """

        self._table = IpFragTable(timeout=5.0)
        self._flow_id = IpFragFlowId(
            src=_HOST_A__IP4,
            dst=_HOST_B__IP4,
            id=42,
            proto=IpProto.UDP,
        )

    def test__ip_frag_table__add_fragment__pending_when_more_expected(self) -> None:
        """
        Ensure 'add_fragment' returns the PENDING outcome and
        stores the fragment when the M flag is still set (more
        fragments to come).

        Reference: RFC 791 §3.2 (fragmented datagram still pending).
        """

        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.PENDING,
            msg="A non-final fragment alone must yield the PENDING outcome.",
        )
        self.assertIn(
            self._flow_id,
            self._table.flows,
            msg="The pending fragment must be stored in the flow table.",
        )

    def test__ip_frag_table__add_fragment__contiguous_completion_returns_payload(self) -> None:
        """
        Ensure two contiguous fragments (offset 0 / MF=1, offset 8
        / MF=0) reassemble into a single joined payload, yield the
        COMPLETE outcome, and drop the flow from the store.

        Reference: RFC 791 §3.2 (reassembly on contiguous offset chain).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=False,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="Final fragment of a contiguous flow must yield the COMPLETE outcome.",
        )
        self.assertEqual(
            result.payload,
            b"\xaa" * 8 + b"\xbb" * 8,
            msg="Joined payload must be the concatenation of fragment payloads in offset order.",
        )
        self.assertEqual(
            result.header,
            b"\x45" + b"\x00" * 19,
            msg="Returned header must be the first-fragment header bytes verbatim.",
        )
        self.assertNotIn(
            self._flow_id,
            self._table.flows,
            msg="The flow must be removed from the store after a successful join.",
        )

    def test__ip_frag_table__add_fragment__hole_keeps_pending(self) -> None:
        """
        Ensure a flow with the last-fragment seen but a missing
        middle fragment does not yet reassemble. The completeness
        check requires a contiguous offset chain rooted at zero.

        Reference: RFC 791 §3.2 (reassembly requires contiguous coverage).
        """

        # offset 0 (MF=1) + offset 16 (MF=0) leaves an 8-byte hole at offset 8.
        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=16,
            payload=b"\xcc" * 8,
            flag_mf=False,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.PENDING,
            msg="A flow with a hole must remain PENDING even after the last fragment lands.",
        )
        self.assertIn(
            self._flow_id,
            self._table.flows,
            msg="The flow must be retained while the hole persists.",
        )


class TestIpFragTableAddFragmentIp6(TestCase):
    """
    The 'IpFragTable.add_fragment' tests for the IPv6-shaped flow
    (no proto in the key).
    """

    def test__ip_frag_table__add_fragment__ip6_flow_keyed_without_proto(self) -> None:
        """
        Ensure 'add_fragment' accepts an IPv6 flow id (proto=None,
        the default) and reassembles a contiguous two-fragment
        datagram exactly like the IPv4 path.

        Reference: RFC 8200 §4.5 (IPv6 reassembly key omits protocol).
        """

        table = IpFragTable(timeout=5.0)
        flow_id = IpFragFlowId(src=_HOST_A__IP6, dst=_HOST_B__IP6, id=99)

        table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\x00" * 8,
            flag_mf=True,
            header=b"\x60" + b"\x00" * 39,
        )
        result = table.add_fragment(
            flow_id=flow_id,
            offset=8,
            payload=b"\x11" * 8,
            flag_mf=False,
            header=b"\x60" + b"\x00" * 39,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="An IPv6 contiguous reassembly must yield COMPLETE.",
        )
        self.assertEqual(
            result.payload,
            b"\x00" * 8 + b"\x11" * 8,
            msg="IPv6 flow must reassemble identically to IPv4.",
        )


class TestIpFragTableAtomicFragment(TestCase):
    """
    The 'IpFragTable' RFC 8200 §4.5 atomic-fragment fast-path tests.
    """

    def test__ip_frag_table__add_fragment__atomic_returns_complete_without_admission(self) -> None:
        """
        Ensure an atomic fragment (offset=0, M=0) yields the
        COMPLETE outcome immediately, with the input bytes
        echoed back as the joined datagram, and the flow store
        is not touched at all.

        Reference: RFC 8200 §4.5 (atomic fragment is a complete datagram).
        Reference: RFC 6946 §4 (atomic fragments processed in isolation).
        """

        table = IpFragTable(timeout=5.0)
        flow_id = IpFragFlowId(
            src=_HOST_A__IP6,
            dst=_HOST_B__IP6,
            id=42,
        )

        result = table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\xaa" * 16,
            flag_mf=False,
            header=b"\x60" + b"\x00" * 39,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="An atomic fragment must yield COMPLETE on a single arrival.",
        )
        self.assertEqual(
            result.payload,
            b"\xaa" * 16,
            msg="The atomic fragment's payload bytes must be returned as the joined payload.",
        )
        self.assertEqual(
            result.header,
            b"\x60" + b"\x00" * 39,
            msg="The atomic fragment's header bytes must be returned verbatim.",
        )
        self.assertEqual(
            table.flows,
            {},
            msg="An atomic fragment must not allocate a flow-table entry.",
        )

    def test__ip_frag_table__add_fragment__atomic_isolated_from_existing_flow(self) -> None:
        """
        Ensure an atomic fragment with the same flow id as an
        in-progress non-atomic reassembly does not interact with
        that reassembly: it returns COMPLETE for itself, and the
        existing flow continues unchanged.

        Reference: RFC 6946 §4 (atomic fragments isolated from
        any concurrent non-atomic reassembly).
        """

        table = IpFragTable(timeout=5.0)
        flow_id = IpFragFlowId(
            src=_HOST_A__IP6,
            dst=_HOST_B__IP6,
            id=99,
        )

        # Seed an in-progress non-atomic reassembly.
        table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x60" + b"\x00" * 39,
        )

        # An atomic fragment with the same flow id arrives.
        atomic_result = table.add_fragment(
            flow_id=flow_id,
            offset=0,
            payload=b"\xff" * 16,
            flag_mf=False,
            header=b"\x60" + b"\x00" * 39,
        )

        self.assertIs(
            atomic_result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="The atomic fragment must complete despite a colliding flow id.",
        )
        self.assertEqual(
            atomic_result.payload,
            b"\xff" * 16,
            msg="The atomic fragment must return its own bytes, not the existing flow's.",
        )
        self.assertIn(
            flow_id,
            table.flows,
            msg="The existing non-atomic flow must remain in the store untouched.",
        )
        self.assertEqual(
            bytes(table.flows[flow_id].payload[0]),
            b"\xaa" * 8,
            msg="The existing flow's stored bytes must remain intact.",
        )


class TestIpFragTableExpiry(TestCase):
    """
    The 'IpFragTable' lazy-expiry sweep tests.
    """

    def test__ip_frag_table__expired_flow_is_reaped_on_next_admit(self) -> None:
        """
        Ensure a flow whose timestamp is older than the
        configured timeout is removed from the store the next
        time 'add_fragment' is called for any flow. The reap is
        lazy / opportunistic — there is no separate timer.

        Reference: RFC 791 §3.2 (IPv4 reassembly timeout).
        Reference: RFC 8200 §4.5 (IPv6 reassembly timeout).
        Reference: RFC 8504 §16 (host buffer-hygiene requirement).
        """

        table = IpFragTable(timeout=5.0)
        stale_id = IpFragFlowId(src=_HOST_A__IP4, dst=_HOST_B__IP4, id=1, proto=IpProto.UDP)
        fresh_id = IpFragFlowId(src=_HOST_A__IP4, dst=_HOST_B__IP4, id=2, proto=IpProto.UDP)

        table.add_fragment(
            flow_id=stale_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        # Backdate the stored fragment's timestamp past the timeout.
        stale_flow = table.flows[stale_id]
        object.__setattr__(stale_flow, "timestamp", stale_flow.timestamp - 10.0)

        # Any subsequent add_fragment call triggers the cleanup.
        table.add_fragment(
            flow_id=fresh_id,
            offset=0,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertNotIn(
            stale_id,
            table.flows,
            msg="A flow older than the timeout must be reaped on the next admission.",
        )
        self.assertIn(
            fresh_id,
            table.flows,
            msg="The fresh flow must be admitted alongside the cleanup.",
        )


class TestIpFragTableOverlap(TestCase):
    """
    The 'IpFragTable' RFC 5722 §3 overlap-detection tests.
    """

    def setUp(self) -> None:
        """
        Build a fresh table per test so flow state cannot leak.
        """

        self._table = IpFragTable(timeout=5.0)
        self._flow_id = IpFragFlowId(
            src=_HOST_A__IP4,
            dst=_HOST_B__IP4,
            id=7,
            proto=IpProto.UDP,
        )

    def test__ip_frag_table__add_fragment__overlap_drops_flow(self) -> None:
        """
        Ensure two fragments whose byte ranges overlap (e.g. one
        at offset 0 / length 16 and one at offset 8 / length 8)
        cause the entire flow to be marked discarded and yield
        the OVERLAP outcome on the second arrival.

        Reference: RFC 5722 §3 (silent-discard on fragment overlap).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 16,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.OVERLAP,
            msg="Overlapping byte ranges must yield the OVERLAP outcome.",
        )
        self.assertTrue(
            self._table.flows[self._flow_id].discarded,
            msg="Overlap detection must mark the flow as discarded.",
        )
        self.assertEqual(
            self._table.flows[self._flow_id].payload,
            {},
            msg=(
                "A discarded flow must clear its stored payload to free "
                "memory (RFC 5722 §3 silent-discard semantics)."
            ),
        )

    def test__ip_frag_table__add_fragment__exact_duplicate_treated_as_overlap(self) -> None:
        """
        Ensure two fragments at the same offset with the same
        length are treated as overlapping. PyTCP picks the
        strict reading over the lenient retransmit-tolerant
        interpretation: any same-offset arrival drops the
        in-progress datagram.

        Reference: RFC 5722 §3 (silent-discard, strict reading
        treats exact duplicates as overlapping).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.OVERLAP,
            msg="An exact-duplicate fragment must be treated as OVERLAP under the strict reading.",
        )

    def test__ip_frag_table__add_fragment__subsequent_after_discard_yields_discarded(self) -> None:
        """
        Ensure a fragment arriving for an already-discarded flow
        yields the DISCARDED outcome, the flow stays cleared,
        and reassembly does not happen even if the new fragment
        would otherwise complete the datagram.

        Reference: RFC 5722 §3 ("any constituent fragments,
        including those not yet received, MUST be silently
        discarded").
        """

        # Trigger overlap to mark the flow discarded.
        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 16,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )

        # A fully reasonable final fragment arrives.
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=16,
            payload=b"\xcc" * 8,
            flag_mf=False,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.DISCARDED,
            msg="A fragment for an already-discarded flow must yield DISCARDED.",
        )
        self.assertEqual(
            self._table.flows[self._flow_id].payload,
            {},
            msg="The discarded flow's payload store must remain cleared.",
        )

    def test__ip_frag_table__add_fragment__three_fragments_no_overlap_still_reassembles(self) -> None:
        """
        Ensure overlap detection does not break the multi-
        fragment happy path: three contiguous, non-overlapping
        fragments still reassemble cleanly into a COMPLETE
        outcome.

        Reference: RFC 791 §3.2 (contiguous non-overlapping
        fragments reassemble normally).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=b"\x45" + b"\x00" * 19,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=16,
            payload=b"\xcc" * 8,
            flag_mf=False,
            header=b"\x45" + b"\x00" * 19,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="Three contiguous non-overlapping fragments must reassemble.",
        )
        self.assertEqual(
            result.payload,
            b"\xaa" * 8 + b"\xbb" * 8 + b"\xcc" * 8,
            msg="Joined payload must be the concatenation in offset order.",
        )


class TestIpFragTableEcnAggregation(TestCase):
    """
    The 'IpFragTable' RFC 3168 §5.3 ECN-aggregation tests.

    Each test exercises the per-flow ECN bookkeeping across
    multiple 'add_fragment' calls and asserts on the aggregated
    ECN value carried on the 'IpFragAddResult' returned at
    completion (or the ECN_MIXED__DROP outcome for inconsistent
    ECN sets).
    """

    def setUp(self) -> None:
        """
        Build a fresh table + canonical flow-id per test so ECN
        state cannot leak between cases.
        """

        self._table = IpFragTable(timeout=5.0)
        self._flow_id = IpFragFlowId(
            src=_HOST_A__IP4,
            dst=_HOST_B__IP4,
            id=42,
            proto=IpProto.UDP,
        )
        self._header = b"\x45" + b"\x00" * 19

    def test__ip_frag_table__atomic_fragment_passes_ecn_through(self) -> None:
        """
        Ensure the atomic-fragment fast-path returns the input ECN
        on the IpFragAddResult — there is no aggregation when
        only one fragment exists.

        Reference: RFC 3168 §5 (ECN field on IPv4 header).
        Reference: RFC 6864 §4.1 (atomic-fragment fast-path).
        """

        for ecn in (ECN__NOT_ECT, ECN__ECT_0, ECN__ECT_1, ECN__CE):
            with self.subTest(ecn=ecn):
                result = self._table.add_fragment(
                    flow_id=self._flow_id,
                    offset=0,
                    payload=b"\xaa" * 8,
                    flag_mf=False,
                    header=self._header,
                    ecn=ecn,
                )
                self.assertEqual(
                    result.ecn,
                    ecn,
                    msg=f"Atomic fragment with ecn={ecn} must pass that value through.",
                )

    def test__ip_frag_table__same_ecn_across_fragments_preserved(self) -> None:
        """
        Ensure two contiguous fragments carrying identical ECN
        codepoints reassemble with that codepoint preserved.

        Reference: RFC 3168 §5.3 (reassembly MUST NOT change ECN
        when all fragments carry the same codepoint).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=self._header,
            ecn=ECN__ECT_0,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=False,
            header=self._header,
            ecn=ECN__ECT_0,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="Same-ECN flow must complete normally.",
        )
        self.assertEqual(
            result.ecn,
            ECN__ECT_0,
            msg="All-ECT(0) flow must reassemble with ECT(0) preserved.",
        )

    def test__ip_frag_table__ce_in_one_fragment_propagates(self) -> None:
        """
        Ensure a single CE-bearing fragment in an otherwise
        ECT(0) flow propagates the CE codepoint onto the
        reassembled packet.

        Reference: RFC 3168 §5.3 (set CE on reassembled packet
        when any fragment carries CE and no fragment carries
        Not-ECT).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=self._header,
            ecn=ECN__ECT_0,
        )
        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=True,
            header=self._header,
            ecn=ECN__CE,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=16,
            payload=b"\xcc" * 8,
            flag_mf=False,
            header=self._header,
            ecn=ECN__ECT_0,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="ECT(0)+CE+ECT(0) flow must complete normally.",
        )
        self.assertEqual(
            result.ecn,
            ECN__CE,
            msg="Any-CE-without-Not-ECT flow must reassemble with CE.",
        )

    def test__ip_frag_table__ect_0_with_ect_1_yields_ect_0(self) -> None:
        """
        Ensure a flow mixing ECT(0) and ECT(1) (no CE, no Not-ECT)
        reassembles to ECT(0) per the Linux-canonical pick.

        Reference: RFC 3168 §5.3 (ECN unchanged when no Not-ECT;
        Linux net/ipv4/ip_fragment.c ip_frag_ecn_table[]).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=self._header,
            ecn=ECN__ECT_0,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=False,
            header=self._header,
            ecn=ECN__ECT_1,
        )

        self.assertEqual(
            result.ecn,
            ECN__ECT_0,
            msg="ECT(0)+ECT(1) mix must reassemble to ECT(0).",
        )

    def test__ip_frag_table__ce_mixed_with_not_ect_drops(self) -> None:
        """
        Ensure a flow mixing CE and Not-ECT yields the
        ECN_MIXED__DROP outcome — the §5.3 "MUST NOT set CE if
        any fragment is Not-ECT" rule, applied as the
        Linux-canonical drop action.

        Reference: RFC 3168 §5.3 (CE MUST NOT be set on
        reassembled packet if any fragment carries Not-ECT;
        alternative MUST action is to drop the packet).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=self._header,
            ecn=ECN__NOT_ECT,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=False,
            header=self._header,
            ecn=ECN__CE,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.ECN_MIXED__DROP,
            msg="Not-ECT mixed with CE must yield ECN_MIXED__DROP.",
        )
        self.assertNotIn(
            self._flow_id,
            self._table.flows,
            msg="An ECN-violation flow must be removed from the store.",
        )

    def test__ip_frag_table__ect_mixed_with_not_ect_drops(self) -> None:
        """
        Ensure a flow mixing any ECT codepoint with Not-ECT yields
        the ECN_MIXED__DROP outcome — inconsistent ECN-capability
        across fragments of the same datagram is a malicious or
        broken sender condition.

        Reference: RFC 3168 §5.3 (ECT mixed with Not-ECT is
        inconsistent; Linux drops).
        """

        for foreign_ecn in (ECN__ECT_0, ECN__ECT_1):
            with self.subTest(foreign_ecn=foreign_ecn):
                table = IpFragTable(timeout=5.0)
                table.add_fragment(
                    flow_id=self._flow_id,
                    offset=0,
                    payload=b"\xaa" * 8,
                    flag_mf=True,
                    header=self._header,
                    ecn=ECN__NOT_ECT,
                )
                result = table.add_fragment(
                    flow_id=self._flow_id,
                    offset=8,
                    payload=b"\xbb" * 8,
                    flag_mf=False,
                    header=self._header,
                    ecn=foreign_ecn,
                )
                self.assertIs(
                    result.outcome,
                    IpFragAddOutcome.ECN_MIXED__DROP,
                    msg=f"Not-ECT mixed with {foreign_ecn=} must yield ECN_MIXED__DROP.",
                )

    def test__ip_frag_table__default_ecn_is_zero(self) -> None:
        """
        Ensure 'add_fragment' default for the 'ecn' kwarg is
        Not-ECT (0), so existing call sites that do not pass
        'ecn=' behave identically to the pre-aggregation
        codebase (all-zero fragments reassemble to zero).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._table.add_fragment(
            flow_id=self._flow_id,
            offset=0,
            payload=b"\xaa" * 8,
            flag_mf=True,
            header=self._header,
        )
        result = self._table.add_fragment(
            flow_id=self._flow_id,
            offset=8,
            payload=b"\xbb" * 8,
            flag_mf=False,
            header=self._header,
        )

        self.assertIs(
            result.outcome,
            IpFragAddOutcome.COMPLETE,
            msg="Default-ecn flow must complete normally.",
        )
        self.assertEqual(
            result.ecn,
            ECN__NOT_ECT,
            msg="Omitting ecn= must default to Not-ECT on the aggregated result.",
        )
