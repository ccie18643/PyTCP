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
This module contains tests for the 'IpFragFlowId' and 'IpFragData' dataclasses.

pytcp/tests/unit/protocols/ip/test__ip__ip_frag.py

ver 3.0.8
"""

import time
from dataclasses import FrozenInstanceError, fields
from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import IpProto
from net_proto.lib.buffer import Buffer
from pytcp.protocols.ip.ip_frag import (
    ECN__CE,
    ECN__ECT_0,
    ECN__ECT_1,
    ECN__NOT_ECT,
    IpFragData,
    IpFragFlowId,
    aggregate_ecn,
    iter_fragment_chunks,
)


class TestIpFragFlowIdIp4(TestCase):
    """
    The 'IpFragFlowId' tests covering the IPv4 address flow.
    """

    @override
    def setUp(self) -> None:
        """
        Build a canonical IPv4 'IpFragFlowId' instance for every test in
        this class.
        """

        self._src = Ip4Address("10.0.0.1")
        self._dst = Ip4Address("10.0.0.2")
        self._id = 0x1234

        self._flow_id = IpFragFlowId(
            src=self._src,
            dst=self._dst,
            id=self._id,
        )

    def test__ip_frag_flow_id__src(self) -> None:
        """
        Ensure the 'src' field stores the constructor's IPv4 source address.

        Reference: RFC 791 §3.2 (IPv4 reassembly flow key — src, dst, id, protocol).
        """

        self.assertEqual(
            self._flow_id.src,
            self._src,
            msg="IpFragFlowId.src must equal the IPv4 address passed to the constructor.",
        )

    def test__ip_frag_flow_id__dst(self) -> None:
        """
        Ensure the 'dst' field stores the constructor's IPv4 destination
        address.

        Reference: RFC 791 §3.2 (IPv4 reassembly flow key — src, dst, id, protocol).
        """

        self.assertEqual(
            self._flow_id.dst,
            self._dst,
            msg="IpFragFlowId.dst must equal the IPv4 address passed to the constructor.",
        )

    def test__ip_frag_flow_id__id(self) -> None:
        """
        Ensure the 'id' field stores the constructor's identification value.

        Reference: RFC 791 §3.2 (IPv4 reassembly flow key — src, dst, id, protocol).
        """

        self.assertEqual(
            self._flow_id.id,
            self._id,
            msg="IpFragFlowId.id must equal the identifier passed to the constructor.",
        )


class TestIpFragFlowIdIp6(TestCase):
    """
    The 'IpFragFlowId' tests covering the IPv6 address flow.
    """

    def test__ip_frag_flow_id__ip6_src_and_dst(self) -> None:
        """
        Ensure the 'src' / 'dst' fields accept 'Ip6Address' values — the
        type union in the source must support both IPv4 and IPv6.

        Reference: RFC 8200 §4.5 (IPv6 reassembly flow key — src, dst, id).
        """

        src = Ip6Address("2001:db8::1")
        dst = Ip6Address("2001:db8::2")

        flow_id = IpFragFlowId(src=src, dst=dst, id=0xABCDEF12)

        self.assertEqual(
            flow_id.src,
            src,
            msg="IpFragFlowId.src must accept an IPv6 address value.",
        )
        self.assertEqual(
            flow_id.dst,
            dst,
            msg="IpFragFlowId.dst must accept an IPv6 address value.",
        )


class TestIpFragFlowIdSemantics(TestCase):
    """
    The 'IpFragFlowId' hashability / equality / immutability tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build two equal and one distinct flow-id instance to exercise the
        equality and hash contracts.
        """

        self._src = Ip4Address("10.0.0.1")
        self._dst = Ip4Address("10.0.0.2")

        self._flow_a = IpFragFlowId(src=self._src, dst=self._dst, id=1)
        self._flow_b = IpFragFlowId(src=self._src, dst=self._dst, id=1)
        self._flow_c = IpFragFlowId(src=self._src, dst=self._dst, id=2)

    def test__ip_frag_flow_id__equality(self) -> None:
        """
        Ensure two 'IpFragFlowId' instances with identical fields compare
        equal (frozen dataclass default __eq__).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._flow_a,
            self._flow_b,
            msg="Two IpFragFlowId instances with identical fields must be equal.",
        )

    def test__ip_frag_flow_id__inequality(self) -> None:
        """
        Ensure two 'IpFragFlowId' instances that differ in one field
        compare unequal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            self._flow_a,
            self._flow_c,
            msg="IpFragFlowId instances must be unequal when any field differs.",
        )

    def test__ip_frag_flow_id__hash_matches_for_equal_instances(self) -> None:
        """
        Ensure equal 'IpFragFlowId' instances produce equal hashes so they
        can be used as dict keys in the fragment store.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            hash(self._flow_a),
            hash(self._flow_b),
            msg="Equal IpFragFlowId instances must share the same hash.",
        )

    def test__ip_frag_flow_id__usable_as_dict_key(self) -> None:
        """
        Ensure 'IpFragFlowId' works as a dict key and equal instances
        resolve to the same entry. This is the flow-id's real use site.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        store: dict[IpFragFlowId, str] = {self._flow_a: "frag-bucket"}

        self.assertEqual(
            store[self._flow_b],
            "frag-bucket",
            msg="An equal IpFragFlowId must hit the same dict entry.",
        )

    def test__ip_frag_flow_id__is_frozen(self) -> None:
        """
        Ensure 'IpFragFlowId' is frozen — direct attribute mutation must
        raise 'FrozenInstanceError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(FrozenInstanceError):
            self._flow_a.id = 999  # type: ignore[misc]

    def test__ip_frag_flow_id__has_slots(self) -> None:
        """
        Ensure 'IpFragFlowId' uses '__slots__' (no per-instance __dict__),
        which is the in-source declaration and a memory/perf guarantee.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            hasattr(self._flow_a, "__dict__"),
            msg="IpFragFlowId must be slotted; instances must not carry a __dict__.",
        )


class TestIpFragFlowIdFields(TestCase):
    """
    The 'IpFragFlowId' dataclass field-layout tests.
    """

    def test__ip_frag_flow_id__field_names(self) -> None:
        """
        Ensure the dataclass exposes exactly the (src, dst, id,
        proto) fields in that order; a silent rename would be a
        wire-format regression.

        Reference: RFC 791 §3.2 (IPv4 reassembly key includes protocol).
        Reference: RFC 8200 §4.5 (IPv6 reassembly key omits protocol).
        """

        self.assertEqual(
            tuple(f.name for f in fields(IpFragFlowId)),
            ("src", "dst", "id", "proto"),
            msg="IpFragFlowId must declare exactly (src, dst, id, proto) in order.",
        )


class TestIpFragFlowIdProto(TestCase):
    """
    The 'IpFragFlowId.proto' field tests.
    """

    def test__ip_frag_flow_id__proto_defaults_to_none(self) -> None:
        """
        Ensure the 'proto' field defaults to None so callers in
        the IPv6 path (whose reassembly key omits the protocol)
        can construct the flow-id without specifying it.

        Reference: RFC 8200 §4.5 (IPv6 reassembly key omits protocol).
        """

        flow = IpFragFlowId(
            src=Ip6Address("2001:db8::1"),
            dst=Ip6Address("2001:db8::2"),
            id=1,
        )

        self.assertIsNone(
            flow.proto,
            msg="IpFragFlowId.proto must default to None for the IPv6-shaped key.",
        )

    def test__ip_frag_flow_id__proto_distinguishes_equal_src_dst_id(self) -> None:
        """
        Ensure two 'IpFragFlowId' instances that share src/dst/ID
        but differ only in 'proto' compare unequal and hash apart,
        so they occupy distinct dict entries — the IPv4 reassembly
        invariant.

        Reference: RFC 791 §3.2 (IPv4 reassembly key includes protocol).
        """

        src = Ip4Address("10.0.0.1")
        dst = Ip4Address("10.0.0.2")

        flow_udp = IpFragFlowId(src=src, dst=dst, id=42, proto=IpProto.UDP)
        flow_tcp = IpFragFlowId(src=src, dst=dst, id=42, proto=IpProto.TCP)

        self.assertNotEqual(
            flow_udp,
            flow_tcp,
            msg=(
                "Two IpFragFlowId instances differing only in 'proto' must " "be unequal (RFC 791 §3.2 reassembly key)."
            ),
        )
        self.assertNotEqual(
            hash(flow_udp),
            hash(flow_tcp),
            msg=(
                "Hashes of IpFragFlowId instances differing only in 'proto' "
                "must differ so dict lookup separates the two streams."
            ),
        )


class TestIpFragDataConstruction(TestCase):
    """
    The 'IpFragData' construction tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a canonical 'IpFragData' instance with one fragment in the
        payload dict so the tests can inspect every field.
        """

        self._header = b"\x45\x00\x00\x14"
        self._payload: dict[int, Buffer] = {0: b"AAAA", 8: b"BBBB"}

        self._frag = IpFragData(header=self._header, payload=self._payload)

    def test__ip_frag_data__header(self) -> None:
        """
        Ensure the 'header' field stores the constructor's byte payload
        verbatim (used later to rebuild the reassembled packet).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._frag.header,
            self._header,
            msg="IpFragData.header must equal the bytes passed to the constructor.",
        )

    def test__ip_frag_data__payload(self) -> None:
        """
        Ensure the 'payload' field stores the constructor's offset->bytes
        mapping verbatim.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._frag.payload,
            self._payload,
            msg="IpFragData.payload must equal the dict passed to the constructor.",
        )

    def test__ip_frag_data__timestamp_bracketed_by_wall_clock(self) -> None:
        """
        Ensure the 'timestamp' field, populated by the dataclass
        'default_factory', lies between the wall-clock reading taken just
        before and just after construction. Guards against any change
        that would replace 'default_factory=time.time' with a constant.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        before = time.time()
        frag = IpFragData(header=b"", payload={})
        after = time.time()

        self.assertGreaterEqual(
            frag.timestamp,
            before,
            msg="IpFragData.timestamp must be >= the clock reading just before construction.",
        )
        self.assertLessEqual(
            frag.timestamp,
            after,
            msg="IpFragData.timestamp must be <= the clock reading just after construction.",
        )

    def test__ip_frag_data__timestamp_default_factory_is_time_time(self) -> None:
        """
        Ensure the 'timestamp' dataclass field's 'default_factory' is
        exactly 'time.time' — this is the contract that underpins the
        wall-clock bracketing test and the fragment-reassembly TTL logic.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        timestamp_field = next(f for f in fields(IpFragData) if f.name == "timestamp")

        self.assertIs(
            timestamp_field.default_factory,
            time.time,
            msg="IpFragData.timestamp default_factory must be 'time.time'.",
        )

    def test__ip_frag_data__last_defaults_to_false(self) -> None:
        """
        Ensure the 'last' flag defaults to False — a fresh fragment bucket
        has not yet received the last-fragment packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._frag.last,
            msg="IpFragData.last must default to False on a freshly built instance.",
        )


class TestIpFragDataReceivedLastFrag(TestCase):
    """
    The 'IpFragData.received_last_frag()' tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh 'IpFragData' instance per test so mutations in one
        test cannot leak into the next.
        """

        self._frag = IpFragData(header=b"hdr", payload={0: b"data"})

    def test__ip_frag_data__received_last_frag__sets_flag(self) -> None:
        """
        Ensure 'received_last_frag()' flips 'last' from False to True by
        bypassing the frozen-dataclass barrier via 'object.__setattr__'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._frag.last,
            msg="Precondition: the 'last' flag must start False.",
        )

        self._frag.received_last_frag()

        self.assertTrue(
            self._frag.last,
            msg="IpFragData.received_last_frag() must set the 'last' flag to True.",
        )

    def test__ip_frag_data__received_last_frag__idempotent(self) -> None:
        """
        Ensure calling 'received_last_frag()' a second time keeps the
        'last' flag True (flag is monotone).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._frag.received_last_frag()
        self._frag.received_last_frag()

        self.assertTrue(
            self._frag.last,
            msg="A repeat received_last_frag() call must keep 'last' True.",
        )

    def test__ip_frag_data__direct_mutation_still_forbidden(self) -> None:
        """
        Ensure the frozen-dataclass contract still rejects direct attribute
        assignment, even though 'received_last_frag()' mutates via the
        'object.__setattr__' escape hatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(FrozenInstanceError):
            self._frag.last = True  # type: ignore[misc]


class TestIpFragDataMarkDiscarded(TestCase):
    """
    The 'IpFragData.mark_discarded()' tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh 'IpFragData' instance with at least one stored
        fragment so 'mark_discarded()' has payload to clear.
        """

        self._frag = IpFragData(
            header=b"hdr",
            payload={0: b"AAAA", 8: b"BBBB"},
        )

    def test__ip_frag_data__discarded_defaults_to_false(self) -> None:
        """
        Ensure the 'discarded' flag defaults to False on
        construction so a freshly admitted flow never appears
        already-discarded.

        Reference: RFC 5722 §3 (discarded state is opt-in per
        overlap detection, not the default).
        """

        self.assertFalse(
            self._frag.discarded,
            msg="IpFragData.discarded must default to False on a freshly built instance.",
        )

    def test__ip_frag_data__mark_discarded__sets_flag(self) -> None:
        """
        Ensure 'mark_discarded()' flips 'discarded' from False to
        True via the frozen-dataclass escape hatch.

        Reference: RFC 5722 §3 (silent-discard requires per-flow
        discarded bit).
        """

        self._frag.mark_discarded()

        self.assertTrue(
            self._frag.discarded,
            msg="mark_discarded() must set 'discarded' to True.",
        )

    def test__ip_frag_data__mark_discarded__clears_payload(self) -> None:
        """
        Ensure 'mark_discarded()' clears the per-offset fragment
        store so a discarded flow does not retain memory for the
        bytes it already received.

        Reference: RFC 5722 §3 (silent-discard semantics; freed
        memory is part of the buffer-hygiene goal).
        """

        self._frag.mark_discarded()

        self.assertEqual(
            self._frag.payload,
            {},
            msg="mark_discarded() must clear the stored fragment payload.",
        )


class TestIpFragDataFields(TestCase):
    """
    The 'IpFragData' dataclass field-layout tests.
    """

    def test__ip_frag_data__field_names(self) -> None:
        """
        Ensure the dataclass exposes exactly (timestamp, header,
        last, payload, ecn, discarded) in that order. The 'ecn'
        field tracks per-offset codepoints for aggregation at
        reassembly time. The 'discarded' field marks a flow
        unrecoverable while it still occupies the table until
        the expiry sweep reaps it.

        Reference: RFC 5722 §3 (silent-discard requires per-flow
        discarded bit).
        Reference: RFC 3168 §5.3 (per-fragment ECN tracking for
        aggregation at reassembly).
        """

        self.assertEqual(
            tuple(f.name for f in fields(IpFragData)),
            ("timestamp", "header", "last", "payload", "ecn", "discarded"),
            msg=("IpFragData must declare exactly " "(timestamp, header, last, payload, ecn, discarded) in order."),
        )

    def test__ip_frag_data__timestamp_is_init_false(self) -> None:
        """
        Ensure the 'timestamp' field is 'init=False' so callers cannot
        inject a spoofed construction time.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        timestamp_field = next(f for f in fields(IpFragData) if f.name == "timestamp")

        self.assertFalse(
            timestamp_field.init,
            msg="IpFragData.timestamp must be init=False (populated by default_factory).",
        )

    def test__ip_frag_data__last_is_init_false(self) -> None:
        """
        Ensure the 'last' field is 'init=False' — it may only be set via
        'received_last_frag()', not through the constructor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        last_field = next(f for f in fields(IpFragData) if f.name == "last")

        self.assertFalse(
            last_field.init,
            msg="IpFragData.last must be init=False (flipped via received_last_frag).",
        )

    def test__ip_frag_data__has_slots(self) -> None:
        """
        Ensure 'IpFragData' uses '__slots__' — matches the in-source
        'slots=True' declaration.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frag = IpFragData(header=b"", payload={})

        self.assertFalse(
            hasattr(frag, "__dict__"),
            msg="IpFragData must be slotted; instances must not carry a __dict__.",
        )


class TestIterFragmentChunks(TestCase):
    """
    The 'iter_fragment_chunks' helper tests — shared IPv4/IPv6
    fragmentation payload slicer.
    """

    def test__iter_fragment_chunks__single_chunk_fits_budget(self) -> None:
        """
        Ensure a payload that fits in 'max_chunk_bytes' yields exactly
        one '(offset=0, chunk=payload, is_last=True)' tuple.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = b"X" * 100
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=200))

        self.assertEqual(
            chunks,
            [(0, payload, True)],
            msg="A payload smaller than the budget must yield a single is_last chunk at offset 0.",
        )

    def test__iter_fragment_chunks__two_chunks(self) -> None:
        """
        Ensure a payload twice the (aligned) budget yields two chunks
        with offsets 0 and 'aligned_budget', is_last=False then True.

        Reference: RFC 791 §3.1 (Fragment Offset, MF flag).
        """

        payload = b"A" * 16 + b"B" * 16
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=16))

        self.assertEqual(
            chunks,
            [(0, b"A" * 16, False), (16, b"B" * 16, True)],
            msg="A 2-chunk slice must carry MF=False on chunk #0 and MF=True on chunk #1.",
        )

    def test__iter_fragment_chunks__three_chunks_with_short_tail(self) -> None:
        """
        Ensure a payload that does not divide evenly by the chunk size
        yields a short final chunk marked is_last=True.

        Reference: RFC 791 §3.1 (Fragment Offset, MF flag).
        """

        payload = b"A" * 16 + b"B" * 16 + b"C" * 5
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=16))

        self.assertEqual(
            chunks,
            [
                (0, b"A" * 16, False),
                (16, b"B" * 16, False),
                (32, b"C" * 5, True),
            ],
            msg="The final short chunk must carry is_last=True and the correct offset.",
        )

    def test__iter_fragment_chunks__exact_multiple_of_budget(self) -> None:
        """
        Ensure a payload that is an exact multiple of the chunk size
        yields chunks of equal length with is_last=True on only the
        last one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = b"X" * 24
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=8))

        self.assertEqual(
            chunks,
            [
                (0, b"X" * 8, False),
                (8, b"X" * 8, False),
                (16, b"X" * 8, True),
            ],
            msg="Exact-multiple slicing must not produce a stray zero-length last chunk.",
        )

    def test__iter_fragment_chunks__non_aligned_budget_rounded_down(self) -> None:
        """
        Ensure a 'max_chunk_bytes' that is not 8-byte aligned is
        rounded down to the nearest 8-byte boundary so every chunk
        except the last carries an 8-byte-aligned payload length.

        Reference: RFC 791 §3.1 (Fragment Offset measured in 8-octet units).
        Reference: RFC 8200 §4.5 (Fragment header Fragment Offset in 8-octet units).
        """

        payload = b"X" * 40
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=17))

        self.assertEqual(
            chunks,
            [
                (0, b"X" * 16, False),
                (16, b"X" * 16, False),
                (32, b"X" * 8, True),
            ],
            msg="A budget of 17 must round down to 16; offsets must remain 8-byte aligned.",
        )

    def test__iter_fragment_chunks__minimum_legal_budget_8(self) -> None:
        """
        Ensure a 'max_chunk_bytes=8' (smallest legal aligned chunk)
        slices the payload into 8-byte chunks.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = b"X" * 16
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=8))

        self.assertEqual(
            chunks,
            [(0, b"X" * 8, False), (8, b"X" * 8, True)],
            msg="Minimum-legal budget of 8 must produce 8-byte chunks aligned at offsets 0, 8.",
        )

    def test__iter_fragment_chunks__empty_payload_yields_nothing(self) -> None:
        """
        Ensure an empty payload yields zero chunks rather than a
        spurious '(0, b"", True)' entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        chunks = list(iter_fragment_chunks(b"", max_chunk_bytes=16))

        self.assertEqual(
            chunks,
            [],
            msg="Empty payload must produce no chunks; callers gate on this before invoking.",
        )

    def test__iter_fragment_chunks__rejects_budget_below_8(self) -> None:
        """
        Ensure a 'max_chunk_bytes' less than 8 raises ValueError —
        the Fragment-Offset wire encoding requires at least an
        8-octet chunk on every non-final fragment.

        Reference: RFC 791 §3.1 (8-octet alignment minimum).
        Reference: RFC 8200 §4.5 (8-octet alignment minimum).
        """

        with self.assertRaises(ValueError) as ctx:
            list(iter_fragment_chunks(b"X" * 16, max_chunk_bytes=7))

        self.assertIn(
            "max_chunk_bytes",
            str(ctx.exception),
            msg="The ValueError message must name the offending kwarg.",
        )

    def test__iter_fragment_chunks__accepts_bytes_bytearray_memoryview(self) -> None:
        """
        Ensure the helper accepts every Buffer alias variant
        ('bytes', 'bytearray', 'memoryview') and returns identical
        chunk byte content for each.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for variant in (b"X" * 24, bytearray(b"X" * 24), memoryview(b"X" * 24)):
            with self.subTest(variant=type(variant).__name__):
                chunks = list(iter_fragment_chunks(variant, max_chunk_bytes=8))
                self.assertEqual(
                    [(off, bytes(chunk), is_last) for off, chunk, is_last in chunks],
                    [
                        (0, b"X" * 8, False),
                        (8, b"X" * 8, False),
                        (16, b"X" * 8, True),
                    ],
                    msg=f"Variant {type(variant).__name__} must produce identical chunk content.",
                )

    def test__iter_fragment_chunks__concatenation_round_trip(self) -> None:
        """
        Ensure the concatenation of every yielded chunk reconstitutes
        the original payload byte-for-byte across a representative
        matrix of payload sizes and chunk budgets — the strongest
        general invariant that catches slicing-math regressions a
        per-case tuple match would miss.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for payload_len, budget in [
            (0, 8),
            (1, 8),
            (7, 8),
            (8, 8),
            (15, 8),
            (16, 16),
            (1480, 1480),
            (1481, 1480),
            (2959, 1480),
            (2960, 1480),
            (65535, 1480),
            (65535, 1500),
        ]:
            with self.subTest(payload_len=payload_len, budget=budget):
                payload = bytes(range(256)) * (payload_len // 256) + bytes(range(payload_len % 256))
                self.assertEqual(
                    len(payload),
                    payload_len,
                    msg="Test fixture must produce the requested payload length.",
                )

                joined = b"".join(chunk for _, chunk, _ in iter_fragment_chunks(payload, max_chunk_bytes=budget))

                self.assertEqual(
                    joined,
                    payload,
                    msg=(
                        f"Concatenation of chunks must reconstitute the original payload "
                        f"for {payload_len=}, {budget=}."
                    ),
                )

    def test__iter_fragment_chunks__ethernet_mtu_scale(self) -> None:
        """
        Ensure a realistic Ethernet-MTU shaped slice (payload near
        the 65535-byte IPv4 total-length ceiling, budget=1480 bytes
        of usable per-fragment payload) produces the expected
        fragment count, monotonically increasing offsets, and final
        is_last on the tail.

        Reference: RFC 791 §3.1 (13-bit Fragment Offset in 8-octet units).
        Reference: RFC 8200 §4.5 (Fragment header Fragment Offset width).
        """

        payload = b"X" * 65000  # large but well within 13-bit offset range
        budget = 1480  # Ethernet MTU 1500 - IPv4 base header 20

        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=budget))

        # Expected count: ceil(65000 / 1480) = 44 chunks.
        self.assertEqual(
            len(chunks),
            44,
            msg=f"65000-byte payload at budget=1480 must produce 44 chunks, got {len(chunks)}.",
        )

        # Per-chunk invariants: every offset is a multiple of 8 and
        # strictly greater than the previous; only the last chunk
        # carries is_last=True; sum of chunk lengths equals payload
        # length.
        previous_offset = -1
        total_chunk_bytes = 0
        for index, (offset, chunk, is_last) in enumerate(chunks):
            self.assertEqual(
                offset % 8,
                0,
                msg=f"Chunk #{index} offset {offset} must be 8-byte aligned.",
            )
            self.assertGreater(
                offset,
                previous_offset,
                msg=f"Chunk #{index} offset {offset} must exceed previous {previous_offset}.",
            )
            self.assertEqual(
                is_last,
                index == len(chunks) - 1,
                msg=f"Chunk #{index} is_last must be True only on the final chunk.",
            )
            previous_offset = offset
            total_chunk_bytes += len(chunk)

        self.assertEqual(
            total_chunk_bytes,
            len(payload),
            msg="Sum of chunk lengths must equal the original payload length.",
        )

        # Highest offset must remain inside the 13-bit Fragment-
        # Offset wire field (max value 0x1FFF in 8-byte units =
        # 65528 bytes).
        self.assertLess(
            chunks[-1][0],
            65528,
            msg=f"Final offset {chunks[-1][0]} must fit in the 13-bit Fragment-Offset field.",
        )

    def test__iter_fragment_chunks__payload_exactly_equals_budget(self) -> None:
        """
        Ensure a payload of length exactly equal to the (aligned)
        budget yields a single chunk with is_last=True — never two
        chunks where the second one is empty.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = b"Y" * 16
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=16))

        self.assertEqual(
            chunks,
            [(0, payload, True)],
            msg=(
                "Exact-fit payload must yield a single is_last chunk; a spurious "
                "(16, b'', True) tail would indicate an off-by-one in the while-loop "
                "termination."
            ),
        )

    def test__iter_fragment_chunks__offset_monotonicity_invariant(self) -> None:
        """
        Ensure every yielded offset is strictly greater than the
        previous one and is 8-byte aligned, across a 5-chunk slice.
        Guards against any future refactor that breaks the offset
        increment or alignment maintenance.

        Reference: RFC 791 §3.1 (Fragment Offset 8-octet alignment).
        Reference: RFC 8200 §4.5 (Fragment Offset 8-octet alignment).
        """

        payload = b"Z" * (16 * 5)
        chunks = list(iter_fragment_chunks(payload, max_chunk_bytes=16))

        offsets = [offset for offset, _, _ in chunks]

        self.assertEqual(
            offsets,
            sorted(offsets),
            msg="Offsets must be monotonically non-decreasing.",
        )
        self.assertEqual(
            len(offsets),
            len(set(offsets)),
            msg="Offsets must be strictly increasing (no duplicates).",
        )
        for index, offset in enumerate(offsets):
            self.assertEqual(
                offset % 8,
                0,
                msg=f"Offset #{index} ({offset}) must be a multiple of 8.",
            )


class TestAggregateEcn(TestCase):
    """
    The 'aggregate_ecn' helper tests — RFC 3168 §5.3 ECN
    aggregation across fragments of a reassembled datagram.
    """

    def test__aggregate_ecn__all_not_ect_preserves_not_ect(self) -> None:
        """
        Ensure a flow of fragments all carrying Not-ECT (00)
        reassembles to Not-ECT — the no-ECN-capable case.

        Reference: RFC 3168 §5.3 (reassembly MUST NOT change ECN
        when all fragments carry the same codepoint).
        """

        self.assertEqual(
            aggregate_ecn([ECN__NOT_ECT, ECN__NOT_ECT, ECN__NOT_ECT]),
            ECN__NOT_ECT,
            msg="All-Not-ECT fragments must reassemble to Not-ECT.",
        )

    def test__aggregate_ecn__all_ect_0_preserves_ect_0(self) -> None:
        """
        Ensure a flow of fragments all carrying ECT(0) (10)
        reassembles to ECT(0).

        Reference: RFC 3168 §5.3 (reassembly MUST NOT change ECN
        when all fragments carry the same codepoint).
        """

        self.assertEqual(
            aggregate_ecn([ECN__ECT_0, ECN__ECT_0]),
            ECN__ECT_0,
            msg="All-ECT(0) fragments must reassemble to ECT(0).",
        )

    def test__aggregate_ecn__all_ect_1_preserves_ect_1(self) -> None:
        """
        Ensure a flow of fragments all carrying ECT(1) (01)
        reassembles to ECT(1).

        Reference: RFC 3168 §5.3 (reassembly MUST NOT change ECN
        when all fragments carry the same codepoint).
        """

        self.assertEqual(
            aggregate_ecn([ECN__ECT_1, ECN__ECT_1, ECN__ECT_1]),
            ECN__ECT_1,
            msg="All-ECT(1) fragments must reassemble to ECT(1).",
        )

    def test__aggregate_ecn__all_ce_preserves_ce(self) -> None:
        """
        Ensure a flow of fragments all carrying CE (11) reassembles
        to CE — every fragment already signals congestion.

        Reference: RFC 3168 §5.3 (reassembly MUST NOT change ECN
        when all fragments carry the same codepoint).
        """

        self.assertEqual(
            aggregate_ecn([ECN__CE, ECN__CE]),
            ECN__CE,
            msg="All-CE fragments must reassemble to CE.",
        )

    def test__aggregate_ecn__ce_with_ect_0_yields_ce(self) -> None:
        """
        Ensure a CE-bearing fragment combined with ECT(0) fragments
        propagates the CE codepoint onto the reassembled packet.

        Reference: RFC 3168 §5.3 (set CE on reassembled packet when
        any fragment carries CE and no fragment carries Not-ECT).
        """

        self.assertEqual(
            aggregate_ecn([ECN__ECT_0, ECN__CE, ECN__ECT_0]),
            ECN__CE,
            msg="CE + ECT(0) must reassemble to CE.",
        )

    def test__aggregate_ecn__ce_with_ect_1_yields_ce(self) -> None:
        """
        Ensure a CE-bearing fragment combined with ECT(1) fragments
        propagates the CE codepoint.

        Reference: RFC 3168 §5.3 (set CE on reassembled packet when
        any fragment carries CE and no fragment carries Not-ECT).
        """

        self.assertEqual(
            aggregate_ecn([ECN__ECT_1, ECN__CE]),
            ECN__CE,
            msg="CE + ECT(1) must reassemble to CE.",
        )

    def test__aggregate_ecn__ce_with_both_ect_yields_ce(self) -> None:
        """
        Ensure a CE-bearing fragment combined with both ECT(0) and
        ECT(1) fragments still propagates the CE codepoint.

        Reference: RFC 3168 §5.3 (set CE on reassembled packet when
        any fragment carries CE and no fragment carries Not-ECT).
        """

        self.assertEqual(
            aggregate_ecn([ECN__ECT_0, ECN__ECT_1, ECN__CE]),
            ECN__CE,
            msg="CE + ECT(0) + ECT(1) must reassemble to CE.",
        )

    def test__aggregate_ecn__ect_0_with_ect_1_yields_ect_0(self) -> None:
        """
        Ensure mixed ECT(0) and ECT(1) fragments (with no CE and no
        Not-ECT) reassemble to ECT(0) — the Linux-canonical pick
        for an ambiguous ECT-only mix.

        Reference: RFC 3168 §5.3 (ECN unchanged when no Not-ECT;
        Linux net/ipv4/ip_fragment.c ip_frag_ecn_table[]).
        """

        self.assertEqual(
            aggregate_ecn([ECN__ECT_0, ECN__ECT_1]),
            ECN__ECT_0,
            msg="ECT(0) + ECT(1) must reassemble to ECT(0).",
        )

    def test__aggregate_ecn__ce_with_not_ect_returns_none(self) -> None:
        """
        Ensure a CE-bearing fragment mixed with a Not-ECT fragment
        signals 'drop' (returns None) — the reassembled packet
        MUST NOT carry CE when any fragment is Not-ECT.

        Reference: RFC 3168 §5.3 (CE MUST NOT be set on reassembled
        packet if any fragment carries Not-ECT; the alternative
        action is to drop).
        """

        self.assertIsNone(
            aggregate_ecn([ECN__NOT_ECT, ECN__CE]),
            msg="CE mixed with Not-ECT must signal drop (None).",
        )

    def test__aggregate_ecn__ect_0_with_not_ect_returns_none(self) -> None:
        """
        Ensure an ECT(0) fragment mixed with a Not-ECT fragment
        signals drop — inconsistent ECN-capability across the
        fragments of a single datagram is a malicious or broken
        sender condition.

        Reference: RFC 3168 §5.3 (ECT mixed with Not-ECT is
        inconsistent; Linux drops).
        """

        self.assertIsNone(
            aggregate_ecn([ECN__NOT_ECT, ECN__ECT_0]),
            msg="ECT(0) mixed with Not-ECT must signal drop (None).",
        )

    def test__aggregate_ecn__ect_1_with_not_ect_returns_none(self) -> None:
        """
        Ensure an ECT(1) fragment mixed with a Not-ECT fragment
        signals drop.

        Reference: RFC 3168 §5.3 (ECT mixed with Not-ECT is
        inconsistent; Linux drops).
        """

        self.assertIsNone(
            aggregate_ecn([ECN__NOT_ECT, ECN__ECT_1]),
            msg="ECT(1) mixed with Not-ECT must signal drop (None).",
        )

    def test__aggregate_ecn__all_three_mixed_with_not_ect_returns_none(self) -> None:
        """
        Ensure any mix containing Not-ECT alongside ECT-capable
        codepoints signals drop — the rule is "any Not-ECT in the
        set, with any non-Not-ECT, fails".

        Reference: RFC 3168 §5.3 (Linux net/ipv4/ip_fragment.c
        ip_frag_ecn_table[] drops every state mixing Not-ECT with
        anything else).
        """

        self.assertIsNone(
            aggregate_ecn([ECN__NOT_ECT, ECN__ECT_0, ECN__ECT_1, ECN__CE]),
            msg="Any mix containing Not-ECT must signal drop (None).",
        )

    def test__aggregate_ecn__single_fragment_passes_through(self) -> None:
        """
        Ensure a one-element list (atomic-datagram fast-path)
        returns that element regardless of value — no aggregation
        possible.

        Reference: PyTCP test infrastructure (atomic-fragment
        fast-path; no RFC clause for single-fragment input).
        """

        for ecn in (ECN__NOT_ECT, ECN__ECT_0, ECN__ECT_1, ECN__CE):
            with self.subTest(ecn=ecn):
                self.assertEqual(
                    aggregate_ecn([ecn]),
                    ecn,
                    msg=f"Single-fragment input {ecn} must pass through unchanged.",
                )
