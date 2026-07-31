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
This module contains tests for the 'PacketStats', 'PacketStatsRx', and
'PacketStatsTx' data stores.

pytcp/tests/unit/lib/test__lib__packet_stats.py

ver 3.0.9
"""

from dataclasses import FrozenInstanceError, dataclass, fields, is_dataclass
from typing import Any
from unittest import TestCase

from pytcp.lib.packet_stats import (
    LinkStatsCounters,
    PacketStats,
    PacketStatsRx,
    PacketStatsShards,
    PacketStatsTx,
)
from pytcp.tests.lib.parameterized import parameterized_class


class TestPacketStatsBase(TestCase):
    """
    The 'PacketStats' base-class tests.
    """

    def test__packet_stats__is_dataclass(self) -> None:
        """
        Ensure 'PacketStats' itself is decorated with '@dataclass', so
        subclasses inherit the proper dataclass bookkeeping.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            is_dataclass(PacketStats),
            msg="PacketStats must itself be a dataclass so subclasses inherit its machinery.",
        )

    def test__packet_stats__has_no_fields(self) -> None:
        """
        Ensure 'PacketStats' declares no fields itself; it is a pure
        marker class. Regressions that move fields up into the base
        would silently conflate RX and TX stat namespaces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            fields(PacketStats),
            (),
            msg="PacketStats must declare zero fields (pure marker class).",
        )

    def test__packet_stats__is_slotted(self) -> None:
        """
        Ensure 'PacketStats' uses '__slots__' so no ad-hoc attribute can
        leak onto instances outside the declared field set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStats()

        self.assertFalse(
            hasattr(stats, "__dict__"),
            msg="PacketStats must be slotted; instances must not carry a __dict__.",
        )


@parameterized_class(
    [
        {
            "_description": "PacketStatsRx (RX-side stats dataclass).",
            "_cls": PacketStatsRx,
            "_results": {
                "is_subclass_of_packet_stats": True,
                "is_dataclass": True,
                "is_slotted": True,
                "field_count": 225,
            },
        },
        {
            "_description": "PacketStatsTx (TX-side stats dataclass).",
            "_cls": PacketStatsTx,
            "_results": {
                "is_subclass_of_packet_stats": True,
                "is_dataclass": True,
                "is_slotted": True,
                "field_count": 125,
            },
        },
    ]
)
class TestPacketStatsSubclasses(TestCase):
    """
    The 'PacketStatsRx' / 'PacketStatsTx' shared structural tests.
    """

    _description: str
    _cls: type[PacketStats]
    _results: dict[str, Any]

    def test__packet_stats__subclass_of_base(self) -> None:
        """
        Ensure the stats dataclass derives from the 'PacketStats' marker
        so callers can branch on the base type (e.g. isinstance checks
        in the packet handler's stats dispatch).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            issubclass(self._cls, PacketStats),
            self._results["is_subclass_of_packet_stats"],
            msg=f"Unexpected PacketStats subclass relationship for case: {self._description}",
        )

    def test__packet_stats__is_dataclass(self) -> None:
        """
        Ensure the stats class is itself a dataclass so 'fields()',
        default construction, and '__eq__' work as expected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            is_dataclass(self._cls),
            self._results["is_dataclass"],
            msg=f"Expected a dataclass for case: {self._description}",
        )

    def test__packet_stats__is_slotted(self) -> None:
        """
        Ensure the stats class uses '__slots__' so counters cannot be
        accidentally created via a typo like 'stats.ip4_typo = 1'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = self._cls()

        self.assertEqual(
            not hasattr(instance, "__dict__"),
            self._results["is_slotted"],
            msg=f"Expected slotted instances for case: {self._description}",
        )

    def test__packet_stats__defaults_to_zero_for_every_field(self) -> None:
        """
        Ensure every declared counter defaults to integer zero — the
        contract every caller of 'PacketStats*()' relies on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        instance = self._cls()

        for f in fields(self._cls):
            with self.subTest(field=f.name):
                value = getattr(instance, f.name)
                self.assertEqual(
                    value,
                    0,
                    msg=(f"{self._cls.__name__}.{f.name} must default to 0. " f"Got: {value!r}"),
                )

    def test__packet_stats__every_field_annotated_int(self) -> None:
        """
        Ensure every counter carries the 'int' type annotation — the
        declared type that 'dataclass' propagates into the default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for f in fields(self._cls):
            with self.subTest(field=f.name):
                self.assertIs(
                    f.type,
                    int,
                    msg=(f"{self._cls.__name__}.{f.name} must be annotated as 'int'. " f"Got: {f.type!r}"),
                )

    def test__packet_stats__field_names_are_unique(self) -> None:
        """
        Ensure no two fields share a name — dataclasses would silently
        shadow earlier definitions and drop a counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        names = [f.name for f in fields(self._cls)]

        self.assertEqual(
            len(set(names)),
            len(names),
            msg=f"{self._cls.__name__} must declare unique field names.",
        )

    def test__packet_stats__field_count(self) -> None:
        """
        Ensure the declared counter count matches the expected total so
        an accidental removal is caught even if the roster list is not
        updated in lockstep elsewhere.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(fields(self._cls)),
            self._results["field_count"],
            msg=(
                f"{self._cls.__name__} field count drifted. "
                f"If intentional, update the '_results[field_count]' in this test."
            ),
        )


class TestPacketStatsRxFields(TestCase):
    """
    The 'PacketStatsRx' field-roster tests.
    """

    def test__packet_stats_rx__roster_includes_every_protocol_family(self) -> None:
        """
        Ensure every RX protocol family declared in the source exposes
        at least one counter. Guards against accidental removal of a
        whole protocol's RX stats block.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        names = [f.name for f in fields(PacketStatsRx)]

        for prefix in (
            "ethernet__",
            "ethernet_802_3__",
            "arp__",
            "ip4__",
            "ip6__",
            "ip6_frag__",
            "icmp4__",
            "icmp6__",
            "udp__",
            "tcp__",
            "raw__",
        ):
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    any(n.startswith(prefix) for n in names),
                    msg=f"PacketStatsRx must expose at least one '{prefix}*' counter.",
                )


class TestPacketStatsTxFields(TestCase):
    """
    The 'PacketStatsTx' field-roster tests.
    """

    def test__packet_stats_tx__roster_includes_every_protocol_family(self) -> None:
        """
        Ensure every TX protocol family declared in the source exposes
        at least one counter. Guards against accidental removal of a
        whole protocol's TX stats block.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        names = [f.name for f in fields(PacketStatsTx)]

        for prefix in (
            "ethernet__",
            "ethernet_802_3__",
            "arp__",
            "ip4__",
            "ip6__",
            "ip6_frag__",
            "icmp4__",
            "icmp6__",
            "udp__",
            "tcp__",
        ):
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    any(n.startswith(prefix) for n in names),
                    msg=f"PacketStatsTx must expose at least one '{prefix}*' counter.",
                )

    def test__packet_stats_tx__every_tcp_flag_counter_present(self) -> None:
        """
        Ensure TX stats cover every TCP flag counter — the per-flag
        breakdown is referenced by the TX packet handler when building
        its flag-annotated log lines.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        names = {f.name for f in fields(PacketStatsTx)}
        required = {
            "tcp__flag_ns",
            "tcp__flag_cwr",
            "tcp__flag_ece",
            "tcp__flag_urg",
            "tcp__flag_ack",
            "tcp__flag_psh",
            "tcp__flag_rst",
            "tcp__flag_syn",
            "tcp__flag_fin",
        }

        self.assertTrue(
            required.issubset(names),
            msg=("PacketStatsTx must expose every per-TCP-flag counter. " f"Missing: {sorted(required - names)}"),
        )


class TestPacketStatsMutation(TestCase):
    """
    The 'PacketStatsRx' / 'PacketStatsTx' mutation-semantics tests.
    """

    def test__packet_stats_rx__counters_are_mutable(self) -> None:
        """
        Ensure RX counters are mutable in place so the packet handler
        can increment them from hot paths without rebuilding the whole
        dataclass.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsRx()
        stats.ip4__dst_unicast += 1

        self.assertEqual(
            stats.ip4__dst_unicast,
            1,
            msg="PacketStatsRx counters must support in-place increment.",
        )

    def test__packet_stats_tx__counters_are_mutable(self) -> None:
        """
        Ensure TX counters are mutable in place (mirror of the RX case).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsTx()
        stats.tcp__flag_syn += 2

        self.assertEqual(
            stats.tcp__flag_syn,
            2,
            msg="PacketStatsTx counters must support in-place increment.",
        )

    def test__packet_stats_rx__constructor_override(self) -> None:
        """
        Ensure kwargs passed to the constructor override the per-field
        default of zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsRx(ip4__dst_unicast=42, tcp__socket_match_active__forward_to_socket=7)

        self.assertEqual(
            stats.ip4__dst_unicast,
            42,
            msg="PacketStatsRx must accept a kwarg override for 'ip4__dst_unicast'.",
        )
        self.assertEqual(
            stats.tcp__socket_match_active__forward_to_socket,
            7,
            msg="PacketStatsRx must accept a kwarg override for 'tcp__socket_match_active__forward_to_socket'.",
        )

    def test__packet_stats_rx__is_not_frozen(self) -> None:
        """
        Ensure 'PacketStatsRx' is NOT frozen — if a future change tags
        it 'frozen=True' the hot-path increments used by the packet
        handler would start raising 'FrozenInstanceError'. This test
        pins the mutable contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsRx()

        try:
            stats.ip4__dst_unicast = 99
        except FrozenInstanceError as exc:  # pragma: no cover - fail path
            self.fail(f"PacketStatsRx must not be frozen. Got FrozenInstanceError: {exc!r}.")

    def test__packet_stats_rx__slots_reject_unknown_attribute(self) -> None:
        """
        Ensure 'PacketStatsRx.__slots__' rejects typos — assigning to a
        field name that does not exist must raise 'AttributeError' so a
        misspelled counter never silently vanishes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsRx()

        with self.assertRaises(AttributeError):
            stats.ip4__typo_counter = 1  # type: ignore[attr-defined]

    def test__packet_stats_tx__slots_reject_unknown_attribute(self) -> None:
        """
        Ensure 'PacketStatsTx.__slots__' rejects typos the same way.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsTx()

        with self.assertRaises(AttributeError):
            stats.tcp__typo_counter = 1  # type: ignore[attr-defined]


class TestPacketStatsEquality(TestCase):
    """
    The 'PacketStatsRx' / 'PacketStatsTx' equality tests.
    """

    def test__packet_stats_rx__two_defaults_compare_equal(self) -> None:
        """
        Ensure two freshly default-constructed 'PacketStatsRx' instances
        compare equal (generated '__eq__' over every field).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            PacketStatsRx(),
            PacketStatsRx(),
            msg="Two default PacketStatsRx instances must compare equal.",
        )

    def test__packet_stats_rx__differing_fields_compare_unequal(self) -> None:
        """
        Ensure any differing counter makes the two instances unequal.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            PacketStatsRx(),
            PacketStatsRx(ip4__dst_unicast=1),
            msg="PacketStatsRx instances with differing counters must compare unequal.",
        )

    def test__packet_stats_rx__ne_packet_stats_tx(self) -> None:
        """
        Ensure RX and TX stats compare unequal — the generated '__eq__'
        short-circuits on type mismatch so a cache that mixes them will
        never silently alias one for the other.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            PacketStatsRx(),
            PacketStatsTx(),
            msg="PacketStatsRx and PacketStatsTx must not compare equal even at defaults.",
        )


@dataclass(slots=True)
class _CustomStats(PacketStats):
    """
    A minimal third-party 'PacketStats' subclass used only to exercise
    the base-class extension path; it adds a single counter so the
    base's behaviour under inheritance is testable.
    """

    custom_counter: int = 0


class TestPacketStatsExtensibility(TestCase):
    """
    The 'PacketStats' subclassing extensibility tests.
    """

    def test__packet_stats__custom_subclass_default(self) -> None:
        """
        Ensure a user-defined 'PacketStats' subclass inherits the base
        contract: dataclass generation, slotted instances, zero default.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = _CustomStats()

        self.assertTrue(
            isinstance(stats, PacketStats),
            msg="_CustomStats must be recognised as a PacketStats.",
        )
        self.assertEqual(
            stats.custom_counter,
            0,
            msg="_CustomStats.custom_counter must default to 0 via the @dataclass default.",
        )
        self.assertFalse(
            hasattr(stats, "__dict__"),
            msg="_CustomStats must inherit the slotted-instance contract.",
        )


class TestLinkStatsCounters(TestCase):
    """
    The link-level aggregate byte counters (Phase-3 Link API).
    """

    def test__packet_stats__link_counters_default_to_zero(self) -> None:
        """
        Ensure a freshly-constructed LinkStatsCounters has both byte
        counters initialised to zero.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        counters = LinkStatsCounters()

        self.assertEqual(counters.rx_bytes, 0, msg="rx_bytes must default to 0.")
        self.assertEqual(counters.tx_bytes, 0, msg="tx_bytes must default to 0.")

    def test__packet_stats__link_counters_are_slotted(self) -> None:
        """
        Ensure LinkStatsCounters is a slotted dataclass so it grows no
        per-instance __dict__ on the PacketHandler.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            hasattr(LinkStatsCounters, "__slots__"),
            msg="LinkStatsCounters must be declared with slots=True.",
        )


class TestPacketStatsShards(TestCase):
    """
    The per-thread sharded statistics aggregator.
    """

    def test__packet_stats__shards_current_returns_seed_on_constructing_thread(self) -> None:
        """
        Ensure 'current' returns the seed shard for the thread that
        constructed the store, so a single-threaded fixture reads back
        the exact instance it injected.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        seed = PacketStatsRx()
        shards: PacketStatsShards[PacketStatsRx] = PacketStatsShards(factory=PacketStatsRx, seed=seed)

        self.assertIs(
            shards.current(),
            seed,
            msg="current() on the constructing thread must return the seed shard.",
        )

    def test__packet_stats__shards_snapshot_sums_fields(self) -> None:
        """
        Ensure 'snapshot' returns a fresh copy-by-value instance whose
        every field is the field-by-field sum across all registered
        shards (here the single seeded shard carrying one non-zero
        counter).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        seed = PacketStatsRx()
        seed.ethernet__pre_parse = 7
        shards: PacketStatsShards[PacketStatsRx] = PacketStatsShards(factory=PacketStatsRx, seed=seed)

        snapshot = shards.snapshot()

        self.assertEqual(
            snapshot.ethernet__pre_parse,
            7,
            msg="snapshot() must sum each field across shards (7 from the single seeded shard).",
        )
        self.assertIsNot(
            snapshot,
            seed,
            msg="snapshot() must return a fresh instance, not the live shard.",
        )
