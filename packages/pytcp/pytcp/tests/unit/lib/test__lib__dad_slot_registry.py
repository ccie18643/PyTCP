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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Unit tests for the generic 'DadSlotRegistry[A]' helper —
the shared per-candidate Duplicate Address Detection slot
bookkeeping consumed by IPv4 ARP DAD (RFC 5227) and IPv6 ND
DAD (RFC 4862).

The tests pin the registry's public API contract — slot
install / teardown, nonce registration, conflict signal
result (NOT_DAD / LOOP_HAIRPIN / SIGNALED), the per-slot
Event the worker waits on, and the lock-discipline
guarantee that concurrent worker install + RX signal does
not raise.

pytcp/tests/unit/lib/test__lib__dad_slot_registry.py

ver 3.0.8
"""

import threading
from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip6Address, MacAddress
from pytcp.lib.dad_slot_registry import DadSignalResult, DadSlotRegistry

_IP6_A = Ip6Address("2001:db8:0:1::5")
_IP6_B = Ip6Address("2001:db8:0:1::6")
_IP4_A = Ip4Address("10.0.0.5")
_PEER_MAC = MacAddress("02:00:00:00:00:91")


class TestDadSlotRegistry__InitialState(TestCase):
    """
    A freshly-constructed registry exposes empty state to
    every read accessor.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh registry per test.
        """

        self._registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()

    def test__dad_slot_registry__has_signal_returns_false_on_missing_slot(self) -> None:
        """
        Ensure 'has_signal' returns False for a candidate with
        no slot rather than raising — the boot / worker poll
        loop calls this on every iteration and MUST cope with
        torn-down slots gracefully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._registry.has_signal(_IP6_A),
            msg="has_signal must return False for an unknown candidate.",
        )

    def test__dad_slot_registry__peer_info_returns_none_on_missing_slot(self) -> None:
        """
        Ensure 'peer_info' returns None for a candidate with
        no slot rather than raising — the worker reads this
        after wait returns and MUST cope with absent slots
        gracefully.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            self._registry.peer_info(_IP6_A),
            msg="peer_info must return None for an unknown candidate.",
        )

    def test__dad_slot_registry__try_signal_conflict_returns_not_dad_on_missing_slot(
        self,
    ) -> None:
        """
        Ensure 'try_signal_conflict' returns NOT_DAD for a
        candidate with no slot so the RX caller falls through
        to its non-DAD processing path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        result = self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=_PEER_MAC,
            inbound_nonce=None,
        )
        self.assertIs(
            result,
            DadSignalResult.NOT_DAD,
            msg="Unknown candidate must yield NOT_DAD.",
        )

    def test__dad_slot_registry__teardown_is_noop_on_missing_slot(self) -> None:
        """
        Ensure 'teardown' does not raise when the slot is
        already absent so the worker tear-down path can call
        it defensively after wait returns.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._registry.teardown(_IP6_A)
        self.assertFalse(
            self._registry.has_signal(_IP6_A),
            msg="teardown of an absent slot must leave state empty.",
        )

    def test__dad_slot_registry__register_nonce_is_noop_on_missing_slot(self) -> None:
        """
        Ensure 'register_nonce' does not raise when the slot
        is already absent so a late worker call after an
        early tear-down does not crash.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._registry.register_nonce(_IP6_A, b"\x01\x02\x03\x04\x05\x06")
        # No exception, and the registry still treats the
        # candidate as unknown.
        result = self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=None,
            inbound_nonce=b"\x01\x02\x03\x04\x05\x06",
        )
        self.assertIs(
            result,
            DadSignalResult.NOT_DAD,
            msg="register_nonce on an absent slot must not install one implicitly.",
        )


class TestDadSlotRegistry__InstallTeardown(TestCase):
    """
    Slot install creates a slot and returns a usable Event;
    teardown removes the slot.
    """

    @override
    def setUp(self) -> None:
        """
        Build a fresh registry per test.
        """

        self._registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()

    def test__dad_slot_registry__install_returns_event(self) -> None:
        """
        Ensure 'install' returns a 'threading.Event' the
        worker can poll / wait on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        event = self._registry.install(_IP6_A)
        self.assertIsInstance(
            event,
            threading.Event,
            msg="install must return a threading.Event handle.",
        )
        self.assertFalse(
            event.is_set(),
            msg="Returned Event must start unset.",
        )

    def test__dad_slot_registry__install_makes_slot_visible(self) -> None:
        """
        Ensure 'has_signal' returns False (slot exists but
        not yet signalled) and 'peer_info' returns None
        immediately after install.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._registry.install(_IP6_A)
        self.assertFalse(
            self._registry.has_signal(_IP6_A),
            msg="Newly-installed slot must not be in signalled state.",
        )
        self.assertIsNone(
            self._registry.peer_info(_IP6_A),
            msg="Newly-installed slot must have no captured peer info.",
        )

    def test__dad_slot_registry__install_is_idempotent_resets_state(self) -> None:
        """
        Ensure a second 'install' for the same candidate
        overwrites the slot — re-claims start clean.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first_event = self._registry.install(_IP6_A)
        first_event.set()
        # Capture peer info on the first slot to confirm it
        # is wiped by the second install.
        self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=_PEER_MAC,
            inbound_nonce=None,
        )

        second_event = self._registry.install(_IP6_A)
        self.assertIsNot(
            second_event,
            first_event,
            msg="Re-install must hand out a fresh Event.",
        )
        self.assertFalse(
            second_event.is_set(),
            msg="Fresh Event must start unset even after prior slot was signalled.",
        )
        self.assertIsNone(
            self._registry.peer_info(_IP6_A),
            msg="Re-install must clear captured peer info.",
        )

    def test__dad_slot_registry__teardown_removes_slot(self) -> None:
        """
        Ensure 'teardown' after 'install' clears the slot —
        subsequent 'try_signal_conflict' returns NOT_DAD.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._registry.install(_IP6_A)
        self._registry.teardown(_IP6_A)
        result = self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=None,
            inbound_nonce=None,
        )
        self.assertIs(
            result,
            DadSignalResult.NOT_DAD,
            msg="Slot must be gone after teardown.",
        )


class TestDadSlotRegistry__TrySignalConflict(TestCase):
    """
    'try_signal_conflict' is the atomic RX-path entry point;
    its three outcomes (NOT_DAD / LOOP_HAIRPIN / SIGNALED)
    define the registry's main behavioural contract.
    """

    @override
    def setUp(self) -> None:
        """
        Build a registry with a pre-installed slot for
        '_IP6_A' so each test exercises a different outcome.
        """

        self._registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()
        self._event = self._registry.install(_IP6_A)

    def test__dad_slot_registry__loop_hairpin_when_nonce_matches(self) -> None:
        """
        Ensure 'try_signal_conflict' returns LOOP_HAIRPIN
        when 'inbound_nonce' is in the slot's registered
        nonce set so the inbound is dropped silently. The
        slot Event must remain unset and no peer info must
        be captured.

        Reference: RFC 7527 §4.2 (Enhanced DAD loop-hairpin).
        """

        nonce = b"\x01\x02\x03\x04\x05\x06"
        self._registry.register_nonce(_IP6_A, nonce)

        result = self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=_PEER_MAC,
            inbound_nonce=nonce,
        )

        self.assertIs(
            result,
            DadSignalResult.LOOP_HAIRPIN,
            msg="Nonce match must return LOOP_HAIRPIN.",
        )
        self.assertFalse(
            self._event.is_set(),
            msg="Loop-hairpin must NOT signal the slot Event.",
        )
        self.assertIsNone(
            self._registry.peer_info(_IP6_A),
            msg="Loop-hairpin must NOT capture peer info.",
        )

    def test__dad_slot_registry__signaled_when_nonce_unknown(self) -> None:
        """
        Ensure 'try_signal_conflict' returns SIGNALED, sets
        the slot Event, and captures 'peer_info' when the
        inbound nonce is not in the slot's registered set —
        genuine peer conflict.

        Reference: RFC 4862 §5.4.3 case (b) (peer conflict).
        """

        result = self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=_PEER_MAC,
            inbound_nonce=b"\xff\xff\xff\xff\xff\xff",
        )

        self.assertIs(
            result,
            DadSignalResult.SIGNALED,
            msg="Unknown nonce must yield SIGNALED.",
        )
        self.assertTrue(
            self._event.is_set(),
            msg="SIGNALED outcome must set the slot Event.",
        )
        self.assertEqual(
            self._registry.peer_info(_IP6_A),
            _PEER_MAC,
            msg="SIGNALED outcome must capture the peer MAC.",
        )

    def test__dad_slot_registry__signaled_when_no_inbound_nonce(self) -> None:
        """
        Ensure 'try_signal_conflict' returns SIGNALED when
        'inbound_nonce' is None — both the ARP path (no
        Nonce option in RFC 5227 wire format) and the IPv6
        NA path (no Nonce option in NA wire format) supply
        None.

        Reference: RFC 4861 §4.4 (NA carries no Nonce option).
        """

        result = self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=None,
            inbound_nonce=None,
        )

        self.assertIs(
            result,
            DadSignalResult.SIGNALED,
            msg="No-nonce inbound must yield SIGNALED.",
        )
        self.assertTrue(
            self._event.is_set(),
            msg="SIGNALED outcome must set the slot Event.",
        )

    def test__dad_slot_registry__signaled_does_not_signal_unrelated_slot(self) -> None:
        """
        Ensure signalling slot '_IP6_A' does not affect a
        separately-installed slot for '_IP6_B' — the
        per-candidate isolation is the whole point of the
        slot dict.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        event_b = self._registry.install(_IP6_B)

        self._registry.try_signal_conflict(
            _IP6_A,
            peer_info=None,
            inbound_nonce=None,
        )

        self.assertTrue(
            self._event.is_set(),
            msg="Slot A's Event must be set.",
        )
        self.assertFalse(
            event_b.is_set(),
            msg="Slot B's Event must NOT be affected by signal on slot A.",
        )


class TestDadSlotRegistry__IPv4Generic(TestCase):
    """
    The registry is generic over the address type; an
    'Ip4Address' candidate works the same way as an
    'Ip6Address' one (ARP DAD's consumer surface).
    """

    def test__dad_slot_registry__ipv4_candidate_round_trip(self) -> None:
        """
        Ensure a 'DadSlotRegistry[Ip4Address]' supports the
        full install / signal / has_signal round-trip — the
        IPv4 ARP DAD path consumes this generic instantiation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        registry: DadSlotRegistry[Ip4Address] = DadSlotRegistry()
        registry.install(_IP4_A)

        self.assertFalse(
            registry.has_signal(_IP4_A),
            msg="Newly-installed IPv4 slot must not be signalled.",
        )

        result = registry.try_signal_conflict(
            _IP4_A,
            peer_info=None,
            inbound_nonce=None,
        )

        self.assertIs(
            result,
            DadSignalResult.SIGNALED,
            msg="IPv4 candidate must signal conflict the same way IPv6 does.",
        )
        self.assertTrue(
            registry.has_signal(_IP4_A),
            msg="has_signal must return True after a SIGNALED outcome.",
        )


class TestDadSlotRegistry__Concurrency(TestCase):
    """
    Concurrent worker install + tear-down + RX-thread
    'try_signal_conflict' calls must not raise — the
    internal lock makes every public operation atomic.
    """

    def test__dad_slot_registry__install_teardown_vs_rx_signal__no_exception(
        self,
    ) -> None:
        """
        Ensure 500 iterations of worker install / tear-down
        racing against an RX-thread signal loop produce no
        exception. Without the lock, the RX path could see
        the slot present during the membership check and
        absent during the Event.set() call, raising
        KeyError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()
        iterations = 500
        errors: list[BaseException] = []
        stop = threading.Event()

        def _worker_loop() -> None:
            try:
                for _ in range(iterations):
                    registry.install(_IP6_A)
                    registry.teardown(_IP6_A)
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)
            finally:
                stop.set()

        def _rx_loop() -> None:
            try:
                while not stop.is_set():
                    registry.try_signal_conflict(
                        _IP6_A,
                        peer_info=_PEER_MAC,
                        inbound_nonce=None,
                    )
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)

        t_worker = threading.Thread(target=_worker_loop, name="dad-registry-worker")
        t_rx = threading.Thread(target=_rx_loop, name="dad-registry-rx")
        t_worker.start()
        t_rx.start()
        t_worker.join(timeout=10.0)
        t_rx.join(timeout=10.0)

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent install / tear-down vs RX signal must not raise. Got: {errors!r}",
        )

    def test__dad_slot_registry__nonce_register_vs_rx_signal__no_exception(self) -> None:
        """
        Ensure 500 iterations of worker 'register_nonce'
        calls racing against an RX-thread
        'try_signal_conflict' with the same probe nonce
        produce no exception — the registry serialises set
        mutation against the nonce-membership check.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()
        registry.install(_IP6_A)
        iterations = 500
        errors: list[BaseException] = []
        stop = threading.Event()

        def _worker_loop() -> None:
            try:
                for i in range(iterations):
                    registry.register_nonce(_IP6_A, i.to_bytes(6, "big"))
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)
            finally:
                stop.set()

        def _rx_loop() -> None:
            try:
                probe = b"\xfe\xfe\xfe\xfe\xfe\xfe"
                while not stop.is_set():
                    registry.try_signal_conflict(
                        _IP6_A,
                        peer_info=_PEER_MAC,
                        inbound_nonce=probe,
                    )
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)

        t_worker = threading.Thread(target=_worker_loop, name="dad-registry-nonce")
        t_rx = threading.Thread(target=_rx_loop, name="dad-registry-rx-nonce")
        t_worker.start()
        t_rx.start()
        t_worker.join(timeout=10.0)
        t_rx.join(timeout=10.0)

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent nonce-register vs RX nonce-check must not raise. Got: {errors!r}",
        )
