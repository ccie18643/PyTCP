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
Integration tests for the IPv6 ND DAD slot-registry wiring
on the packet handler — nd_linux_parity §20.1 lock-discipline
addendum.

The full slot-registry contract (install / teardown /
register_nonce / has_signal / peer_info / try_signal_conflict
+ concurrency) is unit-tested in
'pytcp/tests/unit/lib/test__lib__dad_slot_registry.py'.
These integration tests pin only the handler-level wiring:

- The handler exposes '_icmp6_nd_dad__registry' as a
  'DadSlotRegistry[Ip6Address]'.
- Stress concurrency at handler scope (worker install /
  tear-down racing against an RX-thread signal loop) does
  not raise.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__dad_slot_lock.py

ver 3.0.9
"""

import threading

from net_addr import Ip6Address, MacAddress
from pytcp.lib.dad_slot_registry import DadSlotRegistry
from pytcp.tests.lib.nd_testcase import NdTestCase

_CANDIDATE = Ip6Address("2001:db8:0:1::5")
_PEER_TLLA = MacAddress("02:00:00:00:00:91")


class TestIcmp6Nd__DadSlotLock__HandlerWiring(NdTestCase):
    """
    The packet handler exposes the DAD slot registry as a
    'DadSlotRegistry[Ip6Address]' attribute.
    """

    def test__icmp6__nd__dad_slot_registry__attribute_exists(self) -> None:
        """
        Ensure '_icmp6_nd_dad__registry' is a
        'DadSlotRegistry' instance the RX path and the worker
        can both consume.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            self._packet_handler._icmp6_nd_dad__registry,
            DadSlotRegistry,
            msg="Handler must expose '_icmp6_nd_dad__registry' as a DadSlotRegistry.",
        )


class TestIcmp6Nd__DadSlotLock__Concurrency(NdTestCase):
    """
    Concurrent worker install / tear-down racing against an
    RX-thread signal loop on the handler's registry must not
    raise — the registry's internal lock makes the check +
    signal atomic.
    """

    def test__icmp6__nd__dad_slot_registry__install_teardown_vs_rx_signal__no_exception(
        self,
    ) -> None:
        """
        Ensure 500 iterations of worker install / tear-down
        on the handler's registry racing against an RX-thread
        'try_signal_conflict' loop produce no exception. The
        handler-scope stress mirrors the unit-level
        concurrency test but exercises the live registry
        instance the RX mixin actually consumes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        iterations = 500
        errors: list[BaseException] = []
        stop = threading.Event()
        registry = self._packet_handler._icmp6_nd_dad__registry

        def _worker_loop() -> None:
            try:
                for _ in range(iterations):
                    registry.install(_CANDIDATE)
                    registry.teardown(_CANDIDATE)
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)
            finally:
                stop.set()

        def _rx_loop() -> None:
            try:
                while not stop.is_set():
                    registry.try_signal_conflict(
                        _CANDIDATE,
                        peer_info=_PEER_TLLA,
                        inbound_nonce=None,
                    )
            except BaseException as exc:  # pylint: disable=broad-except
                errors.append(exc)

        t_worker = threading.Thread(target=_worker_loop, name="dad-handler-worker")
        t_rx = threading.Thread(target=_rx_loop, name="dad-handler-rx")
        t_worker.start()
        t_rx.start()
        t_worker.join(timeout=10.0)
        t_rx.join(timeout=10.0)

        self.assertEqual(
            errors,
            [],
            msg=f"Concurrent install / tear-down vs RX signal must not raise. Got: {errors!r}",
        )
