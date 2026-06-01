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
Integration tests for the IPv6 Router Solicitation retransmit
loop with RFC 7559 §2 truncated binary exponential backoff —
nd_linux_parity §22.

PyTCP previously sent a single RS at boot and waited a fixed
1 second for an RA. That spacing was neither RFC 4861 §6.3.7
('MAX_RTR_SOLICITATIONS = 3, RTR_SOLICITATION_INTERVAL = 4s')
nor RFC 7559 §2 (exponential backoff). The host now follows the
RFC 7559 algorithm: send up to 'icmp6.max_rtr_solicitations'
RSes with the inter-message wait doubling each round (capped
at 'icmp6.rtr_solicitation_max_rt_ms') and ±10% randomisation,
exiting early on the first RA receipt.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rs_backoff.py

ver 3.0.8
"""

from unittest.mock import patch

from net_proto import EthernetParser, EtherType, Icmp6NdMessageRouterSolicitation, Icmp6Parser, Ip6Parser, PacketRx
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase


def _count_rs_frames(frames: list[bytes]) -> int:
    """
    Count the number of inbound RS frames in 'frames'.
    """

    count = 0
    for frame in frames:
        prx = PacketRx(frame)
        EthernetParser(prx)
        if prx.ethernet.type is not EtherType.IP6:
            continue
        Ip6Parser(prx)
        Icmp6Parser(prx)
        if isinstance(prx.icmp6.message, Icmp6NdMessageRouterSolicitation):
            count += 1
    return count


class TestIcmp6Nd__RsBackoff__SendsAllRsWhenNoRa(NdTestCase):
    """
    With no RA arriving, the host emits 'max_rtr_solicitations'
    RSes total — one per loop iteration.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rs_backoff__no_ra_sends_max_rtr_solicitations(self) -> None:
        """
        Ensure absent any RA the host emits exactly
        'icmp6.max_rtr_solicitations' RS messages before
        giving up.

        Reference: RFC 4861 §6.3.7 (MAX_RTR_SOLICITATIONS upper bound).
        Reference: RFC 7559 §2 (truncated binary exponential backoff).
        """

        # Tiny intervals so the loop runs sub-millisecond.
        with sysctl_module.override("icmp6.default.rtr_solicitation_interval_ms", 1):
            with sysctl_module.override("icmp6.default.max_rtr_solicitations", 3):
                self._packet_handler._send_icmp6_nd_router_solicitations_with_backoff()

        self.assertEqual(
            _count_rs_frames(self._frames_tx),
            3,
            msg=(
                "With no RA, host must emit exactly 'max_rtr_solicitations' "
                f"(=3) RS messages. Got: {_count_rs_frames(self._frames_tx)}"
            ),
        )


class TestIcmp6Nd__RsBackoff__StopsOnRaReceipt(NdTestCase):
    """
    A successful '_icmp6_ra__event.acquire' (RA received)
    short-circuits the retransmit loop.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rs_backoff__ra_after_first_rs_stops_loop(self) -> None:
        """
        Ensure an RA delivered after the first RS short-circuits
        the loop — only one RS goes out.

        Reference: RFC 7559 §2 (host stops retransmitting on RA receipt).
        """

        # Mock acquire to return True on the first call (RA arrived
        # right after the first RS) and False thereafter.
        original_acquire = self._packet_handler._icmp6_ra__event.acquire
        call_count = [0]

        def mock_acquire(timeout: float | None = None) -> bool:
            call_count[0] += 1
            if call_count[0] == 1:
                return True  # RA received on first wait.
            return original_acquire(timeout=0)  # Should never be hit.

        with patch.object(
            self._packet_handler._icmp6_ra__event,
            "acquire",
            side_effect=mock_acquire,
        ):
            with sysctl_module.override("icmp6.default.rtr_solicitation_interval_ms", 1):
                with sysctl_module.override("icmp6.default.max_rtr_solicitations", 3):
                    self._packet_handler._send_icmp6_nd_router_solicitations_with_backoff()

        self.assertEqual(
            _count_rs_frames(self._frames_tx),
            1,
            msg=("First-RS-then-RA path must emit exactly one RS. " f"Got: {_count_rs_frames(self._frames_tx)}"),
        )


class TestIcmp6Nd__RsBackoff__ExponentialBackoffTimings(NdTestCase):
    """
    The wait between successive RS retransmits doubles each
    round, capped at 'icmp6.rtr_solicitation_max_rt_ms', with
    ±10% randomisation.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rs_backoff__timeouts_double_each_round(self) -> None:
        """
        Ensure the timeout passed to '_icmp6_ra__event.acquire'
        doubles between retransmissions — IRT, 2*IRT, 4*IRT —
        with the random-factor mocked to zero so the bare
        algorithm is observable.

        Reference: RFC 7559 §2 (RT[k+1] = 2*RT[k] + RAND*RT[k], capped at MRT).
        """

        observed_timeouts: list[float] = []

        def mock_acquire(timeout: float | None = None) -> bool:
            assert timeout is not None
            observed_timeouts.append(timeout)
            return False

        with (
            patch.object(self._packet_handler._icmp6_ra__event, "acquire", side_effect=mock_acquire),
            patch("pytcp.runtime.packet_handler.random.uniform", return_value=0.0),
            sysctl_module.override("icmp6.default.rtr_solicitation_interval_ms", 1000),
            sysctl_module.override("icmp6.default.rtr_solicitation_max_rt_ms", 8000),
            sysctl_module.override("icmp6.default.max_rtr_solicitations", 4),
        ):
            self._packet_handler._send_icmp6_nd_router_solicitations_with_backoff()

        # 4 RSes → 4 acquire calls with timeouts: 1.0, 2.0, 4.0, 8.0
        # (the last one is capped at MRT=8s; without the cap it would
        # be 8.0 anyway, but the cap also catches the next-round
        # equality).
        self.assertEqual(
            observed_timeouts,
            [1.0, 2.0, 4.0, 8.0],
            msg=f"Backoff timeouts must double each round, capped at MRT. Got: {observed_timeouts!r}",
        )

    def test__icmp6__nd__rs_backoff__timeouts_capped_at_mrt(self) -> None:
        """
        Ensure once the doubling exceeds 'rtr_solicitation_max_rt_ms'
        the timeout stays at MRT instead of continuing to double.

        Reference: RFC 7559 §2 (MRT cap).
        """

        observed_timeouts: list[float] = []

        def mock_acquire(timeout: float | None = None) -> bool:
            assert timeout is not None
            observed_timeouts.append(timeout)
            return False

        with (
            patch.object(self._packet_handler._icmp6_ra__event, "acquire", side_effect=mock_acquire),
            patch("pytcp.runtime.packet_handler.random.uniform", return_value=0.0),
            sysctl_module.override("icmp6.default.rtr_solicitation_interval_ms", 1000),
            sysctl_module.override("icmp6.default.rtr_solicitation_max_rt_ms", 3000),
            sysctl_module.override("icmp6.default.max_rtr_solicitations", 5),
        ):
            self._packet_handler._send_icmp6_nd_router_solicitations_with_backoff()

        # 5 RSes → 5 acquire calls. IRT=1, then 2 (uncapped), then
        # 3 (clamped from 4 → MRT), then 3 (already at MRT), then 3.
        self.assertEqual(
            observed_timeouts,
            [1.0, 2.0, 3.0, 3.0, 3.0],
            msg=f"Timeouts must be capped at MRT once doubling exceeds it. Got: {observed_timeouts!r}",
        )


class TestIcmp6Nd__RsBackoff__SysctlKillSwitch(NdTestCase):
    """
    'icmp6.max_rtr_solicitations = 0' disables the RS retransmit
    loop entirely (kill switch).
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__rs_backoff__zero_max_attempts_sends_no_rs(self) -> None:
        """
        Ensure 'icmp6.max_rtr_solicitations = 0' suppresses RS
        emission entirely.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with sysctl_module.override("icmp6.default.max_rtr_solicitations", 0):
            self._packet_handler._send_icmp6_nd_router_solicitations_with_backoff()

        self.assertEqual(
            _count_rs_frames(self._frames_tx),
            0,
            msg=("max_rtr_solicitations=0 must suppress RS emission. " f"Got: {_count_rs_frames(self._frames_tx)}"),
        )
