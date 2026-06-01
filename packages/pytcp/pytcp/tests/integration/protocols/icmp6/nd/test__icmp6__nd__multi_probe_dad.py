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
Integration tests for the IPv6 Neighbor Discovery multi-probe
DAD path (RFC 4862 §5.1 + §5.4). The 'icmp6.dad_transmits' and
'icmp6.retrans_timer_ms' sysctls control the probe count and
inter-probe wait, mirroring Linux's
'net.ipv6.conf.<iface>.dad_transmits' / 'retrans_time_ms'.

pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__multi_probe_dad.py

ver 3.0.8
"""

import threading

from net_addr import Ip6Address
from net_proto import (
    EthernetParser,
    EtherType,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6Parser,
    Ip6Parser,
    PacketRx,
)
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.nd_testcase import NdTestCase


def _count_dad_probes_for(frames: list[bytes], *, target: Ip6Address) -> int:
    """
    Count the inbound TX frames that are DAD-form NS messages
    targeting 'target' (src=:: + Icmp6NdMessageNeighborSolicitation
    + target_address == target).
    """

    count = 0
    for frame in frames:
        prx = PacketRx(frame)
        EthernetParser(prx)
        if prx.ethernet.type is not EtherType.IP6:
            continue
        Ip6Parser(prx)
        if not prx.ip6.src.is_unspecified:
            continue
        Icmp6Parser(prx)
        msg = prx.icmp6.message
        if not isinstance(msg, Icmp6NdMessageNeighborSolicitation):
            continue
        if msg.target_address == target:
            count += 1
    return count


_CANDIDATE = Ip6Address("2001:db8:0:1::5")


class TestIcmp6Nd__MultiProbeDad__Default(NdTestCase):
    """
    With the default 'icmp6.dad_transmits = 1' the host sends a
    single DAD probe — backward-compatible with the pre-§8
    behaviour.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__dad__default_emits_one_probe(self) -> None:
        """
        Ensure 'icmp6.dad_transmits = 1' (the registered
        default) drives a single DAD probe through the
        TX ring on the no-duplicate path.

        Reference: RFC 4862 §5.1 (DupAddrDetectTransmits default = 1).
        """

        with sysctl_module.override("icmp6.default.retrans_timer_ms", 10):
            result = self._packet_handler._perform_ip6_nd_dad(
                ip6_unicast_candidate=_CANDIDATE,
            )

        self.assertTrue(
            result,
            msg="With no peer NA / NS for the candidate, DAD must succeed.",
        )
        self.assertEqual(
            _count_dad_probes_for(self._frames_tx, target=_CANDIDATE),
            1,
            msg="Default dad_transmits=1 must produce exactly one DAD probe.",
        )


class TestIcmp6Nd__MultiProbeDad__TransmitsTwo(NdTestCase):
    """
    'icmp6.dad_transmits = 2' drives two DAD probes spaced by
    'icmp6.retrans_timer_ms'.
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__dad__dad_transmits_2_emits_two_probes(self) -> None:
        """
        Ensure 'icmp6.dad_transmits = 2' produces exactly two
        DAD probes — the multi-probe form §5.1 admits.

        Reference: RFC 4862 §5.1 (DupAddrDetectTransmits configurable).
        """

        with sysctl_module.override("icmp6.default.dad_transmits", 2):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 10):
                result = self._packet_handler._perform_ip6_nd_dad(
                    ip6_unicast_candidate=_CANDIDATE,
                )

        self.assertTrue(
            result,
            msg="Without a conflict event, multi-probe DAD must succeed.",
        )
        self.assertEqual(
            _count_dad_probes_for(self._frames_tx, target=_CANDIDATE),
            2,
            msg="dad_transmits=2 must produce exactly two DAD probes.",
        )


class TestIcmp6Nd__MultiProbeDad__ConflictAbortsLoop(NdTestCase):
    """
    A conflict event released mid-loop aborts further probing —
    the host MUST NOT continue probing once a duplicate has been
    detected (RFC 4862 §5.4.5).
    """

    def tearDown(self) -> None:
        """
        Restore sysctl defaults so per-test overrides don't leak.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def test__icmp6__nd__dad__conflict_during_loop_short_circuits(self) -> None:
        """
        Ensure releasing the DAD conflict event before the
        second probe times out short-circuits the multi-probe
        loop — only the first probe goes out and the host
        treats the address as a duplicate (returns False).

        Reference: RFC 4862 §5.4.5 (DAD failure on duplicate detection).
        """

        # Set the conflict event from a background thread ~5ms
        # after the DAD call starts. Using a long retrans timer
        # (200ms) so the wait actually blocks long enough for the
        # background set to land before the first probe's wait
        # would otherwise time out.
        def _trigger_conflict() -> None:
            self._packet_handler._icmp6_nd_dad__registry.try_signal_conflict(
                _CANDIDATE,
                peer_info=None,
                inbound_nonce=None,
            )

        with sysctl_module.override("icmp6.default.dad_transmits", 3):
            with sysctl_module.override("icmp6.default.retrans_timer_ms", 200):
                threading.Timer(0.005, _trigger_conflict).start()
                result = self._packet_handler._perform_ip6_nd_dad(
                    ip6_unicast_candidate=_CANDIDATE,
                )

        self.assertFalse(
            result,
            msg="Conflict event must surface as DAD failure (return False).",
        )
        self.assertEqual(
            _count_dad_probes_for(self._frames_tx, target=_CANDIDATE),
            1,
            msg=(
                "Conflict during the first probe's wait must short-circuit "
                "the loop — only one probe must have been sent."
            ),
        )
