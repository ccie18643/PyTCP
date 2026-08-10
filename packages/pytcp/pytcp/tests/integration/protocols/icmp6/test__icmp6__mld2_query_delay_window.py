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
Integration tests for the RFC 3810 §5.1.10 MLDv2 Maximum
Response Code random-delay window. An inbound Query
schedules the Report 'delay' ms in the future via
'stack.timer' rather than emitting synchronously, and
multiple Queries coalesce per §5.1.10 — the earliest
scheduled Report wins.

pytcp/tests/integration/protocols/icmp6/test__icmp6__mld2_query_delay_window.py

ver 3.0.10
"""

from typing import override

from net_addr import MacAddress
from net_proto.lib.inet_cksum import inet_cksum
from pytcp.runtime.packet_handler.packet_handler__icmp6__rx import (
    _mld2_mrc_to_mrd_ms,
)
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


def _build_mldv2_general_query_frame(*, mrc: int) -> bytes:
    """
    Hand-construct an MLDv2 General Query frame
    (Ethernet/IPv6/ICMPv6 type 130) with the supplied
    Maximum Response Code on the wire.

    - src=fe80::1 (router link-local)
    - dst=ff02::1 (all-nodes)
    - hop=1
    - MLDv2 Query: MRC=mrc, multicast_address=::,
      QRV=2, QQIC=125, N=0.
    """

    mldv2_query_body = (
        mrc.to_bytes(2, "big")  # MRC
        + b"\x00\x00"  # Reserved
        + b"\x00" * 16  # Multicast Address = :: (General)
        + b"\x02"  # Resv|S|QRV = 0/0/0b010
        + b"\x7d"  # QQIC = 125
        + b"\x00\x00"  # Number of Sources = 0
    )

    icmp6_header_no_cksum = (
        b"\x82"  # Type = 130 (MULTICAST_LISTENER_QUERY)
        b"\x00"  # Code = 0
        b"\x00\x00"  # Checksum (zero for cksum compute)
    )
    icmp6_packet = icmp6_header_no_cksum + mldv2_query_body  # 28 bytes

    ip6_src = bytes.fromhex("fe800000000000000000000000000001")
    ip6_dst = bytes.fromhex("ff020000000000000000000000000001")
    icmp6_len = len(icmp6_packet)
    pseudo_header = ip6_src + ip6_dst + icmp6_len.to_bytes(4, "big") + b"\x00\x00\x00" + b"\x3a"

    cksum = inet_cksum(pseudo_header + icmp6_packet)
    icmp6_packet_with_cksum = icmp6_packet[:2] + cksum.to_bytes(2, "big") + icmp6_packet[4:]

    ip6_header = b"\x60\x00\x00\x00" + icmp6_len.to_bytes(2, "big") + b"\x3a" + b"\x01" + ip6_src + ip6_dst

    ethernet_header = b"\x33\x33\x00\x00\x00\x01" b"\x02\x00\x00\x00\x00\x91" b"\x86\xdd"

    return ethernet_header + ip6_header + icmp6_packet_with_cksum


class TestIcmp6Mld2MrcEncodingDecode(IcmpTestCase):
    """
    Unit-style coverage of the RFC 3810 §5.1.3 MRC →
    Max-Response-Delay decoder.
    """

    def test__icmp6__mld2_mrc__linear_for_small_values(self) -> None:
        """
        Ensure MRC < 32768 maps linearly to milliseconds.

        Reference: RFC 3810 §5.1.3 (linear MRC representation).
        """

        for mrc in (0, 1, 100, 10000, 32767):
            self.assertEqual(
                _mld2_mrc_to_mrd_ms(mrc),
                mrc,
                msg=f"MRC {mrc} must map linearly to {mrc} ms.",
            )

    def test__icmp6__mld2_mrc__floating_point_decoding(self) -> None:
        """
        Ensure MRC >= 32768 decodes via the floating-point
        representation MRD = (mant | 0x1000) << (exp + 3).

        Reference: RFC 3810 §5.1.3 (floating-point MRC).
        """

        # exp=0, mant=0 → (0x1000) << 3 = 0x8000 = 32768.
        self.assertEqual(
            _mld2_mrc_to_mrd_ms(0x8000),
            0x8000 << 0,  # = 32768
            msg="MRC 0x8000 (exp=0, mant=0) must decode to 32768 ms.",
        )
        # exp=0, mant=0xfff → (0x1fff) << 3 = 0xfff8.
        self.assertEqual(
            _mld2_mrc_to_mrd_ms(0x8FFF),
            0x1FFF << 3,
            msg="MRC 0x8fff (exp=0, mant=0xfff) must decode per §5.1.3.",
        )
        # exp=7, mant=0xfff → (0x1fff) << 10.
        self.assertEqual(
            _mld2_mrc_to_mrd_ms(0xFFFF),
            0x1FFF << 10,
            msg="MRC 0xffff (exp=7, mant=0xfff) must decode per §5.1.3.",
        )


class TestIcmp6Mld2QueryDelayWindow(IcmpTestCase):
    """
    Verify the §5.1.10 random-delay scheduling: the Report
    fires after the chosen delay rather than on Query
    receipt.
    """

    @override
    def setUp(self) -> None:
        super().setUp()
        self._packet_handler._mac_multicast.append(MacAddress("33:33:00:00:00:01"))

    def _patch_delay_picker(self, *, returns_ms: int) -> None:
        """Force the delay picker to return a deterministic value."""

        self._packet_handler._icmp6_rx._mld2_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda mrd_ms: returns_ms
        )

    def test__icmp6__mld2_query__report_deferred_by_picked_delay(self) -> None:
        """
        Ensure an inbound Query with non-zero MRC schedules
        the Report rather than emitting it synchronously; the
        Report fires after the picked delay elapses.

        Reference: RFC 3810 §5.1.10 (random-delay window on
        Query receipt).
        """

        self._patch_delay_picker(returns_ms=500)

        tx_frames = self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        self.assertEqual(
            len(tx_frames),
            0,
            msg=(
                "Inbound Query must NOT trigger a synchronous Report when "
                f"the picked delay is 500 ms; got {len(tx_frames)} TX frames."
            ),
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__scheduled,
            1,
            msg="Query receipt must bump 'icmp6__mld2_query__scheduled' exactly once.",
        )

        # Advance to just before the scheduled fire time — no Report yet.
        tx_499 = self._advance(ms=499)
        self.assertEqual(
            len(tx_499),
            0,
            msg=f"Report must not fire at t=499; got {len(tx_499)} TX frames.",
        )

        # One more ms crosses the threshold and fires the Report.
        tx_500 = self._advance(ms=1)
        self.assertEqual(
            len(tx_500),
            1,
            msg=f"Report must fire at t=500; got {len(tx_500)} TX frames.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__respond,
            1,
            msg="'icmp6__mld2_query__respond' must bump when the deferred Report fires.",
        )

    def test__icmp6__mld2_query__delay_zero_emits_immediately(self) -> None:
        """
        Ensure a Query whose picked delay is 0 ms emits the
        Report synchronously (the immediate-send fast path).

        Reference: RFC 3810 §5.1.10 (uniformly random in
        [0, MRD]; the 0 endpoint is valid and yields prompt
        response).
        """

        self._patch_delay_picker(returns_ms=0)

        tx_frames = self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        self.assertEqual(
            len(tx_frames),
            1,
            msg=f"Delay=0 must emit Report immediately; got {len(tx_frames)} TX frames.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__scheduled,
            0,
            msg="Delay=0 must NOT bump 'icmp6__mld2_query__scheduled' (no timer registered).",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__respond,
            1,
            msg="'icmp6__mld2_query__respond' must bump on immediate emission.",
        )

    def test__icmp6__mld2_query__later_query_does_not_supersede(self) -> None:
        """
        Ensure a second Query whose computed response time is
        LATER than the existing pending Report is absorbed
        per §5.1.10 coalescing — the original timer fires on
        schedule and the superseded counter stays at zero.

        Reference: RFC 3810 §5.1.10 (use the earliest
        pending response time).
        """

        # First Query — 200 ms delay scheduled.
        self._patch_delay_picker(returns_ms=200)
        self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        # Advance 50 ms (now=50, pending fires at 200).
        self._advance(ms=50)

        # Second Query — 200 ms delay → fires at now+200 = 250,
        # later than 200. Coalesce.
        self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__scheduled,
            1,
            msg="Second (later) Query must NOT reschedule; only the first counts.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__superseded,
            0,
            msg="Second (later) Query must NOT mark the first as superseded.",
        )

        # Advance to t=200 — original schedule. Report fires.
        tx = self._advance(ms=150)
        self.assertEqual(
            len(tx),
            1,
            msg=f"Original Report must fire on its original schedule; got {len(tx)} TX frames.",
        )

    def test__icmp6__mld2_query__earlier_query_supersedes_pending(self) -> None:
        """
        Ensure a second Query whose computed response time is
        EARLIER than the existing pending Report cancels the
        old timer and registers a new one — the
        'icmp6__mld2_query__superseded' counter bumps and
        the Report fires at the new earlier deadline.

        Reference: RFC 3810 §5.1.10 (Listener uses the
        earliest scheduled response).
        """

        # First Query — schedule for 1000 ms.
        self._patch_delay_picker(returns_ms=1000)
        self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        # Second Query — schedule for 200 ms (earlier than 1000).
        self._patch_delay_picker(returns_ms=200)
        self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__superseded,
            1,
            msg=(
                "Second (earlier) Query must cancel the first pending Report; "
                "'icmp6__mld2_query__superseded' must bump exactly once."
            ),
        )
        self.assertEqual(
            self._packet_handler._packet_stats_rx.icmp6__mld2_query__scheduled,
            2,
            msg="Both Queries must have bumped 'scheduled' (first install + reschedule).",
        )

        # Advance 200 ms — new earlier schedule fires.
        tx_200 = self._advance(ms=200)
        self.assertEqual(
            len(tx_200),
            1,
            msg=f"Earlier-supersede Report must fire at t=200; got {len(tx_200)} TX frames.",
        )

        # Advance past the original deadline (now=1100) — no
        # second Report fires (the old timer was cancelled).
        tx_late = self._advance(ms=900)
        self.assertEqual(
            len(tx_late),
            0,
            msg="Cancelled timer must NOT fire after its original deadline.",
        )

    def test__icmp6__mld2_query__pending_state_clears_after_send(self) -> None:
        """
        Ensure the per-handler pending-response state returns
        to None after the timer fires the deferred Report —
        so subsequent Queries start a fresh scheduling cycle.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._patch_delay_picker(returns_ms=100)
        self._drive_rx(frame=_build_mldv2_general_query_frame(mrc=10000))

        self.assertIsNotNone(
            self._packet_handler._mld2_query__pending_response_at_ms,
            msg="Pending state must be set immediately after Query schedules a Report.",
        )

        self._advance(ms=100)

        self.assertIsNone(
            self._packet_handler._mld2_query__pending_response_at_ms,
            msg="Pending state must clear to None after the deferred Report fires.",
        )
