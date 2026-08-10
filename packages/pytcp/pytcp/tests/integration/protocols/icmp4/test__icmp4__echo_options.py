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
Integration tests for the IPv4 Echo Reply options-echo path. Drives
an ICMPv4 Echo Request carrying IPv4 options through the production
RX/TX path and asserts the Echo Reply echoes the inbound options
with LSRR/SSRR reversed (RFC 1122 §3.2.2.6).

pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_options.py

ver 3.0.10
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import (
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4MessageEchoRequest,
    Ip4Assembler,
    Ip4OptionEol,
    Ip4OptionLsrr,
    Ip4OptionNop,
    Ip4OptionRouterAlert,
    Ip4OptionRr,
    Ip4Options,
    Ip4OptionSsrr,
    Ip4OptionTimestamp,
    Ip4OptionTimestampFlag,
    Ip4Parser,
    Ip4TimestampEntry,
    PacketRx,
)
from pytcp import stack
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


def _build_echo_request(*, options: Ip4Options) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Echo Request frame from
    HOST_A → STACK carrying the supplied IPv4 options.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=MacAddress("02:00:00:00:00:91"),
            ethernet__dst=MacAddress("02:00:00:00:00:07"),
            ethernet__payload=Ip4Assembler(
                ip4__src=Ip4Address("10.0.1.91"),
                ip4__dst=Ip4Address("10.0.1.7"),
                ip4__options=options,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoRequest(
                        id=0x1234,
                        seq=0x0001,
                        data=b"hello",
                    ),
                ),
            ),
        )
    )


class TestIcmp4EchoOptions(IcmpTestCase):
    """
    The IPv4 Echo Reply options-echo behaviour tests.
    """

    @override
    def setUp(self) -> None:
        """
        Opt into 'ip4.default.accept_source_route' so the inbound
        LSRR/SSRR gate does not drop the test frames before they
        reach the Echo Reply path. The default-False gate is
        exercised separately in
        'test__packet_handler__ip4__rx__source_route'. The original
        value is restored in tearDown.
        """

        super().setUp()
        self._asr_prior = stack.IP4__ACCEPT_SOURCE_ROUTE["default"]
        stack.IP4__ACCEPT_SOURCE_ROUTE["default"] = True

    @override
    def tearDown(self) -> None:
        """
        Restore the prior 'ip4.default.accept_source_route' so the
        opt-in in setUp does not leak across tests.
        """

        stack.IP4__ACCEPT_SOURCE_ROUTE["default"] = self._asr_prior
        super().tearDown()

    def _parse_reply_lsrr(self, reply_frame: bytes) -> Ip4OptionLsrr | None:
        """
        Re-parse the outbound Echo Reply frame and return its LSRR
        option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.lsrr

    def _parse_reply_ssrr(self, reply_frame: bytes) -> Ip4OptionSsrr | None:
        """
        Re-parse the outbound Echo Reply frame and return its SSRR
        option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.ssrr

    def _parse_reply_rr(self, reply_frame: bytes) -> Ip4OptionRr | None:
        """
        Re-parse the outbound Echo Reply frame and return its Record
        Route option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.rr

    def _parse_reply_timestamp(self, reply_frame: bytes) -> Ip4OptionTimestamp | None:
        """
        Re-parse the outbound Echo Reply frame and return its Timestamp
        option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.timestamp

    def _parse_reply_router_alert(self, reply_frame: bytes) -> Ip4OptionRouterAlert | None:
        """
        Re-parse the outbound Echo Reply frame and return its Router
        Alert option (or None).
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return packet_rx.ip4.router_alert

    def _parse_reply_options_count(self, reply_frame: bytes) -> int:
        """
        Re-parse the outbound Echo Reply frame and return the number
        of IPv4 options.
        """

        packet_rx = PacketRx(reply_frame[14:])  # strip Ethernet header
        Ip4Parser(packet_rx)
        return len(list(packet_rx.ip4.options))

    def test__icmp4__echo_options__lsrr__route_reversed_pointer_reset(self) -> None:
        """
        Ensure an inbound Echo Request carrying an LSRR option
        (route=[A, B], pointer fully consumed) produces an Echo Reply
        whose LSRR option carries the reversed route ([B, A]) with the
        pointer reset to 4 (start). This is the canonical source-route
        reversal mandate.

        Reference: RFC 1122 §3.2.2.6 (LSRR/SSRR MUST be reversed in
        Echo Reply).
        Reference: RFC 791 §3.1 (Loose Source Route wire format).
        """

        inbound_options = Ip4Options(
            Ip4OptionLsrr(
                pointer=12,
                route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
            ),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))

        self.assertEqual(
            len(frames_tx),
            1,
            msg="Echo Request must produce exactly one Echo Reply.",
        )

        reply_lsrr = self._parse_reply_lsrr(frames_tx[0])

        self.assertIsNotNone(
            reply_lsrr,
            msg="Echo Reply must carry an LSRR option matching the request.",
        )
        assert reply_lsrr is not None  # for the type-checker
        self.assertEqual(
            reply_lsrr.route,
            [Ip4Address("10.0.1.20"), Ip4Address("10.0.1.10")],
            msg="Echo Reply LSRR route must be the inbound route reversed.",
        )
        self.assertEqual(
            reply_lsrr.pointer,
            4,
            msg="Echo Reply LSRR pointer must be reset to 4.",
        )

    def test__icmp4__echo_options__ssrr__route_reversed_pointer_reset(self) -> None:
        """
        Ensure an SSRR option in the inbound Echo Request is reversed
        the same way as LSRR — the wire format is identical, the
        semantic distinction (strict vs loose) does not affect the
        echo behaviour.

        Reference: RFC 1122 §3.2.2.6 (LSRR/SSRR MUST be reversed in
        Echo Reply).
        Reference: RFC 791 §3.1 (Strict Source Route wire format).
        """

        inbound_options = Ip4Options(
            Ip4OptionSsrr(
                pointer=12,
                route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
            ),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))

        reply_ssrr = self._parse_reply_ssrr(frames_tx[0])

        self.assertIsNotNone(
            reply_ssrr,
            msg="Echo Reply must carry an SSRR option matching the request.",
        )
        assert reply_ssrr is not None  # for the type-checker
        self.assertEqual(
            reply_ssrr.route,
            [Ip4Address("10.0.1.20"), Ip4Address("10.0.1.10")],
            msg="Echo Reply SSRR route must be the inbound route reversed.",
        )
        self.assertEqual(
            reply_ssrr.pointer,
            4,
            msg="Echo Reply SSRR pointer must be reset to 4.",
        )

    def test__icmp4__echo_options__no_options__reply_unchanged(self) -> None:
        """
        Ensure an Echo Request without any IPv4 options produces an
        Echo Reply with no options either — the regression guard for
        the trivial case the Echo handler used to handle alone.

        Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options
        — when none are present, none are emitted).
        """

        frames_tx = self._drive_rx(frame=_build_echo_request(options=Ip4Options()))

        self.assertEqual(
            self._parse_reply_options_count(frames_tx[0]),
            0,
            msg="Echo Reply must carry no options when the request had none.",
        )

    def test__icmp4__echo_options__rr__echoed_verbatim(self) -> None:
        """
        Ensure an inbound Echo Request carrying a Record Route option
        produces an Echo Reply whose Record Route option is identical
        — same recorded route, same pointer. Echo Reply is not a
        forwarded packet, so RR slots are preserved as-is rather than
        appended to.

        Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options).
        Reference: RFC 791 §3.1 (Record Route wire format).
        """

        inbound_options = Ip4Options(
            Ip4OptionRr(
                pointer=12,
                route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
            ),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))
        reply_rr = self._parse_reply_rr(frames_tx[0])

        self.assertIsNotNone(
            reply_rr,
            msg="Echo Reply must carry a Record Route option matching the request.",
        )
        assert reply_rr is not None  # for the type-checker
        self.assertEqual(
            reply_rr.route,
            [Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
            msg="Echo Reply RR route must match the inbound RR route exactly.",
        )
        self.assertEqual(
            reply_rr.pointer,
            12,
            msg="Echo Reply RR pointer must match the inbound RR pointer.",
        )

    def test__icmp4__echo_options__timestamp_flag_0__echoed_verbatim(self) -> None:
        """
        Ensure an inbound Echo Request carrying a Timestamp option
        with flag=0 (timestamp-only entries) produces an Echo Reply
        whose Timestamp option is identical — same entries, pointer,
        overflow, flag.

        Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options).
        Reference: RFC 791 §3.1 (Timestamp wire format).
        """

        # 12 (TS) + 3 NOPs + 1 EOL = 16 bytes (4-byte aligned).
        inbound_options = Ip4Options(
            Ip4OptionTimestamp(
                pointer=13,
                overflow=2,
                flag=Ip4OptionTimestampFlag.TS_ONLY,
                entries=[
                    Ip4TimestampEntry(timestamp=1234),
                    Ip4TimestampEntry(timestamp=5678),
                ],
            ),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))
        reply_ts = self._parse_reply_timestamp(frames_tx[0])

        self.assertIsNotNone(
            reply_ts,
            msg="Echo Reply must carry a Timestamp option matching the request.",
        )
        assert reply_ts is not None  # for the type-checker
        self.assertEqual(
            reply_ts.flag,
            Ip4OptionTimestampFlag.TS_ONLY,
            msg="Echo Reply Timestamp flag must match the inbound flag.",
        )
        self.assertEqual(
            reply_ts.overflow,
            2,
            msg="Echo Reply Timestamp overflow must match the inbound overflow.",
        )
        self.assertEqual(
            reply_ts.pointer,
            13,
            msg="Echo Reply Timestamp pointer must match the inbound pointer.",
        )
        self.assertEqual(
            [entry.timestamp for entry in reply_ts.entries],
            [1234, 5678],
            msg="Echo Reply Timestamp entries must match the inbound entries.",
        )

    def test__icmp4__echo_options__timestamp_flag_1__echoed_verbatim(self) -> None:
        """
        Ensure an inbound Echo Request carrying a Timestamp option
        with flag=1 (addr+timestamp entries) is also echoed verbatim —
        the per-flag entry shape preserves through the verbatim path
        with no special handling.

        Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options).
        Reference: RFC 791 §3.1 (Timestamp wire format, flag=1).
        """

        # 20 (TS flag=1, 2 addr+ts entries) + 3 NOPs + 1 EOL = 24 (aligned).
        inbound_options = Ip4Options(
            Ip4OptionTimestamp(
                pointer=21,
                overflow=0,
                flag=Ip4OptionTimestampFlag.TS_AND_ADDR,
                entries=[
                    Ip4TimestampEntry(timestamp=1234, address=Ip4Address("10.0.1.10")),
                    Ip4TimestampEntry(timestamp=5678, address=Ip4Address("10.0.1.20")),
                ],
            ),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))
        reply_ts = self._parse_reply_timestamp(frames_tx[0])

        self.assertIsNotNone(
            reply_ts,
            msg="Echo Reply must carry a Timestamp option matching the request.",
        )
        assert reply_ts is not None  # for the type-checker
        self.assertEqual(
            [(entry.address, entry.timestamp) for entry in reply_ts.entries],
            [
                (Ip4Address("10.0.1.10"), 1234),
                (Ip4Address("10.0.1.20"), 5678),
            ],
            msg="Echo Reply Timestamp addr+timestamp pairs must match the request.",
        )

    def test__icmp4__echo_options__router_alert__echoed_verbatim(self) -> None:
        """
        Ensure an inbound Echo Request carrying a Router Alert option
        is echoed verbatim — the value field round-trips unchanged.
        Router Alert has no host-side semantic on Echo Reply; it just
        rides along.

        Reference: RFC 1122 §3.2.2.6 (Echo Reply MUST echo all options).
        Reference: RFC 2113 (Router Alert wire format).
        """

        # 4 (RouterAlert) + 3 NOPs + 1 EOL = 8 bytes (aligned).
        inbound_options = Ip4Options(
            Ip4OptionRouterAlert(value=0),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionNop(),
            Ip4OptionEol(),
        )

        frames_tx = self._drive_rx(frame=_build_echo_request(options=inbound_options))
        reply_ra = self._parse_reply_router_alert(frames_tx[0])

        self.assertIsNotNone(
            reply_ra,
            msg="Echo Reply must carry a Router Alert option matching the request.",
        )
        assert reply_ra is not None  # for the type-checker
        self.assertEqual(
            reply_ra.value,
            0,
            msg="Echo Reply Router Alert value must match the inbound value.",
        )
