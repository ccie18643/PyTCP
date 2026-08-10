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
Integration tests for the 'IP4__ACCEPT_SOURCE_ROUTE' inbound gate.
PyTCP defaults to dropping inbound IPv4 packets carrying LSRR or SSRR
options, mirroring Linux's 'net.ipv4.conf.*.accept_source_route'
default. Operators that genuinely need source-route acceptance can
flip the stack flag and the existing handlers process the packet as
before (including the Echo Reply LSRR/SSRR reversal path).

pytcp/tests/integration/protocols/ip4/test__ip4__source_route.py

ver 3.0.10
"""

from net_addr import Ip4Address, MacAddress
from net_proto import (
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4MessageEchoRequest,
    Ip4Assembler,
    Ip4OptionEol,
    Ip4OptionLsrr,
    Ip4Options,
    Ip4OptionSsrr,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.stack import sysctl as sysctl_module
from pytcp.tests.lib.ip4_testcase import Ip4TestCase


def _build_echo_request_with_options(*, options: Ip4Options) -> bytes:
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


class TestIp4SourceRouteGate(Ip4TestCase):
    """
    The 'IP4__ACCEPT_SOURCE_ROUTE' gate tests.
    """

    def test__ip4__source_route__lsrr__dropped_by_default(self) -> None:
        """
        Ensure an inbound IPv4 packet carrying an LSRR option is
        silently dropped when 'IP4__ACCEPT_SOURCE_ROUTE' is False
        (the default). The drop bumps 'ip4__source_route__drop' and
        produces zero TX frames — the per-protocol handlers (ICMPv4
        Echo, TCP, UDP) never run.

        Reference: RFC 1122 §3.2.1.8 (host MAY discard source-routed
        datagrams).
        Reference: PyTCP test infrastructure: matches Linux's
        'net.ipv4.conf.*.accept_source_route=0' default.
        """

        self.assertFalse(
            stack.IP4__ACCEPT_SOURCE_ROUTE["default"],
            msg="Default 'IP4__ACCEPT_SOURCE_ROUTE[\"default\"]' must be False.",
        )

        frame = _build_echo_request_with_options(
            options=Ip4Options(
                Ip4OptionLsrr(
                    pointer=12,
                    route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
                ),
                Ip4OptionEol(),
            ),
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            self._frames_tx,
            [],
            msg="Source-routed packet must produce zero TX frames when accept=False.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__source_route__drop,
            1,
            msg="Source-routed packet must bump 'ip4__source_route__drop'.",
        )

    def test__ip4__source_route__ssrr__dropped_by_default(self) -> None:
        """
        Ensure an inbound IPv4 packet carrying an SSRR option is
        silently dropped under the same default-False gate as LSRR.
        SSRR has identical wire format and identical inbound handling.

        Reference: RFC 1122 §3.2.1.8 (host MAY discard source-routed
        datagrams).
        """

        frame = _build_echo_request_with_options(
            options=Ip4Options(
                Ip4OptionSsrr(
                    pointer=12,
                    route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
                ),
                Ip4OptionEol(),
            ),
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            self._frames_tx,
            [],
            msg="SSRR-bearing packet must produce zero TX frames when accept=False.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__source_route__drop,
            1,
            msg="SSRR-bearing packet must bump 'ip4__source_route__drop'.",
        )

    def test__ip4__source_route__lsrr__accepted_when_opted_in(self) -> None:
        """
        Ensure an inbound LSRR-bearing Echo Request is processed
        normally when 'IP4__ACCEPT_SOURCE_ROUTE' is flipped to True —
        the Echo Reply path runs (including LSRR reversal) and
        'ip4__source_route__drop' stays zero.

        Reference: RFC 1122 §3.2.2.6 (LSRR/SSRR MUST be reversed in
        Echo Reply).
        """

        with sysctl_module.override("ip4.default.accept_source_route", True):
            frame = _build_echo_request_with_options(
                options=Ip4Options(
                    Ip4OptionLsrr(
                        pointer=12,
                        route=[Ip4Address("10.0.1.10"), Ip4Address("10.0.1.20")],
                    ),
                    Ip4OptionEol(),
                ),
            )

            self._packet_handler._phrx_ethernet(PacketRx(frame))

            self.assertEqual(
                self._packet_handler.packet_stats_rx.ip4__source_route__drop,
                0,
                msg="Source-routed packet must NOT bump the drop counter when accept=True.",
            )
            self.assertEqual(
                len(self._frames_tx),
                1,
                msg="Echo Reply must be emitted when source-route is accepted.",
            )

    def test__ip4__source_route__no_source_route__not_affected(self) -> None:
        """
        Ensure an inbound Echo Request without LSRR/SSRR is not
        affected by the gate — the gate is specifically about
        source-route options, not options in general. A Record-Route-
        like option (carried as Ip4OptionUnknown until elevated) and
        an Echo Request with NO options must both pass through.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = _build_echo_request_with_options(options=Ip4Options())

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__source_route__drop,
            0,
            msg="Non-source-routed packet must not bump the drop counter.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Echo Reply must be emitted when no source-route option is present.",
        )
