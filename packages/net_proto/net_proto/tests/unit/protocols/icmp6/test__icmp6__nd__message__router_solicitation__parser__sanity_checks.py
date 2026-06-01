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
Module contains tests for the ICMPv6 ND Router Solicitation message parser
sanity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_solicitation__parser__sanity_checks.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6Parser, Icmp6SanityError, Ip6Parser, PacketRx

# Valid 8-byte RS, checksum 0x7aff with pshdr_sum=0.
_RS_BASELINE_FRAME = b"\x85\x00\x7a\xff\x00\x00\x00\x00"

# Valid 16-byte RS carrying an SLLA option, checksum 0x1365 with
# pshdr_sum=0 — used to exercise the "slla forbidden when ip6__src is
# unspecified" rule.
_RS_WITH_SLLA_FRAME = b"\x85\x00\x13\x65\x00\x00\x00\x00\x01\x01\x00\x11\x22\x33\x44\x55"


def _packet_rx_with_ip6(
    frame: bytes,
    *,
    ip6__hop: int,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6' so the ND Router Solicitation
    sanity rules can be exercised in both directions.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
            pshdr_sum=0,
            src=ip6__src,
            dst=ip6__dst,
            hop=ip6__hop,
        ),
    )
    return packet_rx


class TestIcmp6NdMessageRouterSolicitationParserSanityChecksHop(TestCase):
    """
    Sanity-check tests for the 'ip6__hop' field (RFC 4861 requires 255).
    """

    def test__icmp6__nd__message__router_solicitation__hop_not_255__rejected(self) -> None:
        """
        Ensure every ip6__hop value other than 255 is rejected with the
        canonical Icmp6SanityError message.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        for hop in (0, 1, 64, 128, 254):
            with self.subTest(ip6__hop=hop):
                with self.assertRaises(Icmp6SanityError) as error:
                    Icmp6Parser(
                        _packet_rx_with_ip6(
                            _RS_BASELINE_FRAME,
                            ip6__hop=hop,
                            ip6__src=Ip6Address("2001:db8::1"),
                            ip6__dst=Ip6Address("ff02::2"),
                        )
                    )

                self.assertEqual(
                    str(error.exception),
                    (
                        "[SANITY ERROR][ICMPv6] ND Router Solicitation - [RFC 4861] "
                        f"The 'ip6__hop' field must be 255. Got: {hop!r}"
                    ),
                    msg=f"Unexpected sanity-error message for ip6__hop={hop}.",
                )

    def test__icmp6__nd__message__router_solicitation__hop_255__accepted(self) -> None:
        """
        Ensure ip6__hop == 255 passes the sanity check.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RS_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::1"),
                ip6__dst=Ip6Address("ff02::2"),
            )
        )


class TestIcmp6NdMessageRouterSolicitationParserSanityChecksSrc(TestCase):
    """
    Sanity-check tests for the 'ip6__src' field (RFC 4861 requires
    unicast or unspecified).
    """

    def test__icmp6__nd__message__router_solicitation__src_multicast__rejected(self) -> None:
        """
        Ensure a multicast 'ip6__src' is rejected.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        src = Ip6Address("ff02::1")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RS_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=src,
                    ip6__dst=Ip6Address("ff02::2"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Solicitation - [RFC 4861] "
                f"The 'ip6__src' address must be unicast or unspecified. Got: {src!r}"
            ),
            msg="Unexpected sanity-error message for multicast 'ip6__src'.",
        )

    def test__icmp6__nd__message__router_solicitation__src_unicast__accepted(self) -> None:
        """
        Ensure a unicast 'ip6__src' passes the sanity check.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RS_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("ff02::2"),
            )
        )

    def test__icmp6__nd__message__router_solicitation__src_unspecified__accepted(self) -> None:
        """
        Ensure an unspecified 'ip6__src' passes the sanity check (the
        stateless-bootstrap case).

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RS_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("::"),
                ip6__dst=Ip6Address("ff02::2"),
            )
        )


class TestIcmp6NdMessageRouterSolicitationParserSanityChecksDst(TestCase):
    """
    Sanity-check tests for the 'ip6__dst' field (RFC 4861 requires the
    all-routers multicast address ff02::2).
    """

    def test__icmp6__nd__message__router_solicitation__dst_unicast__rejected(self) -> None:
        """
        Ensure a unicast 'ip6__dst' is rejected.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        dst = Ip6Address("2001:db8::1")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RS_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("2001:db8::2"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Solicitation - [RFC 4861] "
                f"The 'ip6__dst' address must be all-routers multicast. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for unicast 'ip6__dst'.",
        )

    def test__icmp6__nd__message__router_solicitation__dst_non_all_routers_multicast__rejected(self) -> None:
        """
        Ensure a multicast 'ip6__dst' other than all-routers (ff02::2)
        is rejected.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        dst = Ip6Address("ff02::1")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RS_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("2001:db8::2"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Solicitation - [RFC 4861] "
                f"The 'ip6__dst' address must be all-routers multicast. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for non-all-routers multicast 'ip6__dst'.",
        )

    def test__icmp6__nd__message__router_solicitation__dst_all_routers_multicast__accepted(self) -> None:
        """
        Ensure the all-routers multicast 'ip6__dst' (ff02::2) passes
        the sanity check.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RS_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("ff02::2"),
            )
        )


class TestIcmp6NdMessageRouterSolicitationParserSanityChecksSllaWithUnspecifiedSrc(TestCase):
    """
    Sanity-check tests for the SLLA option when 'ip6__src' is unspecified
    (RFC 4861 forbids SLLA in bootstrap solicitations).
    """

    def test__icmp6__nd__message__router_solicitation__slla_with_unspecified_src__rejected(self) -> None:
        """
        Ensure an RS carrying an SLLA option is rejected when 'ip6__src'
        is unspecified.

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RS_WITH_SLLA_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("::"),
                    ip6__dst=Ip6Address("ff02::2"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Solicitation - [RFC 4861] "
                "When the 'ip6__src' is unspecified, the 'slla' option must not "
                "be included. Got: MacAddress('00:11:22:33:44:55')"
            ),
            msg="Unexpected sanity-error message for SLLA with unspecified 'ip6__src'.",
        )

    def test__icmp6__nd__message__router_solicitation__no_slla_with_unspecified_src__accepted(self) -> None:
        """
        Ensure an RS with no SLLA option passes when 'ip6__src' is
        unspecified (the bootstrap case).

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RS_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("::"),
                ip6__dst=Ip6Address("ff02::2"),
            )
        )

    def test__icmp6__nd__message__router_solicitation__slla_with_unicast_src__accepted(self) -> None:
        """
        Ensure an RS carrying an SLLA option is accepted when 'ip6__src'
        is a unicast address (the rule applies only to the unspecified
        case).

        Reference: RFC 4861 §4.1 (Router Solicitation type 133).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RS_WITH_SLLA_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::1"),
                ip6__dst=Ip6Address("ff02::2"),
            )
        )
