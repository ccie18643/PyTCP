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
Module contains tests for the ICMPv6 ND Router Advertisement message parser
sanity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_advertisement__parser__sanity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6Parser, Icmp6SanityError, Ip6Parser, PacketRx

# Valid 16-byte RA, hop=0xff, flags=M|O, router_lifetime=0xffff,
# reachable_time=0xffffffff, retrans_timer=0xffffffff; checksum 0x7a3e
# with pshdr_sum=0 — used as the positive baseline for every RA sanity
# dimension (hop / src / dst).
_RA_BASELINE_FRAME = b"\x86\x00\x7a\x3e\xff\xc0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"


def _packet_rx_with_ip6(
    frame: bytes,
    *,
    ip6__hop: int,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6' so the ND Router Advertisement
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


class TestIcmp6NdMessageRouterAdvertisementParserSanityChecksHop(TestCase):
    """
    Sanity-check tests for the 'ip6__hop' field (RFC 4861 requires 255).
    """

    def test__icmp6__nd__message__router_advertisement__hop_not_255__rejected(self) -> None:
        """
        Ensure every ip6__hop value other than 255 is rejected with the
        canonical Icmp6SanityError message.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        for hop in (0, 1, 64, 128, 254):
            with self.subTest(ip6__hop=hop):
                with self.assertRaises(Icmp6SanityError) as error:
                    Icmp6Parser(
                        _packet_rx_with_ip6(
                            _RA_BASELINE_FRAME,
                            ip6__hop=hop,
                            ip6__src=Ip6Address("fe80::1"),
                            ip6__dst=Ip6Address("ff02::1"),
                        )
                    )

                self.assertEqual(
                    str(error.exception),
                    (
                        "[SANITY ERROR][ICMPv6] ND Router Advertisement - [RFC 4861] "
                        f"The 'ip6__hop' field must be 255. Got: {hop!r}"
                    ),
                    msg=f"Unexpected sanity-error message for ip6__hop={hop}.",
                )

    def test__icmp6__nd__message__router_advertisement__hop_255__accepted(self) -> None:
        """
        Ensure ip6__hop == 255 passes the sanity check.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RA_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("fe80::1"),
                ip6__dst=Ip6Address("ff02::1"),
            )
        )


class TestIcmp6NdMessageRouterAdvertisementParserSanityChecksSrc(TestCase):
    """
    Sanity-check tests for the 'ip6__src' field (RFC 4861 requires
    link-local).
    """

    def test__icmp6__nd__message__router_advertisement__src_global_unicast__rejected(self) -> None:
        """
        Ensure a global-unicast 'ip6__src' is rejected.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        src = Ip6Address("2001:db8::1")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RA_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=src,
                    ip6__dst=Ip6Address("ff02::1"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Advertisement - [RFC 4861] "
                f"The 'ip6__src' address must be link-local. Got: {src!r}"
            ),
            msg="Unexpected sanity-error message for global-unicast 'ip6__src'.",
        )

    def test__icmp6__nd__message__router_advertisement__src_unspecified__rejected(self) -> None:
        """
        Ensure an unspecified 'ip6__src' is rejected (not link-local).

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        src = Ip6Address("::")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RA_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=src,
                    ip6__dst=Ip6Address("ff02::1"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Advertisement - [RFC 4861] "
                f"The 'ip6__src' address must be link-local. Got: {src!r}"
            ),
            msg="Unexpected sanity-error message for unspecified 'ip6__src'.",
        )

    def test__icmp6__nd__message__router_advertisement__src_link_local__accepted(self) -> None:
        """
        Ensure a link-local 'ip6__src' passes the sanity check.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RA_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("fe80::1"),
                ip6__dst=Ip6Address("ff02::1"),
            )
        )


class TestIcmp6NdMessageRouterAdvertisementParserSanityChecksDst(TestCase):
    """
    Sanity-check tests for the 'ip6__dst' field (RFC 4861 requires unicast
    or all-nodes multicast).
    """

    def test__icmp6__nd__message__router_advertisement__dst_unspecified__rejected(self) -> None:
        """
        Ensure an unspecified 'ip6__dst' is rejected.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        dst = Ip6Address("::")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RA_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("fe80::1"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Advertisement - [RFC 4861] "
                f"The 'ip6__dst' address must be unicast or all-nodes multicast. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for unspecified 'ip6__dst'.",
        )

    def test__icmp6__nd__message__router_advertisement__dst_non_all_nodes_multicast__rejected(self) -> None:
        """
        Ensure a multicast 'ip6__dst' other than all-nodes (ff02::1) is
        rejected.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        dst = Ip6Address("ff02::2")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _RA_BASELINE_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("fe80::1"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Router Advertisement - [RFC 4861] "
                f"The 'ip6__dst' address must be unicast or all-nodes multicast. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for non-all-nodes multicast 'ip6__dst'.",
        )

    def test__icmp6__nd__message__router_advertisement__dst_unicast__accepted(self) -> None:
        """
        Ensure a unicast 'ip6__dst' passes the sanity check.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RA_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("fe80::1"),
                ip6__dst=Ip6Address("2001:db8::1"),
            )
        )

    def test__icmp6__nd__message__router_advertisement__dst_all_nodes_multicast__accepted(self) -> None:
        """
        Ensure the all-nodes multicast 'ip6__dst' (ff02::1) passes the
        sanity check.

        Reference: RFC 4861 §4.2 (Router Advertisement type 134).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _RA_BASELINE_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("fe80::1"),
                ip6__dst=Ip6Address("ff02::1"),
            )
        )
