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
Module contains tests for the ICMPv6 ND Neighbor Advertisement message parser
sanity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_advertisement__parser__sanity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6Parser, Icmp6SanityError, Ip6Parser, PacketRx

# Valid 24-byte NA, flag_s=0 flag_r/o=1, target 2001:db8::1,
# checksum 0xaa44 with pshdr_sum=0.
_NA_UNSOLICITED_FRAME = (
    b"\x88\x00\xaa\x44\xa0\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x01"
)

# Valid 24-byte NA, flag_s=1, target 2001:db8::1, checksum 0x0a45 with pshdr_sum=0.
_NA_SOLICITED_FRAME = (
    b"\x88\x00\x0a\x45\x40\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x01"
)


def _packet_rx_with_ip6(
    frame: bytes,
    *,
    ip6__hop: int,
    ip6__src: Ip6Address,
    ip6__dst: Ip6Address,
) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub exposing the attributes the
    ICMPv6 parser reads off 'packet_rx.ip6' so the ND Neighbor Advertisement
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


class TestIcmp6NdMessageNeighborAdvertisementParserSanityChecksHop(TestCase):
    """
    Sanity-check tests for the 'ip6__hop' field (RFC 4861 requires 255).
    """

    def test__icmp6__nd__message__neighbor_advertisement__hop_not_255__rejected(self) -> None:
        """
        Ensure every ip6__hop value other than 255 is rejected with the
        canonical Icmp6SanityError message.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        for hop in (0, 1, 64, 128, 254):
            with self.subTest(ip6__hop=hop):
                with self.assertRaises(Icmp6SanityError) as error:
                    Icmp6Parser(
                        _packet_rx_with_ip6(
                            _NA_UNSOLICITED_FRAME,
                            ip6__hop=hop,
                            ip6__src=Ip6Address("2001:db8::1"),
                            ip6__dst=Ip6Address("ff02::1"),
                        )
                    )

                self.assertEqual(
                    str(error.exception),
                    (
                        "[SANITY ERROR][ICMPv6] ND Neighbor Advertisement - [RFC 4861] "
                        f"The 'ip6__hop' field must be 255. Got: {hop!r}"
                    ),
                    msg=f"Unexpected sanity-error message for ip6__hop={hop}.",
                )

    def test__icmp6__nd__message__neighbor_advertisement__hop_255__accepted(self) -> None:
        """
        Ensure ip6__hop == 255 passes the sanity check.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NA_UNSOLICITED_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::1"),
                ip6__dst=Ip6Address("ff02::1"),
            )
        )


class TestIcmp6NdMessageNeighborAdvertisementParserSanityChecksSrc(TestCase):
    """
    Sanity-check tests for the 'ip6__src' field (RFC 4861 requires unicast).
    """

    def test__icmp6__nd__message__neighbor_advertisement__src_multicast__rejected(self) -> None:
        """
        Ensure a multicast 'ip6__src' is rejected.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        src = Ip6Address("ff02::1")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NA_UNSOLICITED_FRAME,
                    ip6__hop=255,
                    ip6__src=src,
                    ip6__dst=Ip6Address("ff02::1"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Advertisement - [RFC 4861] "
                f"The 'ip6__src' address must be unicast. Got: {src!r}"
            ),
            msg="Unexpected sanity-error message for multicast 'ip6__src'.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__src_unicast__accepted(self) -> None:
        """
        Ensure a unicast 'ip6__src' passes the sanity check.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NA_UNSOLICITED_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::1"),
                ip6__dst=Ip6Address("ff02::1"),
            )
        )


class TestIcmp6NdMessageNeighborAdvertisementParserSanityChecksDstFlagSet(TestCase):
    """
    Sanity-check tests for the 'ip6__dst' field when flag_s is set
    (RFC 4861 requires unicast or all-nodes multicast).
    """

    def test__icmp6__nd__message__neighbor_advertisement__dst_not_unicast_or_allnodes__rejected(self) -> None:
        """
        Ensure an 'ip6__dst' that is neither unicast nor all-nodes
        multicast is rejected when flag_s is set.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        dst = Ip6Address("ff02::2")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NA_SOLICITED_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("2001:db8::1"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Advertisement - [RFC 4861] "
                "If 'flag_s' flag is set then 'ip6__dst' address must be either "
                f"unicast or all-nodes multicast. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for non-unicast/all-nodes 'ip6__dst' with flag_s=1.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__dst_unicast_or_allnodes__accepted(self) -> None:
        """
        Ensure unicast and all-nodes-multicast 'ip6__dst' values pass when
        flag_s is set.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        for dst in (Ip6Address("2001:db8::2"), Ip6Address("ff02::1")):
            with self.subTest(ip6__dst=dst):
                Icmp6Parser(
                    _packet_rx_with_ip6(
                        _NA_SOLICITED_FRAME,
                        ip6__hop=255,
                        ip6__src=Ip6Address("2001:db8::1"),
                        ip6__dst=dst,
                    )
                )


class TestIcmp6NdMessageNeighborAdvertisementParserSanityChecksDstFlagUnset(TestCase):
    """
    Sanity-check tests for the 'ip6__dst' field when flag_s is not set
    (RFC 4861 requires all-nodes multicast).
    """

    def test__icmp6__nd__message__neighbor_advertisement__dst_unicast__rejected(self) -> None:
        """
        Ensure a unicast 'ip6__dst' is rejected when flag_s is not set.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        dst = Ip6Address("2001:db8::2")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NA_UNSOLICITED_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("2001:db8::1"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Advertisement - [RFC 4861] "
                "If 'flag_s' flag is not set then 'ip6__dst' address must be "
                f"all-nodes multicast address. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for non-all-nodes 'ip6__dst' with flag_s=0.",
        )

    def test__icmp6__nd__message__neighbor_advertisement__dst_allnodes__accepted(self) -> None:
        """
        Ensure an all-nodes-multicast 'ip6__dst' passes when flag_s is not
        set.

        Reference: RFC 4861 §4.4 (Neighbor Advertisement type 136).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NA_UNSOLICITED_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::1"),
                ip6__dst=Ip6Address("ff02::1"),
            )
        )
