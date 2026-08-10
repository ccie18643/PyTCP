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
Module contains tests for the ICMPv6 ND Neighbor Solicitation message parser
sanity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__neighbor_solicitation__parser__sanity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6Parser, Icmp6SanityError, Ip6Parser, PacketRx

# Valid 24-byte NS, target 2001:db8::1, checksum 0x4b45 with pshdr_sum=0.
_NS_TARGET_UNICAST_FRAME = (
    b"\x87\x00\x4b\x45\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00" b"\x00\x00\x00\x00\x00\x00\x00\x01"
)

# Valid 24-byte NS, target :: (unspecified — used to exercise the
# target-address unicast rule), checksum 0x78ff with pshdr_sum=0.
_NS_TARGET_UNSPECIFIED_FRAME = b"\x87\x00\x78\xff" + bytes(4) + bytes(16)

# Valid 32-byte NS, target 2001:db8::2, SLLA option present, checksum
# 0xe3a9 with pshdr_sum=0 — used to exercise the "slla forbidden when
# ip6__src is unspecified" rule.
_NS_WITH_SLLA_FRAME = (
    b"\x87\x00\xe3\xa9\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x02\x01\x01\x00\x11\x22\x33\x44\x55"
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
    ICMPv6 parser reads off 'packet_rx.ip6' so the ND Neighbor Solicitation
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


class TestIcmp6NdMessageNeighborSolicitationParserSanityChecksHop(TestCase):
    """
    Sanity-check tests for the 'ip6__hop' field (RFC 4861 requires 255).
    """

    def test__icmp6__nd__message__neighbor_solicitation__hop_not_255__rejected(self) -> None:
        """
        Ensure every ip6__hop value other than 255 is rejected with the
        canonical Icmp6SanityError message.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        for hop in (0, 1, 64, 128, 254):
            with self.subTest(ip6__hop=hop):
                with self.assertRaises(Icmp6SanityError) as error:
                    Icmp6Parser(
                        _packet_rx_with_ip6(
                            _NS_TARGET_UNICAST_FRAME,
                            ip6__hop=hop,
                            ip6__src=Ip6Address("2001:db8::2"),
                            ip6__dst=Ip6Address("2001:db8::1"),
                        )
                    )

                self.assertEqual(
                    str(error.exception),
                    (
                        "[SANITY ERROR][ICMPv6] ND Neighbor Solicitation - [RFC 4861] "
                        f"The 'ip6__hop' field must be 255. Got: {hop!r}"
                    ),
                    msg=f"Unexpected sanity-error message for ip6__hop={hop}.",
                )

    def test__icmp6__nd__message__neighbor_solicitation__hop_255__accepted(self) -> None:
        """
        Ensure ip6__hop == 255 passes the sanity check.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("2001:db8::1"),
            )
        )


class TestIcmp6NdMessageNeighborSolicitationParserSanityChecksSrc(TestCase):
    """
    Sanity-check tests for the 'ip6__src' field (RFC 4861 requires unicast
    or unspecified).
    """

    def test__icmp6__nd__message__neighbor_solicitation__src_multicast__rejected(self) -> None:
        """
        Ensure a multicast 'ip6__src' is rejected.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        src = Ip6Address("ff02::1")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NS_TARGET_UNICAST_FRAME,
                    ip6__hop=255,
                    ip6__src=src,
                    ip6__dst=Ip6Address("2001:db8::1"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Solicitation - [RFC 4861] "
                f"The 'ip6__src' address must be unicast or unspecified. Got: {src!r}"
            ),
            msg="Unexpected sanity-error message for multicast 'ip6__src'.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__src_unicast__accepted(self) -> None:
        """
        Ensure a unicast 'ip6__src' passes the sanity check.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("2001:db8::1"),
            )
        )

    def test__icmp6__nd__message__neighbor_solicitation__src_unspecified__accepted(self) -> None:
        """
        Ensure an unspecified 'ip6__src' passes the sanity check
        (DAD case, with the canonical DAD-shape destination —
        target_address's solicited-node multicast).

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("::"),
                ip6__dst=Ip6Address("ff02::1:ff00:1"),
            )
        )


class TestIcmp6NdMessageNeighborSolicitationParserSanityChecksDst(TestCase):
    """
    Sanity-check tests for the 'ip6__dst' field (RFC 4861 requires
    equality with target_address or its solicited-node multicast).
    """

    def test__icmp6__nd__message__neighbor_solicitation__dst_unrelated__rejected(self) -> None:
        """
        Ensure an 'ip6__dst' that is neither the target_address nor its
        solicited-node multicast address is rejected.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        dst = Ip6Address("2001:db8::2")

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NS_TARGET_UNICAST_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("2001:db8::2"),
                    ip6__dst=dst,
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Solicitation - [RFC 4861] "
                "The 'ip6__dst' address must be the same as 'target_address' "
                f"address or related solicited-node multicast address. Got: {dst!r}"
            ),
            msg="Unexpected sanity-error message for unrelated 'ip6__dst'.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__dst_target__accepted(self) -> None:
        """
        Ensure an 'ip6__dst' equal to the target_address passes.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("2001:db8::1"),
            )
        )

    def test__icmp6__nd__message__neighbor_solicitation__dst_solicited_node_multicast__accepted(self) -> None:
        """
        Ensure an 'ip6__dst' equal to the target_address's solicited-node
        multicast address passes.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("ff02::1:ff00:1"),
            )
        )


class TestIcmp6NdMessageNeighborSolicitationParserSanityChecksDadDestination(TestCase):
    """
    Sanity-check tests for the DAD-context destination address
    constraint when 'ip6__src' is unspecified.
    """

    def test__icmp6__nd__message__neighbor_solicitation__dad_dst_target__rejected(self) -> None:
        """
        Ensure a DAD-context Neighbor Solicitation (src is the
        unspecified address) whose destination is the
        target_address itself — rather than the solicited-node
        multicast — is rejected with a canonical
        'Icmp6SanityError'.

        Reference: RFC 4861 §7.2.3 (DAD NS validity: src=::,
        dst=solicited-node multicast).
        """

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NS_TARGET_UNICAST_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("::"),
                    ip6__dst=Ip6Address("2001:db8::1"),  # target_address itself, NOT solicited-node mcast.
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Solicitation - [RFC 4861] "
                "When the 'ip6__src' is unspecified, the 'ip6__dst' must be "
                f"the solicited-node multicast of 'target_address'. Got: {Ip6Address('2001:db8::1')!r}"
            ),
            msg="Unexpected sanity-error message for DAD NS with dst==target_address.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__dad_dst_solicited_node_multicast__accepted(self) -> None:
        """
        Ensure a DAD-context Neighbor Solicitation (src is the
        unspecified address) whose destination is the target's
        solicited-node multicast passes the sanity check — the
        canonical DAD shape.

        Reference: RFC 4861 §7.2.3 (DAD NS validity).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("::"),
                ip6__dst=Ip6Address("ff02::1:ff00:1"),
            )
        )


class TestIcmp6NdMessageNeighborSolicitationParserSanityChecksTargetAddress(TestCase):
    """
    Sanity-check tests for the 'target_address' field (RFC 4861 requires
    unicast).
    """

    def test__icmp6__nd__message__neighbor_solicitation__target_address_unspecified__rejected(self) -> None:
        """
        Ensure a non-unicast (unspecified) target_address is rejected.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NS_TARGET_UNSPECIFIED_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("2001:db8::2"),
                    ip6__dst=Ip6Address("::"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Solicitation - [RFC 4861] "
                f"The 'target_address' address must be unicast. Got: {Ip6Address('::')!r}"
            ),
            msg="Unexpected sanity-error message for unspecified 'target_address'.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__target_address_unicast__accepted(self) -> None:
        """
        Ensure a unicast 'target_address' passes the sanity check.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::2"),
                ip6__dst=Ip6Address("2001:db8::1"),
            )
        )


class TestIcmp6NdMessageNeighborSolicitationParserSanityChecksSllaWithUnspecifiedSrc(TestCase):
    """
    Sanity-check tests for the SLLA option when 'ip6__src' is unspecified
    (RFC 4861 forbids SLLA in DAD solicitations).
    """

    def test__icmp6__nd__message__neighbor_solicitation__slla_with_unspecified_src__rejected(self) -> None:
        """
        Ensure an NS carrying an SLLA option is rejected when 'ip6__src'
        is unspecified.

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        with self.assertRaises(Icmp6SanityError) as error:
            Icmp6Parser(
                _packet_rx_with_ip6(
                    _NS_WITH_SLLA_FRAME,
                    ip6__hop=255,
                    ip6__src=Ip6Address("::"),
                    ip6__dst=Ip6Address("ff02::1:ff00:2"),
                )
            )

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][ICMPv6] ND Neighbor Solicitation - [RFC 4861] "
                "When the 'ip6__src' is unspecified, the 'slla' option must not "
                "be included. Got: MacAddress('00:11:22:33:44:55')"
            ),
            msg="Unexpected sanity-error message for SLLA with unspecified 'ip6__src'.",
        )

    def test__icmp6__nd__message__neighbor_solicitation__no_slla_with_unspecified_src__accepted(self) -> None:
        """
        Ensure an NS with no SLLA option passes when 'ip6__src'
        is unspecified (the canonical DAD case, with the
        target's solicited-node multicast as the destination).

        Reference: RFC 4861 §4.3 (Neighbor Solicitation type 135).
        """

        Icmp6Parser(
            _packet_rx_with_ip6(
                _NS_TARGET_UNICAST_FRAME,
                ip6__hop=255,
                ip6__src=Ip6Address("::"),
                ip6__dst=Ip6Address("ff02::1:ff00:1"),
            )
        )
