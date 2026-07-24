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
Module contains tests for the ICMPv6 MLDv2 Report message parser
sanity checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__parser__sanity_checks.py

ver 3.0.9
"""

from types import SimpleNamespace
from typing import cast
from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Icmp6Parser, Icmp6SanityError, Ip6Parser, PacketRx

# Valid bare MLDv2 Report, 8 bytes, checksum 0x70ff (pshdr_sum=0), zero records.
_MLD2_REPORT_EMPTY_FRAME = b"\x8f\x00\x70\xff\x00\x00\x00\x00"


def _packet_rx_with_ip6(frame: bytes, *, ip6__hop: int) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv6 stub. The 'hop' attribute is
    tunable so the MLDv2 Report hop-limit sanity check can be exercised
    in both directions.
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip = packet_rx.ip6 = cast(
        Ip6Parser,
        SimpleNamespace(
            dlen=len(frame),
            payload_len=len(frame),
            pshdr_sum=0,
            src=Ip6Address(),
            dst=Ip6Address(),
            hop=ip6__hop,
        ),
    )
    return packet_rx


class TestIcmp6Mld2MessageReportParserSanityChecksHopInvalid(TestCase):
    """
    Negative sanity-check tests: every ip6__hop value other than 1
    must be rejected per RFC 3810.
    """

    def test__icmp6__mld2__message__report__parser__hop_not_one__rejected(self) -> None:
        """
        Ensure every non-one ip6__hop value is rejected with the
        canonical Icmp6SanityError message.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        for hop in (0, 2, 64, 128, 255):
            with self.subTest(ip6__hop=hop):
                with self.assertRaises(Icmp6SanityError) as error:
                    Icmp6Parser(_packet_rx_with_ip6(_MLD2_REPORT_EMPTY_FRAME, ip6__hop=hop))

                self.assertEqual(
                    str(error.exception),
                    f"[SANITY ERROR][ICMPv6] MLDv2 Report - [RFC 3810] The 'ip6__hop' field must be 1. Got: {hop!r}",
                    msg=f"Unexpected sanity-error message for ip6__hop={hop}.",
                )


class TestIcmp6Mld2MessageReportParserSanityChecksHopValid(TestCase):
    """
    Positive sanity-check test: ip6__hop == 1 must pass.
    """

    def test__icmp6__mld2__message__report__parser__hop_one__accepted(self) -> None:
        """
        Ensure a valid MLDv2 Report with ip6__hop == 1 passes sanity
        checks and parses cleanly.

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report type 143).
        """

        packet_rx = _packet_rx_with_ip6(_MLD2_REPORT_EMPTY_FRAME, ip6__hop=1)

        Icmp6Parser(packet_rx)
