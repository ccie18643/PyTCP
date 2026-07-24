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
This module contains tests for the IPv4 packet sanity checks.

net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address
from net_proto import Ip4Parser, Ip4SanityError, PacketRx
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "TTL field is zero.",
            # 20-byte IPv4 frame with ttl=0 (byte 8), a correctly
            # recomputed checksum (bytes 10-11 = 0xd824), and otherwise
            # valid fields so the integrity checks pass and the sanity
            # validator raises on 'ttl == 0'.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\x00\xff\xd8\x24" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "The 'ttl' field must be greater than 0. Got: 0",
                "pointer": 8,
            },
        },
        {
            "_description": "Source address is in the 0.0.0.0/8 'this network' range (0.10.20.30).",
            # src bytes 12-15 = 0x000a141e (0.10.20.30 — in 0.0.0.0/8,
            # excluding 0.0.0.0 itself which is the DHCP-init unspecified
            # source). RFC 1122 §3.2.1.3(a) "(a) {0, <Host-number>} ...
            # MUST NOT be used as a source address". cksum = 0xed37.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\xed\x37" b"\x00\x0a\x14\x1e\x32\x3c\x46\x50"),
            "_results": {
                "error_message": (
                    "The 'src' field must not be in the 'this network' range (0.0.0.0/8). "
                    "Got: Ip4Address('0.10.20.30')"
                ),
                "pointer": 12,
            },
        },
        {
            "_description": "Source address is a loopback address (127.0.0.1).",
            # src bytes 12-15 = 0x7f000001 (127.0.0.1 — in 127.0.0.0/8).
            # RFC 1122 §3.2.1.3(g) "Addresses of this form MUST NOT
            # appear outside a host." cksum = 0x825e.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x82\x5e" b"\x7f\x00\x00\x01\x32\x3c\x46\x50"),
            "_results": {
                "error_message": ("The 'src' field must not be a loopback address. Got: Ip4Address('127.0.0.1')"),
                "pointer": 12,
            },
        },
        {
            "_description": "Source address is a multicast address (224.0.0.1).",
            # src bytes 12-15 = 0xe0000001 (224.0.0.1 is in the IPv4
            # multicast range 224.0.0.0/4). cksum = 0x215e.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x21\x5e" b"\xe0\x00\x00\x01\x32\x3c\x46\x50"),
            "_results": {
                "error_message": ("The 'src' field must not be a multicast address. Got: Ip4Address('224.0.0.1')"),
                "pointer": 12,
            },
        },
        {
            "_description": "Source address is a reserved address (240.0.0.1).",
            # src bytes 12-15 = 0xf0000001 (240.0.0.1 is in the reserved
            # range 240.0.0.0/4 excluding 255.255.255.255). cksum=0x115e.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x11\x5e" b"\xf0\x00\x00\x01\x32\x3c\x46\x50"),
            "_results": {
                "error_message": ("The 'src' field must not be a reserved address. Got: Ip4Address('240.0.0.1')"),
                "pointer": 12,
            },
        },
        {
            "_description": "Source address is the limited broadcast (255.255.255.255).",
            # src bytes 12-15 = 0xffffffff (limited broadcast).
            # cksum = 0x0160.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x01\x60" b"\xff\xff\xff\xff\x32\x3c\x46\x50"),
            "_results": {
                "error_message": (
                    "The 'src' field must not be a limited broadcast address. Got: Ip4Address('255.255.255.255')"
                ),
                "pointer": 12,
            },
        },
        {
            "_description": "DF and MF flags set simultaneously.",
            # Bytes 6-7 = 0x6000 (DF=1, MF=1, offset=0). The parser runs
            # the 'flag_df and flag_mf' check before the
            # 'flag_df and offset != 0' check, so this case lands in
            # the simultaneous-flags branch. cksum = 0xb923.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x60\x00\xff\xff\xb9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "error_message": (
                    "The 'flag_df' and 'flag_mf' flags must not be set simultaneously. "
                    "Got: self.flag_df=True, self.flag_mf=True"
                ),
                "pointer": 6,
            },
        },
        {
            "_description": "DF flag set with a non-zero fragment offset.",
            # Bytes 6-7 = 0x4100 -> DF=1, MF=0, offset=0x100<<3 = 2048.
            # cksum = 0xd823.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x41\x00\xff\xff\xd8\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "error_message": ("The 'offset' field must be 0 when the 'flag_df' flag is set. Got: 2048"),
                "pointer": 6,
            },
        },
    ]
)
class TestIp4ParserSanityChecks(TestCase):
    """
    The IPv4 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx so it can be fed to
        Ip4Parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__ip4__parser__sanity_error(self) -> None:
        """
        Ensure the IPv4 packet parser raises Ip4SanityError with the
        expected message for each semantically invalid frame.

        Reference: RFC 791 §3.1 (IPv4 header layout).
        """

        with self.assertRaises(Ip4SanityError) as error:
            Ip4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv4] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )

    def test__ip4__parser__sanity_error_pointer(self) -> None:
        """
        Ensure the IPv4 packet parser sets the canonical RFC 792
        Parameter Problem 'pointer' on the raised Ip4SanityError so
        the packet handler can emit Code 0 with the correct byte
        offset of the offending field.

        Reference: RFC 792 (Parameter Problem pointer).
        Reference: RFC 1122 §3.2.2.5 (host SHOULD generate Param Problem
        on inbound IP-header errors).
        """

        with self.assertRaises(Ip4SanityError) as error:
            Ip4Parser(self._packet_rx)

        self.assertEqual(
            error.exception.pointer,
            self._results["pointer"],
            msg=f"Unexpected sanity-error pointer for case: {self._description}",
        )


class TestIp4ParserLoopbackBypass(TestCase):
    """
    The IPv4 parser 'from_loopback' bypass of the loopback-source
    martian check.
    """

    # 20-byte IPv4 frame: src=127.0.0.1 (loopback), dst=50.60.70.80,
    # proto=255, DF set. On the wire this is a §3.2.1.3(g) martian.
    _LOOPBACK_SRC_FRAME = b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x82\x5e\x7f\x00\x00\x01\x32\x3c\x46\x50"

    def test__ip4__parser__loopback_src_rejected_on_the_wire(self) -> None:
        """
        Ensure a loopback source address is rejected on an ordinary
        (wire) inbound packet, where 'from_loopback' defaults False.

        Reference: RFC 1122 §3.2.1.3(g) (loopback address must not appear outside a host).
        """

        with self.assertRaises(Ip4SanityError):
            Ip4Parser(PacketRx(self._LOOPBACK_SRC_FRAME))

    def test__ip4__parser__loopback_src_accepted_when_from_loopback(self) -> None:
        """
        Ensure a loopback source address is accepted when the packet is
        marked 'from_loopback', so the loopback interface's internal
        delivery is not martian-filtered.

        Reference: RFC 1122 §3.2.1.3(g) (loopback filter is a wire-ingress policy).
        """

        packet_rx = PacketRx(self._LOOPBACK_SRC_FRAME)
        packet_rx.from_loopback = True

        parser = Ip4Parser(packet_rx)

        self.assertEqual(
            parser.src,
            Ip4Address("127.0.0.1"),
            msg="A from_loopback packet must parse with its loopback source intact.",
        )
