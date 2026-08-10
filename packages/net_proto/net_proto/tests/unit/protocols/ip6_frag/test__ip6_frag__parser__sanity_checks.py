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
This module contains tests for the IPv6 Frag packet sanity checks.

net_proto/tests/unit/protocols/ip6_frag/test__ip6_frag__parser__sanity_checks.py

ver 3.0.10
"""

from types import SimpleNamespace
from unittest import TestCase

from net_proto import Ip6FragParser, Ip6FragSanityError, PacketRx

# Valid 8-byte IPv6 Frag header (no payload). Used to assert that
# '_validate_sanity()' is a no-op for well-formed frames.
#
# IPv6 Frag wire frame (8 bytes, header only):
#   Byte  0     : 0xff       -> next=IpProto.RAW (255)
#   Byte  1     : 0x00       -> reserved (must be zero)
#   Bytes 2-3   : 0x0000     -> offset=0, res=0, flag_mf=0
#   Bytes 4-7   : 0x00000000 -> id=0
_BASELINE_FRAME = b"\xff\x00\x00\x00\x00\x00\x00\x00"


class TestIp6FragParserSanityChecks(TestCase):
    """
    The IPv6 Frag packet parser sanity checks tests.
    """

    def test__ip6_frag__parser__sanity__no_op_for_baseline_frame(self) -> None:
        """
        Ensure that parsing a well-formed minimal frame does not raise
        Ip6FragSanityError. This guards against a future change that
        accidentally rejects valid frames.

        Reference: RFC 8200 §4.5 (Fragment header well-formed baseline).
        """

        packet_rx = PacketRx(_BASELINE_FRAME)
        packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(_BASELINE_FRAME),
        )

        try:
            Ip6FragParser(packet_rx)
        except Ip6FragSanityError as error:  # pragma: no cover
            self.fail(f"Baseline frame must not raise Ip6FragSanityError, got: {error!s}")

    def test__ip6_frag__parser__sanity__non_final_payload_not_8_byte_aligned(self) -> None:
        """
        Ensure a non-final fragment whose payload length is not a
        multiple of 8 octets raises Ip6FragSanityError. The
        normative MUST is that the receiver discard such a frame;
        the parser raises so the upstream handler can drop it (and,
        in a later commit, may emit ICMPv6 Parameter Problem code
        0 pointing at the Payload Length field).

        Reference: RFC 8200 §4.5 (non-final fragment payload length
        MUST be a multiple of 8).
        """

        # IPv6 Frag wire frame (8 + 7 = 15 bytes):
        #   Byte  0     : 0x06       -> next=TCP (6)
        #   Byte  1     : 0x00       -> reserved
        #   Bytes 2-3   : 0x0001     -> offset=0, res=0, flag_mf=1
        #   Bytes 4-7   : 0x00000042 -> id=0x42
        #   Bytes 8-14  : 0xaa * 7   -> 7-byte payload (sanity violation: not 8-aligned)
        frame = b"\x06\x00\x00\x01\x00\x00\x00\x42" + b"\xaa" * 7

        packet_rx = PacketRx(frame)
        packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(frame),
        )

        with self.assertRaises(Ip6FragSanityError) as error:
            Ip6FragParser(packet_rx)

        self.assertEqual(
            str(error.exception),
            (
                "[SANITY ERROR][IPv6 Frag] Non-final fragment payload length "
                "must be a multiple of 8. Got: len(self._payload)=7, "
                "self._header.flag_mf=True"
            ),
            msg=(
                "Non-final fragment with 7-byte payload must raise "
                "Ip6FragSanityError with the canonical message format."
            ),
        )

    def test__ip6_frag__parser__sanity__final_fragment_unaligned_payload_accepted(self) -> None:
        """
        Ensure a final fragment (M=0) whose payload is not a
        multiple of 8 parses cleanly. The 8-octet-alignment
        constraint applies only to non-final fragments because the
        last fragment carries whatever remainder is left of the
        original datagram.

        Reference: RFC 8200 §4.5 (alignment constraint scoped to
        non-final fragments).
        """

        # IPv6 Frag wire frame (8 + 7 = 15 bytes):
        #   Byte  0     : 0x06       -> next=TCP (6)
        #   Byte  1     : 0x00       -> reserved
        #   Bytes 2-3   : 0x0010     -> offset=2 (16 bytes), res=0, flag_mf=0
        #   Bytes 4-7   : 0x00000042 -> id=0x42
        #   Bytes 8-14  : 0xbb * 7   -> 7-byte payload (final fragment remainder)
        frame = b"\x06\x00\x00\x10\x00\x00\x00\x42" + b"\xbb" * 7

        packet_rx = PacketRx(frame)
        packet_rx.ip6 = SimpleNamespace(  # type: ignore[assignment]
            dlen=len(frame),
        )

        try:
            Ip6FragParser(packet_rx)
        except Ip6FragSanityError as error:  # pragma: no cover
            self.fail(f"Final fragment with unaligned payload must parse, got: {error!s}")

    def test__ip6_frag__sanity_error__message_prefix(self) -> None:
        """
        Ensure the Ip6FragSanityError constructor prepends the
        '[IPv6 Frag] ' protocol tag to the message, matching every
        other PacketSanityError subclass. Pinned even though the parser
        currently has no sanity checks, so the contract is enforced
        from day one for any check added later.

        Reference: RFC 8200 §4.5 (Fragment header sanity).
        """

        error = Ip6FragSanityError("dummy reason")

        self.assertEqual(
            str(error),
            "[SANITY ERROR][IPv6 Frag] dummy reason",
            msg="Ip6FragSanityError must tag messages with '[IPv6 Frag] '.",
        )
