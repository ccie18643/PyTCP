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
Module contains tests for the ICMPv4 packet assembler miscellaneous functions.

net_proto/tests/unit/protocols/icmp4/test__icmp4__assembler__misc.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto import (
    Icmp4Assembler,
    Icmp4Code,
    Icmp4MessageEchoReply,
    Icmp4MessageUnknown,
    Icmp4Type,
    Tracker,
)
from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
)
from net_proto.protocols.icmp4.message.icmp4__message__echo_request import (
    Icmp4EchoRequestCode,
    Icmp4MessageEchoRequest,
)


class TestIcmp4AssemblerMisc(TestCase):
    """
    The ICMPv4 packet assembler miscellaneous functions tests.
    """

    def test__icmp4__assembler__echo_tracker(self) -> None:
        """
        Ensure the ICMPv4 packet assembler 'tracker' property forwards the
        provided 'echo_tracker' so that RX/TX log lines stay correlated with
        the originating packet.

        Reference: RFC 792 (ICMPv4 message wire format — type, code, checksum).
        """

        echo_tracker = Tracker(prefix="RX")

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageEchoReply(),
            echo_tracker=echo_tracker,
        )

        self.assertIs(
            icmp4__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must forward the provided echo_tracker instance.",
        )

    def test__icmp4__assembler__tx_prefix(self) -> None:
        """
        Ensure the ICMPv4 packet assembler 'tracker' is created with the 'TX'
        prefix so that outbound log lines are distinguishable from the inbound
        'RX' side (the prefix is embedded in the tracker serial).

        Reference: RFC 792 (ICMPv4 message wire format — type, code, checksum).
        """

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageEchoReply(),
        )

        self.assertIn(
            "TX",
            str(icmp4__assembler.tracker),
            msg="Assembler tracker serial must embed the 'TX' prefix.",
        )

    def test__icmp4__assembler__defaults_echo_tracker_to_none(self) -> None:
        """
        Ensure that when no 'echo_tracker' is provided the assembler tracker's
        'echo_tracker' attribute is None (standalone transmit, not tied to an
        incoming request).

        Reference: RFC 792 (ICMPv4 message wire format — type, code, checksum).
        """

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageEchoReply(),
        )

        self.assertIsNone(
            icmp4__assembler.tracker.echo_tracker,
            msg="Assembler tracker echo_tracker must default to None when not provided.",
        )


class TestIcmp4AssemblerUnknownCodeReject(TestCase):
    """
    The ICMPv4 assembler TX-strict enum-domain enforcement tests.

    ProtoEnum '_missing_' materialises any unknown wire code byte
    as an `UNKNOWN_<value>` pseudo-member so the parser can
    surface it via `validate_sanity`. The assembler is the
    strict-TX boundary and MUST refuse to emit a known-type
    message whose code field carries such a pseudo-member.

    The closed-set check is exempt for `Icmp4MessageUnknown`:
    that class is the parser-side carrier for RFC 1122 §3.2.2
    unknown-type frames whose code field is by definition an
    `UNKNOWN_n` member of the abstract `Icmp4Code` base.
    Wrapping such a message in an assembler is a legitimate
    roundtrip case (security testing / raw-socket replay).
    """

    def test__icmp4__assembler__unknown_echo_request_code_rejected(self) -> None:
        """
        Ensure constructing an Icmp4Assembler around an Echo Request
        message whose `code` field is an `UNKNOWN_n` enum member
        raises AssertionError at the TX boundary.

        Reference: RFC 792 (ICMPv4 Echo Request code MUST be 0).
        """

        unknown_code = Icmp4EchoRequestCode.from_int(99)
        self.assertTrue(unknown_code.is_unknown, msg="Test fixture sanity: 99 must materialise as UNKNOWN_99.")

        with self.assertRaises(AssertionError) as error:
            Icmp4Assembler(icmp4__message=Icmp4MessageEchoRequest(code=unknown_code))

        self.assertIn(
            "must be a known Icmp4EchoRequestCode",
            str(error.exception),
            msg="AssertionError must cite the closed-set Icmp4EchoRequestCode domain.",
        )

    def test__icmp4__assembler__unknown_dest_unreachable_code_rejected(self) -> None:
        """
        Ensure constructing an Icmp4Assembler around a Destination
        Unreachable message whose `code` field is an `UNKNOWN_n`
        enum member raises AssertionError at the TX boundary.

        Reference: RFC 792 / RFC 1122 §3.2.2.1 / RFC 1812 §5.2.7.1 (DU codes 0..15).
        """

        unknown_code = Icmp4DestinationUnreachableCode.from_int(16)
        self.assertTrue(unknown_code.is_unknown, msg="Test fixture sanity: 16 must materialise as UNKNOWN_16.")

        with self.assertRaises(AssertionError) as error:
            Icmp4Assembler(icmp4__message=Icmp4MessageDestinationUnreachable(code=unknown_code))

        self.assertIn(
            "must be a known Icmp4DestinationUnreachableCode",
            str(error.exception),
            msg="AssertionError must cite the closed-set Icmp4DestinationUnreachableCode domain.",
        )

    def test__icmp4__assembler__unknown_message_wrapper_accepted(self) -> None:
        """
        Ensure constructing an Icmp4Assembler around an
        Icmp4MessageUnknown is accepted — the wrapper exists to
        round-trip wire-side unknown-type frames (the parser
        materialises them; the assembler must be able to re-emit
        them for security-testing / raw-socket replay).

        Reference: RFC 1122 §3.2.2 (host MUST silently discard unknown ICMP types on RX; TX is unconstrained).
        """

        unknown_message = Icmp4MessageUnknown(
            type=Icmp4Type.from_int(99),
            code=Icmp4Code.from_int(99),
            data=b"opaque",
        )

        # Should not raise.
        assembler = Icmp4Assembler(icmp4__message=unknown_message)

        self.assertIs(
            assembler.message,
            unknown_message,
            msg="Assembler must accept an Icmp4MessageUnknown wrapping for roundtrip.",
        )

    def test__icmp4__assembler__known_code_accepted(self) -> None:
        """
        Ensure the canonical happy path — a known-type message with
        a known-code value — passes the TX-strict check.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Should not raise.
        Icmp4Assembler(
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.PORT,
            ),
        )
