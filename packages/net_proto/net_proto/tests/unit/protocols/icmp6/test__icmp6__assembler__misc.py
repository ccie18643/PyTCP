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
Module contains tests for the ICMPv6 packet assembler miscellaneous functions.

net_proto/tests/unit/protocols/icmp6/test__icmp6__assembler__misc.py

ver 3.0.9
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6Code,
    Icmp6MessageEchoReply,
    Icmp6MessageUnknown,
    Icmp6Type,
    Tracker,
)
from net_proto.protocols.icmp6.message.icmp6__message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
)
from net_proto.protocols.icmp6.message.icmp6__message__echo_request import (
    Icmp6EchoRequestCode,
    Icmp6MessageEchoRequest,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__neighbor_solicitation import (
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdNeighborSolicitationCode,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__options import (
    Icmp6NdOptions,
)


class TestIcmp6AssemblerMisc(TestCase):
    """
    The ICMPv6 packet assembler miscellaneous functions tests.
    """

    def test__icmp6__assembler__echo_tracker(self) -> None:
        """
        Ensure the ICMPv6 packet assembler 'tracker' property forwards the
        provided 'echo_tracker' so that RX/TX log lines stay correlated with
        the originating packet.

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        echo_tracker = Tracker(prefix="RX")

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoReply(),
            echo_tracker=echo_tracker,
        )

        self.assertIs(
            icmp6__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must forward the provided echo_tracker instance.",
        )

    def test__icmp6__assembler__tx_prefix(self) -> None:
        """
        Ensure the ICMPv6 packet assembler 'tracker' is created with the 'TX'
        prefix so that outbound log lines are distinguishable from the inbound
        'RX' side (the prefix is embedded in the tracker serial).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoReply(),
        )

        self.assertIn(
            "TX",
            str(icmp6__assembler.tracker),
            msg="Assembler tracker serial must embed the 'TX' prefix.",
        )

    def test__icmp6__assembler__defaults_echo_tracker_to_none(self) -> None:
        """
        Ensure that when no 'echo_tracker' is provided the assembler tracker's
        'echo_tracker' attribute is None (standalone transmit, not tied to an
        incoming request).

        Reference: RFC 4443 §2.1 (ICMPv6 message general format).
        """

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoReply(),
        )

        self.assertIsNone(
            icmp6__assembler.tracker.echo_tracker,
            msg="Assembler tracker echo_tracker must default to None when not provided.",
        )


class TestIcmp6AssemblerUnknownCodeReject(TestCase):
    """
    The ICMPv6 assembler TX-strict enum-domain enforcement tests.

    ProtoEnum '_missing_' materialises any unknown wire code
    byte as an `UNKNOWN_<value>` pseudo-member so the parser
    can surface it via `validate_sanity`. The assembler is
    the strict-TX boundary and MUST refuse to emit a
    known-type message whose code field carries such a
    pseudo-member.

    The closed-set check is exempt for `Icmp6MessageUnknown`:
    that class is the parser-side carrier for RFC 4443 §2.1
    unknown-type frames whose code field is by definition an
    `UNKNOWN_n` member of the abstract `Icmp6Code` base.
    Wrapping such a message in an assembler is a legitimate
    roundtrip case (security testing / raw-socket replay).
    """

    def test__icmp6__assembler__unknown_echo_request_code_rejected(self) -> None:
        """
        Ensure constructing an Icmp6Assembler around an Echo
        Request message whose `code` field is an `UNKNOWN_n`
        enum member raises AssertionError at the TX boundary.

        Reference: RFC 4443 §4.1 (ICMPv6 Echo Request code MUST be 0).
        """

        unknown_code = Icmp6EchoRequestCode.from_int(99)
        self.assertTrue(unknown_code.is_unknown, msg="Test fixture sanity: 99 must materialise as UNKNOWN_99.")

        with self.assertRaises(AssertionError) as error:
            Icmp6Assembler(icmp6__message=Icmp6MessageEchoRequest(code=unknown_code))

        self.assertIn(
            "must be a known Icmp6EchoRequestCode",
            str(error.exception),
            msg="AssertionError must cite the closed-set Icmp6EchoRequestCode domain.",
        )

    def test__icmp6__assembler__unknown_nd_code_rejected(self) -> None:
        """
        Ensure constructing an Icmp6Assembler around a
        Neighbor Solicitation message whose `code` field is
        an `UNKNOWN_n` enum member raises AssertionError at
        the TX boundary. This pins the TX-strict guard on
        the surface exposed by the ND parser-tolerant
        migration (commit `8535e9b2`) — before that commit
        the ND messages' strict `<Code-enum>(value)`
        constructor would have caught the unknown at
        construction time and the assembler would never have
        seen it.

        Reference: RFC 4861 §4.3 (ND Neighbor Solicitation code MUST be 0).
        """

        unknown_code = Icmp6NdNeighborSolicitationCode.from_int(99)
        self.assertTrue(unknown_code.is_unknown, msg="Test fixture sanity: 99 must materialise as UNKNOWN_99.")

        with self.assertRaises(AssertionError) as error:
            Icmp6Assembler(
                icmp6__message=Icmp6NdMessageNeighborSolicitation(
                    code=unknown_code,
                    target_address=Ip6Address("fe80::1"),
                    options=Icmp6NdOptions(),
                ),
            )

        self.assertIn(
            "must be a known Icmp6NdNeighborSolicitationCode",
            str(error.exception),
            msg="AssertionError must cite the closed-set Icmp6NdNeighborSolicitationCode domain.",
        )

    def test__icmp6__assembler__unknown_message_wrapper_accepted(self) -> None:
        """
        Ensure constructing an Icmp6Assembler around an
        Icmp6MessageUnknown is accepted — the wrapper exists
        to round-trip wire-side unknown-type frames (the
        parser materialises them; the assembler must be able
        to re-emit them for security-testing / raw-socket
        replay).

        Reference: RFC 4443 §2.1 (host MUST silently discard unknown ICMPv6 types on RX; TX is unconstrained).
        """

        unknown_message = Icmp6MessageUnknown(
            type=Icmp6Type.from_int(99),
            code=Icmp6Code.from_int(99),
            data=b"opaque",
        )

        # Should not raise.
        assembler = Icmp6Assembler(icmp6__message=unknown_message)

        self.assertIs(
            assembler.message,
            unknown_message,
            msg="Assembler must accept an Icmp6MessageUnknown wrapping for roundtrip.",
        )

    def test__icmp6__assembler__known_code_accepted(self) -> None:
        """
        Ensure the canonical happy path — a known-type
        message with a known-code value — passes the
        TX-strict check.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Should not raise.
        Icmp6Assembler(
            icmp6__message=Icmp6MessageDestinationUnreachable(
                code=Icmp6DestinationUnreachableCode.PORT,
            ),
        )
