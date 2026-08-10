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
This module contains tests for the ICMP outbound-error eligibility gates.

pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__gates.py

ver 3.0.9
"""

from typing import Any
from unittest import TestCase

from pytcp.protocols.icmp.icmp__error_emitter import (
    IcmpErrorBlockReason,
    IcmpErrorContext,
    should_emit_icmp_error,
)
from pytcp.tests.lib.parameterized import parameterized_class


class TestShouldEmitIcmpError__Permit(TestCase):
    """
    The 'should_emit_icmp_error()' permit-path tests.
    """

    def test__icmp__error_emitter__permits_clean_unicast(self) -> None:
        """
        Ensure a context with all gates clear (default unicast inbound)
        permits the outbound ICMP error.

        Reference: RFC 1122 §3.2.2 (host MUST-NOT-emit gates; permit when none fire).
        Reference: RFC 4443 §2.4(e) (analogous list for ICMPv6).
        """

        verdict = should_emit_icmp_error(IcmpErrorContext())

        self.assertIsNone(
            verdict,
            msg="A clean unicast inbound must permit ICMP error emission.",
        )


@parameterized_class(
    [
        {
            "_description": "Inbound was itself an ICMP error message.",
            "_kwargs": {"inbound_was_icmp_error": True},
            "_results": {"reason": IcmpErrorBlockReason.INBOUND_WAS_ICMP_ERROR},
        },
        {
            "_description": "Inbound destination was IP broadcast.",
            "_kwargs": {"inbound_dst_is_broadcast": True},
            "_results": {"reason": IcmpErrorBlockReason.INBOUND_DST_IS_BROADCAST},
        },
        {
            "_description": "Inbound destination was IP multicast.",
            "_kwargs": {"inbound_dst_is_multicast": True},
            "_results": {"reason": IcmpErrorBlockReason.INBOUND_DST_IS_MULTICAST},
        },
        {
            "_description": "Inbound source did not define a single host.",
            "_kwargs": {"inbound_src_invalid": True},
            "_results": {"reason": IcmpErrorBlockReason.INBOUND_SRC_INVALID},
        },
        {
            "_description": "Inbound was a non-initial fragment.",
            "_kwargs": {"inbound_non_initial_fragment": True},
            "_results": {"reason": IcmpErrorBlockReason.INBOUND_NON_INITIAL_FRAGMENT},
        },
    ]
)
class TestShouldEmitIcmpError__Block(TestCase):
    """
    The 'should_emit_icmp_error()' MUST-NOT gate tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__icmp__error_emitter__blocks_per_gate(self) -> None:
        """
        Ensure each of the host-requirements MUST-NOT gates blocks
        emission and reports the correct blocking reason.

        Reference: RFC 1122 §3.2.2 (host MUST NOT send ICMP error in
        response to: ICMP error, bcast/mcast destination, non-initial
        fragment, source not defining a single host).
        Reference: RFC 4443 §2.4(e) (analogous list for ICMPv6).
        """

        verdict = should_emit_icmp_error(IcmpErrorContext(**self._kwargs))

        self.assertEqual(
            verdict,
            self._results["reason"],
            msg=f"Unexpected block verdict for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Multicast destination + PMTUD response (PTB).",
            "_kwargs": {
                "inbound_dst_is_multicast": True,
                "is_pmtud_response": True,
            },
        },
        {
            "_description": "Multicast destination + Param Problem code 2.",
            "_kwargs": {
                "inbound_dst_is_multicast": True,
                "is_param_problem_code_2": True,
            },
        },
    ]
)
class TestShouldEmitIcmpError__McastExceptions(TestCase):
    """
    The 'should_emit_icmp_error()' multicast-exception tests.
    """

    _description: str
    _kwargs: dict[str, Any]

    def test__icmp__error_emitter__permits_mcast_exception(self) -> None:
        """
        Ensure that an outbound Packet Too Big or Parameter Problem
        (Code 2) is permitted even when the inbound destination was
        multicast.

        Reference: RFC 4443 §2.4(e) (two multicast exceptions: PTB and
        Parameter Problem code 2).
        """

        verdict = should_emit_icmp_error(IcmpErrorContext(**self._kwargs))

        self.assertIsNone(
            verdict,
            msg=f"Mcast-exception case must permit emission: {self._description}",
        )


class TestShouldEmitIcmpError__GatePrecedence(TestCase):
    """
    The 'should_emit_icmp_error()' gate-precedence tests.
    """

    def test__icmp__error_emitter__icmp_error_wins_over_mcast_exception(self) -> None:
        """
        Ensure that the 'inbound was an ICMP error' gate blocks emission
        even when the multicast-exception flags would otherwise permit
        it. The ICMPv6-error-in-response-to-ICMPv6-error rule takes
        precedence over the multicast exceptions.

        Reference: RFC 4443 §2.4(e.1) (ICMPv6 error in response to ICMPv6
        error is unconditionally forbidden).
        """

        ctx = IcmpErrorContext(
            inbound_was_icmp_error=True,
            inbound_dst_is_multicast=True,
            is_pmtud_response=True,
        )

        verdict = should_emit_icmp_error(ctx)

        self.assertEqual(
            verdict,
            IcmpErrorBlockReason.INBOUND_WAS_ICMP_ERROR,
            msg="ICMP-error-in-response-to-ICMP-error must take precedence "
            "over the multicast PMTUD/Param-Problem exceptions.",
        )


class TestIcmpErrorContext__Defaults(TestCase):
    """
    The 'IcmpErrorContext' default-value tests.
    """

    def test__icmp__error_emitter__default_context_is_clean(self) -> None:
        """
        Ensure the default-constructed context represents a clean
        unicast inbound that does not trip any gate. This is the
        baseline call sites can compose from with only the relevant
        flags set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ctx = IcmpErrorContext()

        self.assertFalse(ctx.inbound_was_icmp_error, msg="Default 'inbound_was_icmp_error' must be False.")
        self.assertFalse(ctx.inbound_dst_is_broadcast, msg="Default 'inbound_dst_is_broadcast' must be False.")
        self.assertFalse(ctx.inbound_dst_is_multicast, msg="Default 'inbound_dst_is_multicast' must be False.")
        self.assertFalse(ctx.inbound_src_invalid, msg="Default 'inbound_src_invalid' must be False.")
        self.assertFalse(
            ctx.inbound_non_initial_fragment,
            msg="Default 'inbound_non_initial_fragment' must be False.",
        )
        self.assertFalse(ctx.is_pmtud_response, msg="Default 'is_pmtud_response' must be False.")
        self.assertFalse(ctx.is_param_problem_code_2, msg="Default 'is_param_problem_code_2' must be False.")
