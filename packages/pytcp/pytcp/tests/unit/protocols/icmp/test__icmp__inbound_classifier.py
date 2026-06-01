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
This module contains tests for the ICMP inbound classifier.

pytcp/tests/unit/protocols/icmp/test__icmp__inbound_classifier.py

ver 3.0.8
"""

from types import SimpleNamespace
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address, Ip6Address, IpVersion
from pytcp.protocols.icmp.icmp__inbound_classifier import classify_inbound


def _ip4_packet_rx(
    *,
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    offset: int = 0,
) -> Any:
    return SimpleNamespace(
        ip=SimpleNamespace(ver=IpVersion.IP4),
        ip4=SimpleNamespace(
            src=Ip4Address(src),
            dst=Ip4Address(dst),
            offset=offset,
        ),
    )


def _ip6_packet_rx(
    *,
    src: str = "2001:db8::1",
    dst: str = "2001:db8::2",
) -> Any:
    return SimpleNamespace(
        ip=SimpleNamespace(ver=IpVersion.IP6),
        ip6=SimpleNamespace(
            src=Ip6Address(src),
            dst=Ip6Address(dst),
        ),
    )


class TestClassifyInbound__Ip4Defaults(TestCase):
    """
    The 'classify_inbound' IPv4 clean-unicast tests.
    """

    def test__icmp__classifier__ip4_clean_unicast(self) -> None:
        """
        Ensure a clean IPv4 unicast inbound (global-unicast src/dst,
        offset=0) yields a context with all gates clear.

        Reference: RFC 1122 §3.2.2 (clean unicast permits emission).
        """

        ctx = classify_inbound(_ip4_packet_rx())

        self.assertFalse(ctx.inbound_was_icmp_error, msg="Default 'inbound_was_icmp_error' must be False.")
        self.assertFalse(ctx.inbound_dst_is_broadcast, msg="Clean unicast must not flag dst as broadcast.")
        self.assertFalse(ctx.inbound_dst_is_multicast, msg="Clean unicast must not flag dst as multicast.")
        self.assertFalse(ctx.inbound_src_invalid, msg="Clean unicast src must be valid.")
        self.assertFalse(ctx.inbound_non_initial_fragment, msg="offset=0 must not flag non-initial fragment.")
        self.assertFalse(ctx.is_pmtud_response, msg="Default 'is_pmtud_response' must be False.")
        self.assertFalse(ctx.is_param_problem_code_2, msg="Default 'is_param_problem_code_2' must be False.")


@parameterized_class(
    [
        {
            "_description": "Limited broadcast 255.255.255.255 destination.",
            "_kwargs": {"dst": "255.255.255.255"},
            "_expected_field": "inbound_dst_is_broadcast",
        },
        {
            "_description": "Multicast destination 224.0.0.1.",
            "_kwargs": {"dst": "224.0.0.1"},
            "_expected_field": "inbound_dst_is_multicast",
        },
        {
            "_description": "Multicast destination 239.255.255.250 (SSDP).",
            "_kwargs": {"dst": "239.255.255.250"},
            "_expected_field": "inbound_dst_is_multicast",
        },
    ]
)
class TestClassifyInbound__Ip4DstClassification(TestCase):
    """
    The 'classify_inbound' IPv4 destination-classification tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected_field: str

    def test__icmp__classifier__ip4_dst_flags(self) -> None:
        """
        Ensure each non-unicast IPv4 destination class lights up the
        correct context flag.

        Reference: RFC 1122 §3.2.2 (host MUST NOT emit ICMP error in
        response to bcast/mcast destination).
        """

        ctx = classify_inbound(_ip4_packet_rx(**self._kwargs))

        self.assertTrue(
            getattr(ctx, self._expected_field),
            msg=f"Expected '{self._expected_field}=True' for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Unspecified source 0.0.0.0.",
            "_src": "0.0.0.0",
        },
        {
            "_description": "Loopback source 127.0.0.1.",
            "_src": "127.0.0.1",
        },
        {
            "_description": "Multicast source 224.0.0.1.",
            "_src": "224.0.0.1",
        },
        {
            "_description": "Limited-broadcast source 255.255.255.255.",
            "_src": "255.255.255.255",
        },
        {
            "_description": "Class E (reserved) source 240.0.0.1.",
            "_src": "240.0.0.1",
        },
    ]
)
class TestClassifyInbound__Ip4SrcInvalid(TestCase):
    """
    The 'classify_inbound' IPv4 invalid-source tests.
    """

    _description: str
    _src: str

    def test__icmp__classifier__ip4_src_invalid(self) -> None:
        """
        Ensure a source address that does not define a single host
        flags 'inbound_src_invalid'.

        Reference: RFC 1122 §3.2.2 (host MUST NOT emit ICMP error in
        response to a datagram whose source does not define a single
        host: zero, loopback, broadcast, multicast, or Class E).
        """

        ctx = classify_inbound(_ip4_packet_rx(src=self._src))

        self.assertTrue(
            ctx.inbound_src_invalid,
            msg=f"Expected 'inbound_src_invalid=True' for case: {self._description}",
        )


class TestClassifyInbound__Ip4Fragment(TestCase):
    """
    The 'classify_inbound' IPv4 non-initial-fragment tests.
    """

    def test__icmp__classifier__ip4_offset_zero_is_initial(self) -> None:
        """
        Ensure offset=0 does not flag the packet as a non-initial
        fragment. Initial (or non-fragmented) packets pass.

        Reference: RFC 1122 §3.2.2 (initial fragment is permitted).
        """

        ctx = classify_inbound(_ip4_packet_rx(offset=0))

        self.assertFalse(
            ctx.inbound_non_initial_fragment,
            msg="offset=0 must NOT flag non-initial-fragment.",
        )

    def test__icmp__classifier__ip4_offset_nonzero_is_non_initial(self) -> None:
        """
        Ensure offset != 0 flags the packet as a non-initial fragment.

        Reference: RFC 1122 §3.2.2 (host MUST NOT emit ICMP error in
        response to a non-initial fragment).
        """

        ctx = classify_inbound(_ip4_packet_rx(offset=8))

        self.assertTrue(
            ctx.inbound_non_initial_fragment,
            msg="offset=8 must flag the packet as a non-initial fragment.",
        )


class TestClassifyInbound__Ip6Defaults(TestCase):
    """
    The 'classify_inbound' IPv6 clean-unicast tests.
    """

    def test__icmp__classifier__ip6_clean_unicast(self) -> None:
        """
        Ensure a clean IPv6 unicast inbound yields a context with all
        gates clear, including 'inbound_dst_is_broadcast' (no broadcast
        on IPv6).

        Reference: RFC 4443 §2.4(e) (clean unicast permits emission).
        """

        ctx = classify_inbound(_ip6_packet_rx())

        self.assertFalse(ctx.inbound_dst_is_broadcast, msg="IPv6 has no broadcast — must always be False.")
        self.assertFalse(ctx.inbound_dst_is_multicast, msg="Clean unicast must not flag dst as multicast.")
        self.assertFalse(ctx.inbound_src_invalid, msg="Clean unicast src must be valid.")
        self.assertFalse(ctx.inbound_non_initial_fragment, msg="Clean unicast must not flag non-initial-fragment.")


class TestClassifyInbound__Ip6Multicast(TestCase):
    """
    The 'classify_inbound' IPv6 multicast-destination tests.
    """

    def test__icmp__classifier__ip6_mcast_dst(self) -> None:
        """
        Ensure an IPv6 multicast destination flags
        'inbound_dst_is_multicast'.

        Reference: RFC 4443 §2.4(e.3) (host MUST NOT emit ICMPv6 error
        in response to multicast destination, except PTB / Param Problem
        code 2).
        """

        ctx = classify_inbound(_ip6_packet_rx(dst="ff02::1"))

        self.assertTrue(
            ctx.inbound_dst_is_multicast,
            msg="IPv6 multicast destination ff02::1 must flag dst-is-multicast.",
        )


@parameterized_class(
    [
        {
            "_description": "Unspecified source ::.",
            "_src": "::",
        },
        {
            "_description": "Loopback source ::1.",
            "_src": "::1",
        },
        {
            "_description": "Multicast source ff02::1 (illegal as source).",
            "_src": "ff02::1",
        },
    ]
)
class TestClassifyInbound__Ip6SrcInvalid(TestCase):
    """
    The 'classify_inbound' IPv6 invalid-source tests.
    """

    _description: str
    _src: str

    def test__icmp__classifier__ip6_src_invalid(self) -> None:
        """
        Ensure an IPv6 source that does not define a single host flags
        'inbound_src_invalid'. RFC 4291 forbids multicast as source.

        Reference: RFC 4291 §2.5 (multicast addresses MUST NOT appear
        as the source address).
        Reference: RFC 4443 §2.4(e) (host MUST NOT emit ICMPv6 error
        in response to invalid source).
        """

        ctx = classify_inbound(_ip6_packet_rx(src=self._src))

        self.assertTrue(
            ctx.inbound_src_invalid,
            msg=f"Expected 'inbound_src_invalid=True' for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "Caller flags 'inbound_was_icmp_error'.",
            "_kwargs": {"inbound_was_icmp_error": True},
            "_field": "inbound_was_icmp_error",
        },
        {
            "_description": "Caller flags 'is_pmtud_response'.",
            "_kwargs": {"is_pmtud_response": True},
            "_field": "is_pmtud_response",
        },
        {
            "_description": "Caller flags 'is_param_problem_code_2'.",
            "_kwargs": {"is_param_problem_code_2": True},
            "_field": "is_param_problem_code_2",
        },
    ]
)
class TestClassifyInbound__CallerOverrides(TestCase):
    """
    The 'classify_inbound' caller-flag passthrough tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _field: str

    def test__icmp__classifier__caller_flag_passthrough(self) -> None:
        """
        Ensure caller-supplied keyword flags pass through verbatim into
        the resulting IcmpErrorContext. The classifier inspects only
        IP-layer state; outbound-error-type flags come from the caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ctx = classify_inbound(_ip4_packet_rx(), **self._kwargs)

        self.assertTrue(
            getattr(ctx, self._field),
            msg=f"Caller flag '{self._field}' must pass through. Case: {self._description}",
        )
