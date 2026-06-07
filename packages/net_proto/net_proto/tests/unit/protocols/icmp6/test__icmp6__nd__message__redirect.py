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
Module contains tests for the ICMPv6 ND Redirect message (RFC 4861 §4.5).

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__redirect.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip6Address, MacAddress
from net_proto import (
    ICMP6__ND__REDIRECT__LEN,
    Icmp6IntegrityError,
    Icmp6NdMessageRedirect,
    Icmp6NdOptionRedirectedHeader,
    Icmp6NdOptions,
    Icmp6NdOptionTlla,
    Icmp6NdRedirectCode,
    Icmp6SanityError,
    Icmp6Type,
)

# Common fixtures
_TARGET = Ip6Address("fe80::1")
_DESTINATION = Ip6Address("2001:db8::1234")
_TARGET_MAC = MacAddress("00:11:22:33:44:55")


class TestIcmp6NdMessageRedirectAsserts(TestCase):
    """
    The ICMPv6 ND Redirect message constructor argument assert
    tests.
    """

    def _kwargs(self, **overrides: Any) -> dict[str, Any]:
        """
        Build a baseline-valid kwargs dict, with caller-supplied
        overrides.
        """

        base: dict[str, Any] = {
            "target_address": _TARGET,
            "destination_address": _DESTINATION,
            "options": Icmp6NdOptions(),
        }
        base.update(overrides)
        return base

    def test__icmp6__nd__message__redirect__defaults_accepted(self) -> None:
        """
        Ensure the constructor accepts a baseline-valid kwargs
        bundle and the resulting message has the canonical
        type/code defaults (137 / 0).

        Reference: RFC 4861 §4.5 (Type = 137, Code = 0).
        """

        msg = Icmp6NdMessageRedirect(**self._kwargs())

        self.assertEqual(
            msg.type,
            Icmp6Type.ND__REDIRECT,
            msg="The 'type' field default must be Icmp6Type.ND__REDIRECT.",
        )
        self.assertEqual(
            msg.code,
            Icmp6NdRedirectCode.DEFAULT,
            msg="The 'code' field default must be Icmp6NdRedirectCode.DEFAULT.",
        )
        self.assertEqual(
            len(msg),
            ICMP6__ND__REDIRECT__LEN,
            msg="A Redirect with no options must have len == ICMP6__ND__REDIRECT__LEN (40).",
        )

    def test__icmp6__nd__message__redirect__cksum__not_uint16(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' value outside
        the unsigned 16-bit range.

        Reference: RFC 4443 §2.3 (16-bit checksum field).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRedirect(**self._kwargs(cksum=0x10000))

        self.assertIn(
            "16-bit unsigned integer",
            str(error.exception),
            msg="Rejection must call out the 16-bit constraint on 'cksum'.",
        )

    def test__icmp6__nd__message__redirect__target_address__not_Ip6Address(self) -> None:
        """
        Ensure the constructor rejects a 'target_address' that
        is not an Ip6Address instance.

        Reference: RFC 4861 §4.5 (Target Address — IPv6 address field).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRedirect(**self._kwargs(target_address="fe80::1"))

        self.assertIn(
            "target_address",
            str(error.exception),
            msg="Rejection must call out the offending field name.",
        )

    def test__icmp6__nd__message__redirect__destination_address__not_Ip6Address(self) -> None:
        """
        Ensure the constructor rejects a 'destination_address'
        that is not an Ip6Address instance.

        Reference: RFC 4861 §4.5 (Destination Address — IPv6 address field).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRedirect(**self._kwargs(destination_address="2001:db8::1"))

        self.assertIn(
            "destination_address",
            str(error.exception),
            msg="Rejection must call out the offending field name.",
        )

    def test__icmp6__nd__message__redirect__options__not_Icmp6NdOptions(self) -> None:
        """
        Ensure the constructor rejects 'options' that is not an
        Icmp6NdOptions instance.

        Reference: RFC 4861 §4.5 (Possible options follow the fixed-length section).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRedirect(**self._kwargs(options=[]))

        self.assertIn(
            "options",
            str(error.exception),
            msg="Rejection must call out the offending field name.",
        )


@parameterized_class(
    [
        {
            "_description": "ICMPv6 ND Redirect message — no options (smallest valid form).",
            "_kwargs": {
                "target_address": _TARGET,
                "destination_address": _DESTINATION,
                "options": Icmp6NdOptions(),
            },
            "_results": {
                "__len__": 40,
                "__bytes__": (
                    # Redirect header (40 bytes):
                    #   Type      : 137 (Redirect)
                    #   Code      : 0
                    #   Checksum  : 0 (Icmp6Assembler back-patches; raw __bytes__ leaves 0)
                    #   Reserved  : 32 zero bits
                    #   Target    : fe80::1
                    #   Destination : 2001:db8::1234
                    b"\x89\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34"
                ),
                "type": Icmp6Type.ND__REDIRECT,
                "code": Icmp6NdRedirectCode.DEFAULT,
                "target_address": _TARGET,
                "destination_address": _DESTINATION,
            },
        },
        {
            "_description": "ICMPv6 ND Redirect message — with TLLA option.",
            "_kwargs": {
                "target_address": _TARGET,
                "destination_address": _DESTINATION,
                "options": Icmp6NdOptions(Icmp6NdOptionTlla(tlla=_TARGET_MAC)),
            },
            "_results": {
                "__len__": 48,
                "__bytes__": (
                    # Redirect header (40):
                    b"\x89\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34"
                    # TLLA option (8 bytes): type=2, len=1, MAC
                    b"\x02\x01\x00\x11\x22\x33\x44\x55"
                ),
                "type": Icmp6Type.ND__REDIRECT,
                "code": Icmp6NdRedirectCode.DEFAULT,
                "target_address": _TARGET,
                "destination_address": _DESTINATION,
            },
        },
        {
            "_description": "ICMPv6 ND Redirect message — with TLLA and Redirected Header (carrying 8 bytes).",
            "_kwargs": {
                "target_address": _TARGET,
                "destination_address": _DESTINATION,
                "options": Icmp6NdOptions(
                    Icmp6NdOptionTlla(tlla=_TARGET_MAC),
                    Icmp6NdOptionRedirectedHeader(data=b"\x60\x00\x00\x00\x00\x10\x06\x40"),
                ),
            },
            "_results": {
                "__len__": 64,
                "__bytes__": (
                    # Redirect header (40):
                    b"\x89\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
                    b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34"
                    # TLLA (8):
                    b"\x02\x01\x00\x11\x22\x33\x44\x55"
                    # Redirected Header (16): type=4, len=2, 6 reserved zeros, 8 data bytes
                    b"\x04\x02\x00\x00\x00\x00\x00\x00"
                    b"\x60\x00\x00\x00\x00\x10\x06\x40"
                ),
                "type": Icmp6Type.ND__REDIRECT,
                "code": Icmp6NdRedirectCode.DEFAULT,
                "target_address": _TARGET,
                "destination_address": _DESTINATION,
            },
        },
    ]
)
class TestIcmp6NdMessageRedirectAssembler(TestCase):
    """
    The ICMPv6 ND Redirect message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the Redirect message from the parametrized kwargs.
        """

        self._msg = Icmp6NdMessageRedirect(**self._kwargs)

    def test__icmp6__nd__message__redirect__len(self) -> None:
        """
        Ensure '__len__()' returns the expected byte length —
        40-byte fixed header plus the assembled options block.

        Reference: RFC 4861 §4.5 (Redirect wire format).
        """

        self.assertEqual(
            len(self._msg),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__message__redirect__bytes(self) -> None:
        """
        Ensure '__bytes__()' produces the expected wire bytes —
        type=137, code=0, zero checksum, 32-bit reserved zero,
        Target Address, Destination Address, then options
        block.

        Reference: RFC 4861 §4.5 (Redirect wire format).
        """

        self.assertEqual(
            bytes(self._msg),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__message__redirect__type(self) -> None:
        """
        Ensure the message 'type' field is ND__REDIRECT (137).

        Reference: RFC 4861 §4.5 (Type = 137).
        """

        self.assertEqual(
            self._msg.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__icmp6__nd__message__redirect__code(self) -> None:
        """
        Ensure the message 'code' field is the canonical
        DEFAULT (0).

        Reference: RFC 4861 §4.5 (Code = 0).
        """

        self.assertEqual(
            self._msg.code,
            self._results["code"],
            msg=f"Unexpected 'code' for case: {self._description}",
        )

    def test__icmp6__nd__message__redirect__target_address(self) -> None:
        """
        Ensure the 'target_address' field carries the supplied
        Ip6Address.

        Reference: RFC 4861 §4.5 (Target Address — better first hop).
        """

        self.assertEqual(
            self._msg.target_address,
            self._results["target_address"],
            msg=f"Unexpected 'target_address' for case: {self._description}",
        )

    def test__icmp6__nd__message__redirect__destination_address(self) -> None:
        """
        Ensure the 'destination_address' field carries the
        supplied Ip6Address.

        Reference: RFC 4861 §4.5 (Destination Address — endpoint redirected to target).
        """

        self.assertEqual(
            self._msg.destination_address,
            self._results["destination_address"],
            msg=f"Unexpected 'destination_address' for case: {self._description}",
        )


class TestIcmp6NdMessageRedirectParser(TestCase):
    """
    The ICMPv6 ND Redirect message parser positive tests.
    """

    def test__icmp6__nd__message__redirect__from_buffer__minimal(self) -> None:
        """
        Ensure 'from_buffer' parses a minimal (no-options)
        Redirect message correctly.

        Reference: RFC 4861 §4.5 (Redirect wire format).
        """

        wire = (
            b"\x89\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34"
        )

        msg = Icmp6NdMessageRedirect.from_buffer(wire)

        self.assertEqual(
            msg,
            Icmp6NdMessageRedirect(
                target_address=_TARGET,
                destination_address=_DESTINATION,
                options=Icmp6NdOptions(),
            ),
            msg="Parsed Redirect must equal the reference message.",
        )

    def test__icmp6__nd__message__redirect__from_buffer__round_trip_with_options(self) -> None:
        """
        Ensure assemble→parse round-trip preserves every field
        when the options block carries TLLA + Redirected
        Header.

        Reference: RFC 4861 §4.5 + §4.6.3 (Redirect carrying TLLA + Redirected Header).
        """

        original = Icmp6NdMessageRedirect(
            target_address=_TARGET,
            destination_address=_DESTINATION,
            options=Icmp6NdOptions(
                Icmp6NdOptionTlla(tlla=_TARGET_MAC),
                Icmp6NdOptionRedirectedHeader(data=b"\x60\x00\x00\x00\x00\x10\x06\x40"),
            ),
        )

        parsed = Icmp6NdMessageRedirect.from_buffer(bytes(original))

        self.assertEqual(
            parsed,
            original,
            msg="Round-trip parse must reproduce the original Redirect message.",
        )


class TestIcmp6NdMessageRedirectIntegrity(TestCase):
    """
    The ICMPv6 ND Redirect message integrity-check tests.
    """

    def test__icmp6__nd__message__redirect__validate_integrity__below_minimum_length(self) -> None:
        """
        Ensure 'validate_integrity' rejects a frame shorter
        than the 40-byte fixed Redirect header.

        Reference: RFC 4861 §4.5 (40-byte fixed header is mandatory).
        """

        short_frame = b"\x89\x00\x00\x00" + b"\x00" * 35

        with self.assertRaises(Icmp6IntegrityError) as ctx:
            Icmp6NdMessageRedirect.validate_integrity(frame=short_frame, ip6__dlen=len(short_frame))

        self.assertIn(
            "ICMP6__ND__REDIRECT__LEN",
            str(ctx.exception),
            msg="Rejection must call out the minimum-length constraint.",
        )

    def test__icmp6__nd__message__redirect__validate_integrity__minimum_accepted(self) -> None:
        """
        Ensure the shortest-valid (40-byte) Redirect frame
        passes integrity checks.

        Reference: RFC 4861 §4.5 (40-byte fixed header without options is valid).
        """

        wire = (
            b"\x89\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
            b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34"
        )

        # Should not raise
        Icmp6NdMessageRedirect.validate_integrity(frame=wire, ip6__dlen=len(wire))


class TestIcmp6NdMessageRedirectSanity(TestCase):
    """
    The ICMPv6 ND Redirect message sanity-check tests
    (RFC 4861 §8.1 acceptance gates that the parser enforces).
    """

    @override
    def setUp(self) -> None:
        """
        Build a baseline Redirect message used across the
        sanity-check tests.
        """

        self._msg = Icmp6NdMessageRedirect(
            target_address=_TARGET,
            destination_address=_DESTINATION,
            options=Icmp6NdOptions(),
        )

    def test__icmp6__nd__message__redirect__sanity__hop_limit_not_255(self) -> None:
        """
        Ensure 'validate_sanity' rejects a Redirect with IP
        Hop Limit != 255 — required by §8.1 to guard against
        off-link spoofing.

        Reference: RFC 4861 §8.1 (Hop Limit MUST be 255).
        """

        with self.assertRaises(Icmp6SanityError) as ctx:
            self._msg.validate_sanity(
                ip6__hop=64,
                ip6__src=Ip6Address("fe80::abcd"),
                ip6__dst=Ip6Address("fe80::1234"),
            )

        self.assertIn(
            "255",
            str(ctx.exception),
            msg="Rejection must call out the Hop Limit = 255 requirement.",
        )

    def test__icmp6__nd__message__redirect__sanity__source_not_link_local(self) -> None:
        """
        Ensure 'validate_sanity' rejects a Redirect whose IP
        source is not a link-local address — the redirecting
        router MUST source from its link-local per §8.1.

        Reference: RFC 4861 §8.1 (Source Address MUST be link-local).
        """

        with self.assertRaises(Icmp6SanityError) as ctx:
            self._msg.validate_sanity(
                ip6__hop=255,
                ip6__src=Ip6Address("2001:db8::abcd"),
                ip6__dst=Ip6Address("fe80::1234"),
            )

        self.assertIn(
            "link-local",
            str(ctx.exception),
            msg="Rejection must call out the link-local source requirement.",
        )

    def test__icmp6__nd__message__redirect__sanity__valid_passes(self) -> None:
        """
        Ensure 'validate_sanity' accepts a Redirect with
        Hop=255, link-local source, and unicast destination.

        Reference: RFC 4861 §8.1 (acceptance gates).
        """

        # Should not raise
        self._msg.validate_sanity(
            ip6__hop=255,
            ip6__src=Ip6Address("fe80::abcd"),
            ip6__dst=Ip6Address("fe80::1234"),
        )
