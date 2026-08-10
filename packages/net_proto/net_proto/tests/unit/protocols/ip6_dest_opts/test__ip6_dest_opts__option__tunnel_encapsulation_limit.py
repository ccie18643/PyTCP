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
This module contains tests for the IPv6 Dest Opts Tunnel Encapsulation
Limit option.

net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__option__tunnel_encapsulation_limit.py

ver 3.0.10
"""

from typing import Any
from unittest import TestCase

from net_proto.lib.int_checks import UINT_8__MAX
from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import Ip6DestOptsIntegrityError
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option import (
    Ip6DestOptsOptionType,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__pad1 import (
    Ip6DestOptsOptionPad1,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__tunnel_encapsulation_limit import (
    IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN,
    Ip6DestOptsOptionTunnelEncapsulationLimit,
)
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__options import (
    Ip6DestOptsOptions,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Tunnel encap limit value 0 (forbids further encap).",
            "_kwargs": {"value": 0},
            "_results": {
                "len": 3,
                "bytes": b"\x04\x01\x00",
                "value": 0,
            },
        },
        {
            "_description": "Tunnel encap limit value 4 (typical Linux default).",
            "_kwargs": {"value": 4},
            "_results": {
                "len": 3,
                "bytes": b"\x04\x01\x04",
                "value": 4,
            },
        },
        {
            "_description": "Tunnel encap limit at uint8 maximum.",
            "_kwargs": {"value": UINT_8__MAX},
            "_results": {
                "len": 3,
                "bytes": b"\x04\x01\xff",
                "value": 0xFF,
            },
        },
    ]
)
class TestIp6DestOptsOptionTunnelEncapsulationLimit(TestCase):
    """
    The IPv6 Dest Opts Tunnel Encapsulation Limit happy-path matrix.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__len(self) -> None:
        """
        Ensure the option always reports total wire length 3
        (1-byte Type + 1-byte Opt Data Len + 1-byte value).

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit option, total 3 octets).
        """

        opt = Ip6DestOptsOptionTunnelEncapsulationLimit(**self._kwargs)
        self.assertEqual(
            len(opt),
            self._results["len"],
            msg=f"Unexpected length for case: {self._description}.",
        )
        self.assertEqual(
            len(opt),
            IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN,
            msg=(
                f"Length must equal IP6_DEST_OPTS__OPTION__TUNNEL_ENCAPSULATION_LIMIT__LEN "
                f"for case: {self._description}."
            ),
        )

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__bytes(self) -> None:
        """
        Ensure the option serialises to Type=0x04, Opt Data Len=1,
        then a 1-byte value.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit wire format).
        """

        opt = Ip6DestOptsOptionTunnelEncapsulationLimit(**self._kwargs)
        self.assertEqual(
            bytes(opt),
            self._results["bytes"],
            msg=f"Unexpected bytes for case: {self._description}.",
        )

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__value(self) -> None:
        """
        Ensure the option's 'value' attribute returns the 8-bit
        tunnel encapsulation limit the caller provided.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit value).
        """

        opt = Ip6DestOptsOptionTunnelEncapsulationLimit(**self._kwargs)
        self.assertEqual(
            opt.value,
            self._results["value"],
            msg=f"Unexpected value for case: {self._description}.",
        )

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__type(self) -> None:
        """
        Ensure the option's 'type' field is the canonical
        Ip6DestOptsOptionType.TUNNEL_ENCAPSULATION_LIMIT enum
        member (0x04).

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit type 0x04).
        """

        opt = Ip6DestOptsOptionTunnelEncapsulationLimit(**self._kwargs)
        self.assertIs(
            opt.type,
            Ip6DestOptsOptionType.TUNNEL_ENCAPSULATION_LIMIT,
            msg=f"Type must be TUNNEL_ENCAPSULATION_LIMIT for case: {self._description}.",
        )

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' on the serialised bytes produces an
        instance equal to the original — round-trip identity.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit wire format).
        """

        original = Ip6DestOptsOptionTunnelEncapsulationLimit(**self._kwargs)
        recovered = Ip6DestOptsOptionTunnelEncapsulationLimit.from_buffer(bytes(original))
        self.assertEqual(
            recovered,
            original,
            msg=f"Round-trip from_buffer must equal original for case: {self._description}.",
        )


class TestIp6DestOptsOptionTunnelEncapsulationLimitAsserts(TestCase):
    """
    The Tunnel Encapsulation Limit constructor and parser-guard tests.
    """

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__rejects_negative(self) -> None:
        """
        Ensure constructing with a negative value trips the
        is_uint8 assert.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsOptionTunnelEncapsulationLimit(value=-1)

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__rejects_overflow(self) -> None:
        """
        Ensure constructing with a value above the uint8 ceiling
        trips the is_uint8 assert.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsOptionTunnelEncapsulationLimit(value=UINT_8__MAX + 1)

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__from_buffer_rejects_wrong_type(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose first byte is
        not 0x04 — the option-parser's defensive guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsOptionTunnelEncapsulationLimit.from_buffer(b"\x05\x01\x00")

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__from_buffer_rejects_truncated(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer shorter than the
        3-byte fixed wire size.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit is exactly 3 octets on the wire).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsOptionTunnelEncapsulationLimit.from_buffer(b"\x04\x01")


class TestIp6DestOptsOptionTunnelEncapsulationLimitIntegrity(TestCase):
    """
    The IPv6 Dest Opts Tunnel Encapsulation Limit 'from_buffer'
    integrity-check tests. Hostile-wire defense-in-depth — these
    inputs must raise Ip6DestOptsIntegrityError so the IPv6 chain
    walker's PacketValidationError catch can drop the frame
    cleanly. The pre-fix behaviour was a bare AssertionError that
    leaked past the catch.
    """

    def test__ip6_dest_opts__option__tunnel_encapsulation_limit__integrity__opt_data_len__wrong(self) -> None:
        """
        Ensure 'from_buffer' raises Ip6DestOptsIntegrityError when
        the wire Opt Data Len byte is not exactly 1 — the Tunnel
        Encapsulation Limit field is fixed at 8 bits.

        Reference: RFC 2473 §4.1.1 (Opt Data Len fixed at 1).
        """

        # Bytes: 0x04=type, 0x02=opt_data_len (should be 1), 2 trailing bytes.
        buffer = b"\x04\x02\x00\x00"

        with self.assertRaises(Ip6DestOptsIntegrityError) as error:
            Ip6DestOptsOptionTunnelEncapsulationLimit.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv6 Dest Opts] The IPv6 Dest Opts Tunnel Encap Limit "
                "option Opt Data Len must be 1. Got: 2"
            ),
            msg="Unexpected integrity-error message for wrong Opt Data Len.",
        )


class TestIp6DestOptsOptionsTunnelEncapsulationLimitProperty(TestCase):
    """
    The 'Ip6DestOptsOptions.tunnel_encapsulation_limit' accessor
    property tests.
    """

    def test__ip6_dest_opts__options__tunnel_encapsulation_limit__present(self) -> None:
        """
        Ensure 'tunnel_encapsulation_limit' returns the contained
        option when one is present.

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit option presence).
        """

        tel = Ip6DestOptsOptionTunnelEncapsulationLimit(value=4)
        opts = Ip6DestOptsOptions(tel, Ip6DestOptsOptionPad1())
        self.assertIs(
            opts.tunnel_encapsulation_limit,
            tel,
            msg="tunnel_encapsulation_limit property must return the contained option.",
        )

    def test__ip6_dest_opts__options__tunnel_encapsulation_limit__absent_returns_none(self) -> None:
        """
        Ensure 'tunnel_encapsulation_limit' returns None when no
        such option is present in the container.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opts = Ip6DestOptsOptions(Ip6DestOptsOptionPad1())
        self.assertIsNone(
            opts.tunnel_encapsulation_limit,
            msg="tunnel_encapsulation_limit property must return None when absent.",
        )

    def test__ip6_dest_opts__options__tunnel_encapsulation_limit__from_buffer_synthesises_typed_option(self) -> None:
        """
        Ensure 'Ip6DestOptsOptions.from_buffer' walks the TLV block
        and synthesises a typed
        'Ip6DestOptsOptionTunnelEncapsulationLimit' for the 0x04
        type byte (rather than wrapping it in
        'Ip6DestOptsOptionUnknown').

        Reference: RFC 2473 §4.1.1 (Tunnel Encap Limit type 0x04 typed dispatch).
        """

        # Wire frame (3 bytes):
        #   Byte 0 : 0x04 -> TUNNEL_ENCAPSULATION_LIMIT type
        #   Byte 1 : 0x01 -> Opt Data Len
        #   Byte 2 : 0x04 -> value=4
        opts = Ip6DestOptsOptions.from_buffer(b"\x04\x01\x04")
        tel = opts.tunnel_encapsulation_limit
        self.assertIsNotNone(
            tel,
            msg="from_buffer must synthesise a typed Tunnel Encap Limit option.",
        )
        assert tel is not None  # mypy hint
        self.assertEqual(
            tel.value,
            4,
            msg="Tunnel Encap Limit value must round-trip through Ip6DestOptsOptions.from_buffer.",
        )
