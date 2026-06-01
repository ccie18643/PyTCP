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
This module contains tests for the IPv6 HBH Jumbo Payload option.

net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__jumbo_payload.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.lib.int_checks import UINT_32__MAX
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import Ip6HbhOptionType
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__jumbo_payload import (
    IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN,
    IP6_HBH__OPTION__JUMBO_PAYLOAD__MIN_VALUE,
    Ip6HbhOptionJumboPayload,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    Ip6HbhOptionPad1,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions


@parameterized_class(
    [
        {
            "_description": "Jumbo Payload at the spec minimum (65536, 1 over uint16 max).",
            "_kwargs": {"value": 65536},
            "_results": {
                "len": 6,
                "bytes": b"\xc2\x04\x00\x01\x00\x00",
                "value": 65536,
            },
        },
        {
            "_description": "Jumbo Payload at a typical large value (262144).",
            "_kwargs": {"value": 262144},
            "_results": {
                "len": 6,
                "bytes": b"\xc2\x04\x00\x04\x00\x00",
                "value": 262144,
            },
        },
        {
            "_description": "Jumbo Payload at the uint32 ceiling.",
            "_kwargs": {"value": UINT_32__MAX},
            "_results": {
                "len": 6,
                "bytes": b"\xc2\x04\xff\xff\xff\xff",
                "value": 0xFFFFFFFF,
            },
        },
    ]
)
class TestIp6HbhOptionJumboPayload(TestCase):
    """
    The IPv6 HBH Jumbo Payload option happy-path matrix.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6_hbh__option__jumbo_payload__len(self) -> None:
        """
        Ensure the Jumbo Payload option always reports total wire
        length 6 (1-byte Type + 1-byte Opt Data Len + 4-byte value).

        Reference: RFC 2675 §2 (Jumbo Payload option format, total 6 octets).
        """

        opt = Ip6HbhOptionJumboPayload(**self._kwargs)
        self.assertEqual(
            len(opt),
            self._results["len"],
            msg=f"Unexpected Jumbo Payload length for case: {self._description}.",
        )
        self.assertEqual(
            len(opt),
            IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN,
            msg=f"Jumbo Payload length must equal IP6_HBH__OPTION__JUMBO_PAYLOAD__LEN for case: {self._description}.",
        )

    def test__ip6_hbh__option__jumbo_payload__bytes(self) -> None:
        """
        Ensure the Jumbo Payload option serialises to Type=0xC2,
        Opt Data Len=4, then a 4-byte big-endian Jumbo Payload Length.

        Reference: RFC 2675 §2 (Jumbo Payload wire format).
        """

        opt = Ip6HbhOptionJumboPayload(**self._kwargs)
        self.assertEqual(
            bytes(opt),
            self._results["bytes"],
            msg=f"Unexpected Jumbo Payload bytes for case: {self._description}.",
        )

    def test__ip6_hbh__option__jumbo_payload__value(self) -> None:
        """
        Ensure the Jumbo Payload option's 'value' attribute returns
        the 32-bit Jumbo Payload Length the caller provided.

        Reference: RFC 2675 §2 (Jumbo Payload Length 32-bit unsigned).
        """

        opt = Ip6HbhOptionJumboPayload(**self._kwargs)
        self.assertEqual(
            opt.value,
            self._results["value"],
            msg=f"Unexpected Jumbo Payload value for case: {self._description}.",
        )

    def test__ip6_hbh__option__jumbo_payload__type(self) -> None:
        """
        Ensure the option's 'type' field is the canonical
        Ip6HbhOptionType.JUMBO_PAYLOAD enum member (0xC2).

        Reference: RFC 2675 §2 (Jumbo Payload type 0xC2).
        """

        opt = Ip6HbhOptionJumboPayload(**self._kwargs)
        self.assertIs(
            opt.type,
            Ip6HbhOptionType.JUMBO_PAYLOAD,
            msg=f"Jumbo Payload type must be Ip6HbhOptionType.JUMBO_PAYLOAD for case: {self._description}.",
        )

    def test__ip6_hbh__option__jumbo_payload__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' on the serialised bytes produces an
        instance equal to the original — round-trip identity.

        Reference: RFC 2675 §2 (Jumbo Payload wire format).
        """

        original = Ip6HbhOptionJumboPayload(**self._kwargs)
        recovered = Ip6HbhOptionJumboPayload.from_buffer(bytes(original))
        self.assertEqual(
            recovered,
            original,
            msg=f"Round-trip from_buffer must equal original for case: {self._description}.",
        )


class TestIp6HbhOptionJumboPayloadAsserts(TestCase):
    """
    The IPv6 HBH Jumbo Payload constructor and parser-guard tests.
    """

    def test__ip6_hbh__option__jumbo_payload__rejects_below_uint16_max(self) -> None:
        """
        Ensure constructing with a value <= 65535 trips the
        '>UINT_16__MAX' assert. The Jumbo Payload option is
        defined for IPv6 packets whose payload exceeds the 16-bit
        Payload Length field; using it for smaller payloads is a
        spec violation that the receiver must report as an
        integrity failure.

        Reference: RFC 2675 §3 (Jumbo Payload Length must be > 65535).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionJumboPayload(value=65535)

    def test__ip6_hbh__option__jumbo_payload__rejects_zero(self) -> None:
        """
        Ensure constructing with value=0 trips the
        '>UINT_16__MAX' assert — value 0 has the special meaning
        "no jumbogram" and is not a valid option payload.

        Reference: RFC 2675 §3 (Jumbo Payload Length must be > 65535).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionJumboPayload(value=0)

    def test__ip6_hbh__option__jumbo_payload__minimum_accepted_value(self) -> None:
        """
        Ensure the minimum spec-valid value (UINT_16__MAX + 1 =
        65536) is accepted — boundary case so future tightening
        does not silently reject it.

        Reference: RFC 2675 §3 (Jumbo Payload Length must be > 65535).
        """

        opt = Ip6HbhOptionJumboPayload(value=IP6_HBH__OPTION__JUMBO_PAYLOAD__MIN_VALUE)
        self.assertEqual(
            opt.value,
            65536,
            msg="value=65536 (one over uint16 max) must be accepted.",
        )

    def test__ip6_hbh__option__jumbo_payload__rejects_above_uint32(self) -> None:
        """
        Ensure constructing with a value above the uint32 ceiling
        trips the is_uint32 assert — the wire field is fixed at
        32 bits.

        Reference: RFC 2675 §2 (Jumbo Payload Length 32-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionJumboPayload(value=UINT_32__MAX + 1)

    def test__ip6_hbh__option__jumbo_payload__from_buffer_rejects_wrong_type(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose first byte is
        not 0xC2 — the option-parser's defensive guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionJumboPayload.from_buffer(b"\x05\x04\x00\x01\x00\x00")

    def test__ip6_hbh__option__jumbo_payload__from_buffer_rejects_wrong_length(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose Opt Data Len
        byte is not exactly 4 — the value field is fixed at 32
        bits.

        Reference: RFC 2675 §2 (Opt Data Len fixed at 4).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionJumboPayload.from_buffer(b"\xc2\x02\x00\x01")

    def test__ip6_hbh__option__jumbo_payload__from_buffer_rejects_truncated(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer shorter than the
        6-byte fixed Jumbo Payload size.

        Reference: RFC 2675 §2 (Jumbo Payload is exactly 6 octets on the wire).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionJumboPayload.from_buffer(b"\xc2\x04\x00\x01\x00")


class TestIp6HbhOptionJumboPayloadIntegrity(TestCase):
    """
    The IPv6 HBH Jumbo Payload 'from_buffer' integrity-check tests.
    Hostile-wire defense-in-depth — these inputs must raise
    Ip6HbhIntegrityError so the IPv6 chain walker's
    PacketValidationError catch can drop the frame cleanly. The
    pre-fix behaviour was a bare AssertionError that leaked past
    the catch.
    """

    def test__ip6_hbh__option__jumbo_payload__integrity__opt_data_len__wrong(self) -> None:
        """
        Ensure 'from_buffer' raises Ip6HbhIntegrityError when the
        wire Opt Data Len byte is not exactly 4 — the Jumbo
        Payload Length field is fixed at 32 bits.

        Reference: RFC 2675 §2 (Opt Data Len fixed at 4).
        """

        # Bytes: 0xc2=type, 0x02=opt_data_len (should be 4), 4 trailing bytes.
        buffer = b"\xc2\x02\x00\x01\x00\x00"

        with self.assertRaises(Ip6HbhIntegrityError) as error:
            Ip6HbhOptionJumboPayload.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv6 HBH] The IPv6 HBH Jumbo Payload option Opt Data Len must be 4. Got: 2",
            msg="Unexpected integrity-error message for wrong Opt Data Len.",
        )

    def test__ip6_hbh__option__jumbo_payload__integrity__value__at_uint16_max(self) -> None:
        """
        Ensure 'from_buffer' raises Ip6HbhIntegrityError when the
        wire Jumbo Payload Length is exactly 65535. The value
        must be strictly greater than the uint16 ceiling — at or
        below means the standard IPv6 Payload Length field would
        have sufficed and a Jumbo Payload option carrying such a
        value is a spec violation.

        Reference: RFC 2675 §3 (Jumbo Payload Length MUST be > 65535).
        """

        # Bytes: 0xc2=type, 0x04=opt_data_len, value=65535 (RFC violation).
        buffer = b"\xc2\x04\x00\x00\xff\xff"

        with self.assertRaises(Ip6HbhIntegrityError) as error:
            Ip6HbhOptionJumboPayload.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv6 HBH] The IPv6 HBH Jumbo Payload option value "
                "must be greater than 65535 (jumbograms only — RFC 2675 §3). Got: 65535"
            ),
            msg="Unexpected integrity-error message for value at uint16 max.",
        )

    def test__ip6_hbh__option__jumbo_payload__integrity__value__zero(self) -> None:
        """
        Ensure 'from_buffer' raises Ip6HbhIntegrityError when the
        wire Jumbo Payload Length is zero — value 0 is reserved
        and not a valid jumbogram payload length.

        Reference: RFC 2675 §3 (Jumbo Payload Length MUST be > 65535).
        """

        # Bytes: 0xc2=type, 0x04=opt_data_len, value=0 (RFC violation).
        buffer = b"\xc2\x04\x00\x00\x00\x00"

        with self.assertRaises(Ip6HbhIntegrityError) as error:
            Ip6HbhOptionJumboPayload.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][IPv6 HBH] The IPv6 HBH Jumbo Payload option value "
                "must be greater than 65535 (jumbograms only — RFC 2675 §3). Got: 0"
            ),
            msg="Unexpected integrity-error message for value=0.",
        )


class TestIp6HbhOptionsJumboPayloadProperty(TestCase):
    """
    The 'Ip6HbhOptions.jumbo_payload' accessor property tests.
    """

    def test__ip6_hbh__options__jumbo_payload__present(self) -> None:
        """
        Ensure 'Ip6HbhOptions.jumbo_payload' returns the contained
        Jumbo Payload option when one is present.

        Reference: RFC 2675 §2 (Jumbo Payload option presence).
        """

        jumbo = Ip6HbhOptionJumboPayload(value=70000)
        opts = Ip6HbhOptions(jumbo)
        self.assertIs(
            opts.jumbo_payload,
            jumbo,
            msg="jumbo_payload property must return the contained Jumbo Payload option.",
        )

    def test__ip6_hbh__options__jumbo_payload__absent_returns_none(self) -> None:
        """
        Ensure 'jumbo_payload' returns None when no Jumbo Payload
        option is present in the container.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opts = Ip6HbhOptions(Ip6HbhOptionPad1())
        self.assertIsNone(
            opts.jumbo_payload,
            msg="jumbo_payload property must return None when no Jumbo Payload option is present.",
        )

    def test__ip6_hbh__options__jumbo_payload__from_buffer_synthesises_typed_option(self) -> None:
        """
        Ensure 'Ip6HbhOptions.from_buffer' walks the TLV block and
        synthesises a typed 'Ip6HbhOptionJumboPayload' for the
        0xC2 type byte (rather than wrapping it in
        'Ip6HbhOptionUnknown').

        Reference: RFC 2675 §2 (Jumbo Payload type 0xC2 typed dispatch).
        """

        # Wire frame (6 bytes):
        #   Byte 0    : 0xC2 -> JUMBO_PAYLOAD type
        #   Byte 1    : 0x04 -> Opt Data Len
        #   Bytes 2-5 : 00 04 00 00 -> value=262144
        opts = Ip6HbhOptions.from_buffer(b"\xc2\x04\x00\x04\x00\x00")
        jumbo = opts.jumbo_payload
        self.assertIsNotNone(
            jumbo,
            msg="from_buffer must synthesise a typed Jumbo Payload option.",
        )
        assert jumbo is not None  # mypy hint
        self.assertEqual(
            jumbo.value,
            262144,
            msg="Jumbo Payload value must round-trip through Ip6HbhOptions.from_buffer.",
        )
