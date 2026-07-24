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
This module contains tests for the IPv6 HBH Router Alert option.

net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__router_alert.py

ver 3.0.9
"""

from typing import Any
from unittest import TestCase

from net_proto.lib.int_checks import UINT_16__MAX
from net_proto.protocols.ip6_hbh.ip6_hbh__errors import Ip6HbhIntegrityError
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option import Ip6HbhOptionType
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__pad1 import (
    Ip6HbhOptionPad1,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__padn import (
    Ip6HbhOptionPadN,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__option__router_alert import (
    IP6_HBH__OPTION__ROUTER_ALERT__LEN,
    IP6_HBH__OPTION__ROUTER_ALERT__VALUE__ACTIVE_NETWORKS,
    IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
    IP6_HBH__OPTION__ROUTER_ALERT__VALUE__RSVP,
    Ip6HbhOptionRouterAlert,
)
from net_proto.protocols.ip6_hbh.options.ip6_hbh__options import Ip6HbhOptions
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Router Alert MLD (well-known value 0).",
            "_kwargs": {"value": IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD},
            "_results": {
                "len": 4,
                "bytes": b"\x05\x02\x00\x00",
                "value": 0,
                "str": "router-alert (MLD)",
            },
        },
        {
            "_description": "Router Alert RSVP (well-known value 1).",
            "_kwargs": {"value": IP6_HBH__OPTION__ROUTER_ALERT__VALUE__RSVP},
            "_results": {
                "len": 4,
                "bytes": b"\x05\x02\x00\x01",
                "value": 1,
                "str": "router-alert (RSVP)",
            },
        },
        {
            "_description": "Router Alert Active Networks (well-known value 2).",
            "_kwargs": {"value": IP6_HBH__OPTION__ROUTER_ALERT__VALUE__ACTIVE_NETWORKS},
            "_results": {
                "len": 4,
                "bytes": b"\x05\x02\x00\x02",
                "value": 2,
                "str": "router-alert (Active Networks)",
            },
        },
        {
            "_description": "Router Alert with non-well-known value 0x1234.",
            "_kwargs": {"value": 0x1234},
            "_results": {
                "len": 4,
                "bytes": b"\x05\x02\x12\x34",
                "value": 0x1234,
                "str": "router-alert (4660)",
            },
        },
        {
            "_description": "Router Alert with maximum uint16 value (0xFFFF).",
            "_kwargs": {"value": UINT_16__MAX},
            "_results": {
                "len": 4,
                "bytes": b"\x05\x02\xff\xff",
                "value": 0xFFFF,
                "str": "router-alert (65535)",
            },
        },
    ]
)
class TestIp6HbhOptionRouterAlert(TestCase):
    """
    The IPv6 HBH Router Alert option happy-path matrix.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6_hbh__option__router_alert__len(self) -> None:
        """
        Ensure the Router Alert option always reports total wire
        length 4 (1-byte Type + 1-byte Opt Data Len + 2-byte value).

        Reference: RFC 2711 §2 (Router Alert option format, total 4 octets).
        """

        opt = Ip6HbhOptionRouterAlert(**self._kwargs)
        self.assertEqual(
            len(opt),
            self._results["len"],
            msg=f"Unexpected Router Alert length for case: {self._description}.",
        )
        self.assertEqual(
            len(opt),
            IP6_HBH__OPTION__ROUTER_ALERT__LEN,
            msg=f"Router Alert length must equal IP6_HBH__OPTION__ROUTER_ALERT__LEN for case: {self._description}.",
        )

    def test__ip6_hbh__option__router_alert__bytes(self) -> None:
        """
        Ensure the Router Alert option serialises to Type=0x05,
        Opt Data Len=2, then a 2-byte big-endian value field.

        Reference: RFC 2711 §2 (Router Alert wire format).
        """

        opt = Ip6HbhOptionRouterAlert(**self._kwargs)
        self.assertEqual(
            bytes(opt),
            self._results["bytes"],
            msg=f"Unexpected Router Alert bytes for case: {self._description}.",
        )

    def test__ip6_hbh__option__router_alert__value(self) -> None:
        """
        Ensure the Router Alert option's 'value' attribute returns
        the 16-bit value the caller provided.

        Reference: RFC 2711 §2 (Router Alert 16-bit value).
        """

        opt = Ip6HbhOptionRouterAlert(**self._kwargs)
        self.assertEqual(
            opt.value,
            self._results["value"],
            msg=f"Unexpected Router Alert value for case: {self._description}.",
        )

    def test__ip6_hbh__option__router_alert__type(self) -> None:
        """
        Ensure the option's 'type' field is the canonical
        Ip6HbhOptionType.ROUTER_ALERT enum member (0x05).

        Reference: RFC 2711 §2 (Router Alert type 0x05).
        """

        opt = Ip6HbhOptionRouterAlert(**self._kwargs)
        self.assertIs(
            opt.type,
            Ip6HbhOptionType.ROUTER_ALERT,
            msg=f"Router Alert type must be Ip6HbhOptionType.ROUTER_ALERT for case: {self._description}.",
        )

    def test__ip6_hbh__option__router_alert__str(self) -> None:
        """
        Ensure the option's log string includes a human-readable
        value rendering: 'MLD' / 'RSVP' / 'Active Networks' for
        the well-known codes, decimal integer otherwise.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opt = Ip6HbhOptionRouterAlert(**self._kwargs)
        self.assertEqual(
            str(opt),
            self._results["str"],
            msg=f"Unexpected Router Alert __str__ for case: {self._description}.",
        )

    def test__ip6_hbh__option__router_alert__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' on the serialised bytes produces an
        instance equal to the original — round-trip identity.

        Reference: RFC 2711 §2 (Router Alert wire format).
        """

        original = Ip6HbhOptionRouterAlert(**self._kwargs)
        recovered = Ip6HbhOptionRouterAlert.from_buffer(bytes(original))
        self.assertEqual(
            recovered,
            original,
            msg=f"Round-trip from_buffer must equal original for case: {self._description}.",
        )


class TestIp6HbhOptionRouterAlertAsserts(TestCase):
    """
    The IPv6 HBH Router Alert constructor and parser-guard tests.
    """

    def test__ip6_hbh__option__router_alert__rejects_negative_value(self) -> None:
        """
        Ensure constructing with a negative value trips the
        is_uint16 assert in '__post_init__'.

        Reference: RFC 2711 §2 (value field is 16-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionRouterAlert(value=-1)

    def test__ip6_hbh__option__router_alert__rejects_overflow_value(self) -> None:
        """
        Ensure constructing with a value above the uint16 ceiling
        trips the is_uint16 assert.

        Reference: RFC 2711 §2 (value field is 16-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionRouterAlert(value=UINT_16__MAX + 1)

    def test__ip6_hbh__option__router_alert__from_buffer_rejects_wrong_type(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose first byte is
        not 0x05 — the option-parser's defensive guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionRouterAlert.from_buffer(b"\x06\x02\x00\x00")

    def test__ip6_hbh__option__router_alert__from_buffer_rejects_truncated(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer shorter than the
        4-byte fixed Router Alert size.

        Reference: RFC 2711 §2 (Router Alert is exactly 4 octets on the wire).
        """

        with self.assertRaises(AssertionError):
            Ip6HbhOptionRouterAlert.from_buffer(b"\x05\x02\x00")


class TestIp6HbhOptionRouterAlertIntegrity(TestCase):
    """
    The IPv6 HBH Router Alert 'from_buffer' integrity-check tests.
    Hostile-wire defense-in-depth — these inputs must raise
    Ip6HbhIntegrityError so the IPv6 chain walker's
    PacketValidationError catch can drop the frame cleanly. The
    pre-fix behaviour was a bare AssertionError that leaked past
    the catch.
    """

    def test__ip6_hbh__option__router_alert__integrity__opt_data_len__wrong(self) -> None:
        """
        Ensure 'from_buffer' raises Ip6HbhIntegrityError when the
        wire Opt Data Len byte is not exactly 2. RFC 2711 fixes
        the value field at 16 bits, so Opt Data Len = 2 is the
        only valid value.

        Reference: RFC 2711 §2.1 (Opt Data Len fixed at 2).
        """

        # Bytes: 0x05=type, 0x04=opt_data_len (should be 2), 4 data bytes.
        buffer = b"\x05\x04\x00\x00\x00\x00"

        with self.assertRaises(Ip6HbhIntegrityError) as error:
            Ip6HbhOptionRouterAlert.from_buffer(buffer)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv6 HBH] The IPv6 HBH Router Alert option Opt Data Len must be 2. Got: 4",
            msg="Unexpected integrity-error message for wrong Opt Data Len.",
        )


class TestIp6HbhOptionsRouterAlertProperty(TestCase):
    """
    The 'Ip6HbhOptions.router_alert' accessor property tests.
    """

    def test__ip6_hbh__options__router_alert__present(self) -> None:
        """
        Ensure 'Ip6HbhOptions.router_alert' returns the contained
        Router Alert option when one is present.

        Reference: RFC 2711 §2 (Router Alert option presence).
        """

        ra = Ip6HbhOptionRouterAlert(value=IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD)
        opts = Ip6HbhOptions(ra, Ip6HbhOptionPadN(b"\x00\x00"))
        self.assertIs(
            opts.router_alert,
            ra,
            msg="router_alert property must return the contained Router Alert option.",
        )

    def test__ip6_hbh__options__router_alert__absent_returns_none(self) -> None:
        """
        Ensure 'router_alert' returns None when no Router Alert
        option is present in the container.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opts = Ip6HbhOptions(Ip6HbhOptionPad1(), Ip6HbhOptionPadN(b"\x00\x00\x00\x00"))
        self.assertIsNone(
            opts.router_alert,
            msg="router_alert property must return None when no RA option is present.",
        )

    def test__ip6_hbh__options__router_alert__from_buffer_synthesises_typed_option(self) -> None:
        """
        Ensure 'Ip6HbhOptions.from_buffer' walks the TLV block and
        synthesises a typed 'Ip6HbhOptionRouterAlert' for the 0x05
        type byte (rather than wrapping it in 'Ip6HbhOptionUnknown').

        Reference: RFC 2711 §2 (Router Alert type 0x05 typed dispatch).
        """

        # Wire frame (4 bytes):
        #   Byte 0    : 0x05 -> ROUTER_ALERT type
        #   Byte 1    : 0x02 -> Opt Data Len
        #   Bytes 2-3 : 0x00 0x00 -> value=0 (MLD)
        opts = Ip6HbhOptions.from_buffer(b"\x05\x02\x00\x00")
        ra = opts.router_alert
        self.assertIsNotNone(
            ra,
            msg="from_buffer must synthesise a typed Router Alert option.",
        )
        assert ra is not None  # mypy hint
        self.assertEqual(
            ra.value,
            IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
            msg="Router Alert value must round-trip through Ip6HbhOptions.from_buffer.",
        )
