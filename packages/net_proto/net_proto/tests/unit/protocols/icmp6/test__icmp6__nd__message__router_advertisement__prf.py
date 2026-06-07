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
Module contains tests for the ICMPv6 ND Router Advertisement Prf
(Default Router Preference) field per RFC 4191 §2.2. Prf rides
in bits 3-4 of the RA-header flags byte; the assembler / parser
pair must round-trip every encoded value (HIGH=01, MEDIUM=00,
LOW=11, RESERVED=10) without disturbing the surrounding M / O
flag bits.

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__message__router_advertisement__prf.py

ver 3.0.8
"""

from typing import Any, cast, override
from unittest import TestCase

from net_proto import (
    Icmp6Assembler,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptions,
    Icmp6NdRoutePreference,
)
from net_proto.lib.buffer import Buffer
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__router_advertisement import (
    Icmp6NdMessageRouterAdvertisement as Msg,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Prf=HIGH (01) encodes flags byte 0x08, no surrounding flags.",
            "_prf": Icmp6NdRoutePreference.HIGH,
            "_flag_m": False,
            "_flag_o": False,
            "_expected_flags_byte": 0x08,
        },
        {
            "_description": "Prf=MEDIUM (00) encodes flags byte 0x00, no surrounding flags.",
            "_prf": Icmp6NdRoutePreference.MEDIUM,
            "_flag_m": False,
            "_flag_o": False,
            "_expected_flags_byte": 0x00,
        },
        {
            "_description": "Prf=LOW (11) encodes flags byte 0x18, no surrounding flags.",
            "_prf": Icmp6NdRoutePreference.LOW,
            "_flag_m": False,
            "_flag_o": False,
            "_expected_flags_byte": 0x18,
        },
        {
            "_description": "Prf=RESERVED (10) encodes flags byte 0x10, no surrounding flags.",
            "_prf": Icmp6NdRoutePreference.RESERVED,
            "_flag_m": False,
            "_flag_o": False,
            "_expected_flags_byte": 0x10,
        },
        {
            "_description": "Prf=HIGH with M+O set: flags byte 0xc8 (M=0x80 | O=0x40 | Prf=0x08).",
            "_prf": Icmp6NdRoutePreference.HIGH,
            "_flag_m": True,
            "_flag_o": True,
            "_expected_flags_byte": 0xC8,
        },
        {
            "_description": "Prf=LOW with M set only: flags byte 0x98 (M=0x80 | Prf=0x18).",
            "_prf": Icmp6NdRoutePreference.LOW,
            "_flag_m": True,
            "_flag_o": False,
            "_expected_flags_byte": 0x98,
        },
    ]
)
class TestIcmp6NdRouterAdvertisementPrfRoundTrip(TestCase):
    """
    Per-Prf-value round-trip checks for the RA assembler /
    parser pair. The flags byte is bytes[1] of the RA wire
    body (after the 4-byte ICMP type/code/checksum prefix
    Icmp6Assembler back-patches; the assembler-emitted
    payload starts at the 'Hop Limit' byte).
    """

    _description: str
    _prf: Icmp6NdRoutePreference
    _flag_m: bool
    _flag_o: bool
    _expected_flags_byte: int

    def test__icmp6__nd__router_advertisement__prf__assembled_flags_byte(self) -> None:
        """
        Ensure the assembler packs Prf into bits 3-4 of the
        flags byte, layered correctly on top of M and O.

        Reference: RFC 4191 §2.2 (Prf wire encoding).
        """

        message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=self._flag_m,
            flag_o=self._flag_o,
            prf=self._prf,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(),
        )
        buffers: list[Buffer] = []
        Icmp6Assembler(icmp6__message=message).assemble(buffers)
        wire = b"".join(bytes(b) for b in buffers)

        # Wire layout: 0=Type, 1=Code, 2-3=Cksum, 4=HopLimit,
        # 5=Flags. The flags byte is index 5.
        self.assertEqual(
            wire[5],
            self._expected_flags_byte,
            msg=(
                f"Unexpected flags byte for case: {self._description}. "
                f"Got: 0x{wire[5]:02x}, expected: 0x{self._expected_flags_byte:02x}"
            ),
        )

    def test__icmp6__nd__router_advertisement__prf__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer' decodes the flags byte back to
        the same Prf value the assembler packed.

        Reference: RFC 4191 §2.2 (Prf wire encoding).
        """

        original = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=self._flag_m,
            flag_o=self._flag_o,
            prf=self._prf,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(),
        )
        roundtripped = cast(
            Any,
            Msg.from_buffer(bytes(memoryview(original))),
        )

        self.assertEqual(
            roundtripped.prf,
            self._prf,
            msg=f"Round-trip failed for case: {self._description}. Got: {roundtripped.prf!r}",
        )
        self.assertEqual(
            roundtripped.flag_m,
            self._flag_m,
            msg=f"flag_m corrupted by Prf packing for case: {self._description}",
        )
        self.assertEqual(
            roundtripped.flag_o,
            self._flag_o,
            msg=f"flag_o corrupted by Prf packing for case: {self._description}",
        )


class TestIcmp6NdRouterAdvertisementPrfAsserts(TestCase):
    """
    Constructor argument validation for the Prf field.
    """

    @override
    def setUp(self) -> None:
        """
        Build the default constructor kwargs.
        """

        self._kwargs: dict[str, Any] = {
            "hop": 64,
            "flag_m": False,
            "flag_o": False,
            "router_lifetime": 0,
            "reachable_time": 0,
            "retrans_timer": 0,
            "options": Icmp6NdOptions(),
        }

    def test__icmp6__nd__router_advertisement__prf__default_medium_accepted(self) -> None:
        """
        Ensure the constructor defaults 'prf' to MEDIUM when
        the caller omits the kwarg.

        Reference: RFC 4191 §2.2 (MEDIUM is the default Prf).
        """

        message = Icmp6NdMessageRouterAdvertisement(**self._kwargs)
        self.assertEqual(
            message.prf,
            Icmp6NdRoutePreference.MEDIUM,
            msg=f"Default Prf must be MEDIUM. Got: {message.prf!r}",
        )

    def test__icmp6__nd__router_advertisement__prf__not_Icmp6NdRoutePreference(self) -> None:
        """
        Ensure the constructor rejects a non-enum 'prf' value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._kwargs["prf"] = value = "not an Icmp6NdRoutePreference"

        with self.assertRaises(AssertionError) as error:
            Icmp6NdMessageRouterAdvertisement(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'prf' field must be an Icmp6NdRoutePreference. Got: {type(value)!r}",
            msg="Unexpected assertion message for non-enum Prf.",
        )

    def test__icmp6__nd__router_advertisement__prf__every_member_accepted(self) -> None:
        """
        Ensure the constructor accepts every defined
        'Icmp6NdRoutePreference' member.

        Reference: RFC 4191 §2.2 (full Prf encoding range).
        """

        for prf in (
            Icmp6NdRoutePreference.HIGH,
            Icmp6NdRoutePreference.MEDIUM,
            Icmp6NdRoutePreference.LOW,
            Icmp6NdRoutePreference.RESERVED,
        ):
            with self.subTest(prf=prf):
                kwargs = dict(self._kwargs)
                kwargs["prf"] = prf
                message = Icmp6NdMessageRouterAdvertisement(**kwargs)
                self.assertEqual(
                    message.prf,
                    prf,
                    msg=f"Constructor must round-trip Prf={prf!r}",
                )
