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
This module contains tests for the IPv6 Dest Opts PadN option.

net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__option__padn.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto.protocols.ip6_dest_opts.ip6_dest_opts__errors import Ip6DestOptsIntegrityError
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option import Ip6DestOptsOptionType
from net_proto.protocols.ip6_dest_opts.options.ip6_dest_opts__option__padn import (
    Ip6DestOptsOptionPadN,
)


@parameterized_class(
    [
        {
            "_description": "PadN(0) — header only, zero data bytes.",
            "_kwargs": {"data": b""},
            "_results": {
                "len": 2,
                "bytes": b"\x01\x00",
                "str": "padN (0)",
            },
        },
        {
            "_description": "PadN(4) — typical alignment to 8-byte boundary.",
            "_kwargs": {"data": b"\x00\x00\x00\x00"},
            "_results": {
                "len": 6,
                "bytes": b"\x01\x04\x00\x00\x00\x00",
                "str": "padN (4)",
            },
        },
        {
            "_description": "PadN(253) — maximum data size (uint8 length 253 + 2-byte header = 255).",
            "_kwargs": {"data": b"\xff" * 253},
            "_results": {
                "len": 255,
                "bytes": b"\x01\xfd" + b"\xff" * 253,
                "str": "padN (253)",
            },
        },
    ]
)
class TestIp6DestOptsOptionPadN(TestCase):
    """
    The IPv6 Dest Opts PadN option happy-path matrix.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__ip6_dest_opts__option__padn__len(self) -> None:
        """
        Ensure the PadN option reports total wire length equal to
        its 2-byte header plus its data payload.

        Reference: RFC 8200 §4.2 (PadN option, Type=1, Opt Data Len=N).
        """

        opt = Ip6DestOptsOptionPadN(**self._kwargs)
        self.assertEqual(
            len(opt),
            self._results["len"],
            msg=f"Unexpected PadN length for case: {self._description}.",
        )

    def test__ip6_dest_opts__option__padn__bytes(self) -> None:
        """
        Ensure the PadN option serializes to Type byte 0x01,
        followed by the 1-byte Opt Data Len, followed by the
        opaque data payload.

        Reference: RFC 8200 §4.2 (PadN option wire format).
        """

        opt = Ip6DestOptsOptionPadN(**self._kwargs)
        self.assertEqual(
            bytes(opt),
            self._results["bytes"],
            msg=f"Unexpected PadN bytes for case: {self._description}.",
        )

    def test__ip6_dest_opts__option__padn__str(self) -> None:
        """
        Ensure the PadN option's log string reports the data length
        in parentheses (e.g. 'padN (4)').

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        opt = Ip6DestOptsOptionPadN(**self._kwargs)
        self.assertEqual(
            str(opt),
            self._results["str"],
            msg=f"Unexpected PadN __str__ for case: {self._description}.",
        )

    def test__ip6_dest_opts__option__padn__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer' on the serialized bytes produces an
        instance equal to the source — round-trip identity.

        Reference: RFC 8200 §4.2 (PadN option wire format).
        """

        original = Ip6DestOptsOptionPadN(**self._kwargs)
        recovered = Ip6DestOptsOptionPadN.from_buffer(bytes(original))
        self.assertEqual(
            recovered,
            original,
            msg=f"Round-trip from_buffer must equal original for case: {self._description}.",
        )


class TestIp6DestOptsOptionPadNAsserts(TestCase):
    """
    The IPv6 Dest Opts PadN option constructor and parser-guard tests.
    """

    def test__ip6_dest_opts__option__padn__rejects_oversize_data(self) -> None:
        """
        Ensure constructing PadN with more than 253 bytes of data
        (which would push 'len' over the uint8 ceiling 255) trips
        the 'is_uint8(self.len)' assert in '__post_init__'.

        Reference: RFC 8200 §4.2 (Opt Data Len is 8-bit unsigned).
        """

        with self.assertRaises(AssertionError):
            Ip6DestOptsOptionPadN(data=b"\x00" * 254)

    def test__ip6_dest_opts__option__padn__type_field_is_padn(self) -> None:
        """
        Ensure the PadN option's 'type' field is the canonical
        Ip6DestOptsOptionType.PADN enum member, set by the dataclass
        default.

        Reference: RFC 8200 §4.2 (PadN option type 1).
        """

        opt = Ip6DestOptsOptionPadN(data=b"\x00\x00")
        self.assertIs(
            opt.type,
            Ip6DestOptsOptionType.PADN,
            msg="PadN option type must be Ip6DestOptsOptionType.PADN.",
        )

    def test__ip6_dest_opts__option__padn__from_buffer_rejects_wrong_type(self) -> None:
        """
        Ensure 'from_buffer' rejects a buffer whose first byte is
        not the PadN type (0x01) — defensive guard at the option-
        parser boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            # Buffer claims type=PAD1 (0x00); PadN parser must reject.
            Ip6DestOptsOptionPadN.from_buffer(b"\x00\x00")

    def test__ip6_dest_opts__option__padn__from_buffer_rejects_truncated(self) -> None:
        """
        Ensure 'from_buffer' raises 'Ip6DestOptsIntegrityError' when the
        Opt Data Len declares more bytes than are available in the
        buffer — the option's wire-level integrity guarantee.

        Reference: RFC 8200 §4.2 (PadN option Opt Data Len).
        """

        # PadN frame (3 bytes, deliberately truncated):
        #   Byte 0 : 0x01 -> type=PADN
        #   Byte 1 : 0x04 -> opt_data_len=4 (claims 4 data bytes)
        #   Byte 2 : 0x00 -> only 1 data byte present
        # opt_data_len + IP6_DEST_OPTS__OPTION__LEN = 6, but len(buffer) = 3.
        with self.assertRaises(Ip6DestOptsIntegrityError):
            Ip6DestOptsOptionPadN.from_buffer(b"\x01\x04\x00")
