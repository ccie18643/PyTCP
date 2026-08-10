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
Module contains tests for the TCP AccECN0 (kind=172) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__accecn0.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TCP__OPTION__ACCECN0__LEN,
    UINT_24__MAX,
    UINT_24__MIN,
    TcpOptionAccecn0,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError
from net_proto.tests.lib.parameterized import parameterized_class


class TestTcpOptionAccecn0Asserts(TestCase):
    """
    The TCP AccECN0 option constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the TCP AccECN0 option
        constructor so each test can override one field and trigger its
        assert.
        """

        self._kwargs: dict[str, Any] = {
            "ee0b": 0,
            "eceb": 0,
            "ee1b": 0,
        }

    def test__tcp__option__accecn0__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions that would make the
        baseline invalid.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        option = TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            len(option),
            TCP__OPTION__ACCECN0__LEN,
            msg="Default-constructed option must serialize to the 11-byte AccECN0 option.",
        )

    def test__tcp__option__accecn0__ee0b__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'ee0b' value below
        UINT_24__MIN.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self._kwargs["ee0b"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee0b' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn0__ee0b__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'ee0b' value above
        UINT_24__MAX.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self._kwargs["ee0b"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee0b' over UINT_24__MAX.",
        )

    def test__tcp__option__accecn0__eceb__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'eceb' value below
        UINT_24__MIN.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self._kwargs["eceb"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'eceb' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'eceb' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn0__eceb__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'eceb' value above
        UINT_24__MAX.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self._kwargs["eceb"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'eceb' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'eceb' over UINT_24__MAX.",
        )

    def test__tcp__option__accecn0__ee1b__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'ee1b' value below
        UINT_24__MIN.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self._kwargs["ee1b"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee1b' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn0__ee1b__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'ee1b' value above
        UINT_24__MAX.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self._kwargs["ee1b"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee1b' over UINT_24__MAX.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP AccECN0 with all-zero counters (minimum values).",
            "_kwargs": {
                "ee0b": 0,
                "eceb": 0,
                "ee1b": 0,
            },
            "_results": {
                "__str__": "accecn0 ect0=0/ce=0/ect1=0",
                "__repr__": "TcpOptionAccecn0(ee0b=0, eceb=0, ee1b=0)",
                # TCP AccECN0 wire frame (11 bytes):
                #   Byte 0     : 0xac     -> type=TcpOptionType.ACCECN0 (172)
                #   Byte 1     : 0x0b     -> len=TCP__OPTION__ACCECN0__LEN (11)
                #   Bytes 2-4  : 0x000000 -> ee0b=0   (r.ECT(0))
                #   Bytes 5-7  : 0x000000 -> eceb=0   (r.CE)
                #   Bytes 8-10 : 0x000000 -> ee1b=0   (r.ECT(1))
                "__bytes__": b"\xac\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            },
        },
        {
            "_description": "TCP AccECN0 with all-max counters (UINT_24 ceiling).",
            "_kwargs": {
                "ee0b": 16777215,
                "eceb": 16777215,
                "ee1b": 16777215,
            },
            "_results": {
                "__str__": "accecn0 ect0=16777215/ce=16777215/ect1=16777215",
                "__repr__": "TcpOptionAccecn0(ee0b=16777215, eceb=16777215, ee1b=16777215)",
                # TCP AccECN0 wire frame (11 bytes):
                #   Byte 0     : 0xac     -> type=TcpOptionType.ACCECN0 (172)
                #   Byte 1     : 0x0b     -> len=11
                #   Bytes 2-4  : 0xffffff -> ee0b=16777215 (UINT_24__MAX)
                #   Bytes 5-7  : 0xffffff -> eceb=16777215
                #   Bytes 8-10 : 0xffffff -> ee1b=16777215
                "__bytes__": b"\xac\x0b\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            },
        },
        {
            "_description": "TCP AccECN0 with distinct typical counter values.",
            "_kwargs": {
                "ee0b": 0x123456,
                "eceb": 0x789ABC,
                "ee1b": 0xDEF012,
            },
            "_results": {
                "__str__": "accecn0 ect0=1193046/ce=7903932/ect1=14610450",
                "__repr__": "TcpOptionAccecn0(ee0b=1193046, eceb=7903932, ee1b=14610450)",
                # TCP AccECN0 wire frame (11 bytes):
                #   Byte 0     : 0xac     -> type=TcpOptionType.ACCECN0 (172)
                #   Byte 1     : 0x0b     -> len=11
                #   Bytes 2-4  : 0x123456 -> ee0b=0x123456 (r.ECT(0))
                #   Bytes 5-7  : 0x789abc -> eceb=0x789abc (r.CE)
                #   Bytes 8-10 : 0xdef012 -> ee1b=0xdef012 (r.ECT(1))
                "__bytes__": b"\xac\x0b\x12\x34\x56\x78\x9a\xbc\xde\xf0\x12",
            },
        },
    ]
)
class TestTcpOptionAccecn0Assembler(TestCase):
    """
    The TCP AccECN0 option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP AccECN0 option from the parametrized kwargs.
        """

        self._option = TcpOptionAccecn0(**self._kwargs)

    def test__tcp__option__accecn0__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__ACCECN0__LEN (11 bytes).

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__ACCECN0__LEN,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__accecn0__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__accecn0__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__accecn0__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__accecn0__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.ACCECN0.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.ACCECN0,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__accecn0__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__ACCECN0__LEN.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__ACCECN0__LEN,
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__tcp__option__accecn0__ee0b(self) -> None:
        """
        Ensure the 'ee0b' field exposes the provided value.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            self._option.ee0b,
            self._kwargs["ee0b"],
            msg=f"Unexpected 'ee0b' field for case: {self._description}",
        )

    def test__tcp__option__accecn0__eceb(self) -> None:
        """
        Ensure the 'eceb' field exposes the provided value.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            self._option.eceb,
            self._kwargs["eceb"],
            msg=f"Unexpected 'eceb' field for case: {self._description}",
        )

    def test__tcp__option__accecn0__ee1b(self) -> None:
        """
        Ensure the 'ee1b' field exposes the provided value.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        self.assertEqual(
            self._option.ee1b,
            self._kwargs["ee1b"],
            msg=f"Unexpected 'ee1b' field for case: {self._description}",
        )

    def test__tcp__option__accecn0__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer()' reconstructs an equal option from
        the wire bytes produced by '__bytes__()'.

        Reference: RFC 9768 §3.2.3 (AccECN0 option wire format).
        """

        decoded = TcpOptionAccecn0.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            decoded,
            self._option,
            msg=f"Round-trip decode disagrees with assembled value for case: {self._description}",
        )


class TestTcpOptionAccecn0AbbreviatedForms(TestCase):
    """
    The TCP AccECN0 abbreviated-form tests (RFC 9768 §3.2.3
    Length 8/5/2 forms in addition to the canonical Length 11).
    """

    def test__tcp__option__accecn0__construct_length_11(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn0' with all three
        byte counters yields the canonical Length=11 wire form.

        Reference: RFC 9768 §3.2.3 (Length 11: full three-counter form).
        """

        option = TcpOptionAccecn0(ee0b=0x111111, eceb=0x222222, ee1b=0x333333)
        self.assertEqual(option.len, 11, msg=f"All three counters set MUST yield len=11. Got {option.len}.")

    def test__tcp__option__accecn0__construct_length_8(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn0' with only ee0b
        and eceb (omitting ee1b) yields the Length=8 wire form
        per the §3.2.3 abbreviation rule.

        Reference: RFC 9768 §3.2.3 (Length 8: ee1b omitted from the tail).
        """

        option = TcpOptionAccecn0(ee0b=0x111111, eceb=0x222222)
        self.assertEqual(option.len, 8, msg=f"ee0b+eceb set, ee1b None MUST yield len=8. Got {option.len}.")
        self.assertIsNone(option.ee1b, msg="ee1b MUST be None when omitted.")

    def test__tcp__option__accecn0__construct_length_5(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn0' with only ee0b
        (omitting eceb and ee1b) yields the Length=5 wire form.

        Reference: RFC 9768 §3.2.3 (Length 5: eceb and ee1b omitted from the tail).
        """

        option = TcpOptionAccecn0(ee0b=0x111111)
        self.assertEqual(option.len, 5, msg=f"Only ee0b set MUST yield len=5. Got {option.len}.")
        self.assertIsNone(option.eceb, msg="eceb MUST be None when omitted.")
        self.assertIsNone(option.ee1b, msg="ee1b MUST be None when omitted.")

    def test__tcp__option__accecn0__construct_length_2(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn0' with no
        counters set (all default None) yields the Length=2
        empty wire form, used to satisfy 'an option must be
        present' under tight option-space constraints.

        Reference: RFC 9768 §3.2.3 (Length 2: empty form for option-space pressure).
        """

        option = TcpOptionAccecn0()
        self.assertEqual(option.len, 2, msg=f"No counters set MUST yield len=2. Got {option.len}.")

    def test__tcp__option__accecn0__bytes_length_8(self) -> None:
        """
        Ensure the Length=8 form serialises to exactly 8 bytes
        on the wire: 1 byte kind + 1 byte length + 2 24-bit
        fields (ee0b + eceb, dropping ee1b).

        Reference: RFC 9768 §3.2.3 Table 5 (Length 8 wire layout: EE0B, ECEB).
        """

        option = TcpOptionAccecn0(ee0b=0x111111, eceb=0x222222)
        # AccECN0 Length=8 wire frame:
        #   Byte 0    : 0xac     -> kind=ACCECN0 (172)
        #   Byte 1    : 0x08     -> len=8
        #   Bytes 2-4 : 0x111111 -> ee0b
        #   Bytes 5-7 : 0x222222 -> eceb
        self.assertEqual(
            bytes(option),
            b"\xac\x08\x11\x11\x11\x22\x22\x22",
            msg=f"AccECN0 Length=8 wire form mismatch. Got {bytes(option)!r}.",
        )

    def test__tcp__option__accecn0__bytes_length_5(self) -> None:
        """
        Ensure the Length=5 form serialises to exactly 5 bytes:
        1 byte kind + 1 byte length + 1 24-bit field (ee0b
        only).

        Reference: RFC 9768 §3.2.3 Table 5 (Length 5 wire layout: EE0B only).
        """

        option = TcpOptionAccecn0(ee0b=0x111111)
        # AccECN0 Length=5 wire frame:
        #   Byte 0    : 0xac     -> kind=ACCECN0 (172)
        #   Byte 1    : 0x05     -> len=5
        #   Bytes 2-4 : 0x111111 -> ee0b
        self.assertEqual(
            bytes(option),
            b"\xac\x05\x11\x11\x11",
            msg=f"AccECN0 Length=5 wire form mismatch. Got {bytes(option)!r}.",
        )

    def test__tcp__option__accecn0__bytes_length_2(self) -> None:
        """
        Ensure the Length=2 (empty) form serialises to exactly
        2 bytes: 1 byte kind + 1 byte length, no counters.

        Reference: RFC 9768 §3.2.3 Table 5 (Length 2 wire layout: empty).
        """

        option = TcpOptionAccecn0()
        # AccECN0 Length=2 wire frame:
        #   Byte 0 : 0xac -> kind=ACCECN0 (172)
        #   Byte 1 : 0x02 -> len=2
        self.assertEqual(
            bytes(option),
            b"\xac\x02",
            msg=f"AccECN0 Length=2 wire form mismatch. Got {bytes(option)!r}.",
        )

    def test__tcp__option__accecn0__from_buffer_length_8(self) -> None:
        """
        Ensure 'from_buffer()' parses a Length=8 wire form,
        decoding ee0b and eceb from the wire and leaving
        ee1b at None to indicate 'absent on the wire'.

        Reference: RFC 9768 §3.2.3 (parser MUST accept abbreviated forms).
        """

        # AccECN0 Length=8 wire frame: EE0B=0xabcdef, ECEB=0x123456.
        decoded = TcpOptionAccecn0.from_buffer(b"\xac\x08\xab\xcd\xef\x12\x34\x56")

        self.assertEqual(decoded.len, 8, msg=f"Parsed len MUST be 8. Got {decoded.len}.")
        self.assertEqual(decoded.ee0b, 0xABCDEF, msg=f"ee0b MUST decode to 0xabcdef. Got {decoded.ee0b!r}.")
        self.assertEqual(decoded.eceb, 0x123456, msg=f"eceb MUST decode to 0x123456. Got {decoded.eceb!r}.")
        self.assertIsNone(decoded.ee1b, msg=f"ee1b MUST be None for Length=8. Got {decoded.ee1b!r}.")

    def test__tcp__option__accecn0__from_buffer_length_5(self) -> None:
        """
        Ensure 'from_buffer()' parses a Length=5 wire form,
        decoding only ee0b and leaving eceb and ee1b at None.

        Reference: RFC 9768 §3.2.3 (parser MUST accept Length 5).
        """

        decoded = TcpOptionAccecn0.from_buffer(b"\xac\x05\xab\xcd\xef")

        self.assertEqual(decoded.len, 5, msg=f"Parsed len MUST be 5. Got {decoded.len}.")
        self.assertEqual(decoded.ee0b, 0xABCDEF, msg=f"ee0b MUST decode. Got {decoded.ee0b!r}.")
        self.assertIsNone(decoded.eceb, msg=f"eceb MUST be None for Length=5. Got {decoded.eceb!r}.")
        self.assertIsNone(decoded.ee1b, msg=f"ee1b MUST be None for Length=5. Got {decoded.ee1b!r}.")

    def test__tcp__option__accecn0__from_buffer_length_2(self) -> None:
        """
        Ensure 'from_buffer()' parses a Length=2 wire form
        (empty option), leaving all three counters at None.

        Reference: RFC 9768 §3.2.3 (parser MUST accept Length 2).
        """

        decoded = TcpOptionAccecn0.from_buffer(b"\xac\x02")

        self.assertEqual(decoded.len, 2, msg=f"Parsed len MUST be 2. Got {decoded.len}.")
        self.assertIsNone(decoded.ee0b, msg=f"ee0b MUST be None for Length=2. Got {decoded.ee0b!r}.")
        self.assertIsNone(decoded.eceb, msg=f"eceb MUST be None for Length=2. Got {decoded.eceb!r}.")
        self.assertIsNone(decoded.ee1b, msg=f"ee1b MUST be None for Length=2. Got {decoded.ee1b!r}.")

    def test__tcp__option__accecn0__from_buffer_invalid_length_raises(self) -> None:
        """
        Ensure 'from_buffer()' raises 'TcpIntegrityError' for
        any wire length not in {2, 5, 8, 11}, so off-spec
        encodings are rejected as integrity violations rather
        than silently accepted.

        Reference: RFC 9768 §3.2.3 (Length values are an enumerated set).
        """

        with self.assertRaises(TcpIntegrityError):
            TcpOptionAccecn0.from_buffer(b"\xac\x03\x00\x00")
        with self.assertRaises(TcpIntegrityError):
            TcpOptionAccecn0.from_buffer(b"\xac\x07\x00\x00\x00\x00\x00\x00\x00")
        with self.assertRaises(TcpIntegrityError):
            TcpOptionAccecn0.from_buffer(b"\xac\x0c" + b"\x00" * 12)

    def test__tcp__option__accecn0__round_trip_all_lengths(self) -> None:
        """
        Ensure assemble -> bytes -> from_buffer reconstructs
        an equal option for each of the four supported wire
        lengths.

        Reference: RFC 9768 §3.2.3 (round-trip semantic equivalence).
        """

        for kwargs in (
            {"ee0b": 0x111, "eceb": 0x222, "ee1b": 0x333},
            {"ee0b": 0x111, "eceb": 0x222},
            {"ee0b": 0x111},
            {},
        ):
            with self.subTest(kwargs=kwargs):
                original = TcpOptionAccecn0(**kwargs)
                decoded = TcpOptionAccecn0.from_buffer(bytes(original))
                self.assertEqual(decoded, original, msg=f"Round-trip mismatch for kwargs={kwargs}.")


class TestTcpOptionAccecn0IntegrityAndOrdering(TestCase):
    """
    The TCP AccECN0 option field-ordering and parser-integrity tests.
    """

    def test__tcp__option__accecn0__ordering_requires_preceding_fields(self) -> None:
        """
        Ensure setting a trailing counter while a required preceding
        counter is absent is rejected, pinning the field-presence
        ordering invariant ('and' must not relax to 'or').

        Reference: RFC 9768 §3.2.3 (a present field implies all preceding fields present).
        """

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn0(ee0b=1, ee1b=3)

        self.assertEqual(
            str(error.exception),
            "AccECN0 Length=11 (ee1b set) requires ee0b and eceb to also be set.",
            msg="Unexpected ordering-invariant assertion message for AccECN0.",
        )

    def test__tcp__option__accecn0__from_buffer_valid_len_short_buffer_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects a frame whose Length byte is a
        valid AccECN0 length (11) but exceeds the bytes actually
        provided, pinning the 'buffer[1] > len(buffer)' bound.

        Reference: RFC 9293 §3.2 (option length must not exceed the buffer).
        """

        # Length byte declares 11 octets, but only 9 are present.
        with self.assertRaises(TcpIntegrityError) as error:
            TcpOptionAccecn0.from_buffer(b"\xac\x0b" + b"\x00" * 7)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][TCP] The TCP AccECN0 option length value must be less than or "
            "equal to the length of provided bytes (9). Got: 11",
            msg="Unexpected integrity-error message for a valid-length byte over a short buffer.",
        )

    def test__tcp__option__accecn0__from_buffer_wrong_type_below_raises(self) -> None:
        """
        Ensure 'from_buffer()' asserts the kind byte equals ACCECN0
        and rejects a kind byte below it, pinning the equality check
        against a '<=' relaxation.

        Reference: RFC 9768 §3.2.3 (AccECN0 option kind).
        """

        with self.assertRaises(AssertionError):
            TcpOptionAccecn0.from_buffer(b"\x00\x02")

    def test__tcp__option__accecn0__from_buffer_wrong_type_above_raises(self) -> None:
        """
        Ensure 'from_buffer()' rejects a kind byte above ACCECN0,
        pinning the equality check against a '>=' relaxation.

        Reference: RFC 9768 §3.2.3 (AccECN0 option kind).
        """

        with self.assertRaises(AssertionError):
            TcpOptionAccecn0.from_buffer(b"\xff\x02")
