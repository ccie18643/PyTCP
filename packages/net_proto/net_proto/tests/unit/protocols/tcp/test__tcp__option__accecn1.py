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
Module contains tests for the TCP AccECN1 (kind=174) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__accecn1.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    TCP__OPTION__ACCECN1__LEN,
    UINT_24__MAX,
    UINT_24__MIN,
    TcpOptionAccecn1,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError


class TestTcpOptionAccecn1Asserts(TestCase):
    """
    The TCP AccECN1 option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the TCP AccECN1 option
        constructor so each test can override one field and trigger its
        assert.
        """

        self._kwargs: dict[str, Any] = {
            "ee0b": 0,
            "eceb": 0,
            "ee1b": 0,
        }

    def test__tcp__option__accecn1__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions that would make the
        baseline invalid.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        option = TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            len(option),
            TCP__OPTION__ACCECN1__LEN,
            msg="Default-constructed option must serialize to the 11-byte AccECN1 option.",
        )

    def test__tcp__option__accecn1__ee0b__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'ee0b' value below
        UINT_24__MIN.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self._kwargs["ee0b"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee0b' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn1__ee0b__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'ee0b' value above
        UINT_24__MAX.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self._kwargs["ee0b"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee0b' over UINT_24__MAX.",
        )

    def test__tcp__option__accecn1__eceb__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'eceb' value below
        UINT_24__MIN.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self._kwargs["eceb"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'eceb' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'eceb' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn1__eceb__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'eceb' value above
        UINT_24__MAX.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self._kwargs["eceb"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'eceb' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'eceb' over UINT_24__MAX.",
        )

    def test__tcp__option__accecn1__ee1b__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'ee1b' value below
        UINT_24__MIN.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self._kwargs["ee1b"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee1b' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn1__ee1b__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'ee1b' value above
        UINT_24__MAX.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self._kwargs["ee1b"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee1b' over UINT_24__MAX.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP AccECN1 with all-zero counters (minimum values).",
            "_kwargs": {
                "ee0b": 0,
                "eceb": 0,
                "ee1b": 0,
            },
            "_results": {
                "__str__": "accecn1 ect1=0/ce=0/ect0=0",
                "__repr__": "TcpOptionAccecn1(ee0b=0, eceb=0, ee1b=0)",
                # TCP AccECN1 wire frame (11 bytes):
                #   Byte 0     : 0xae     -> type=TcpOptionType.ACCECN1 (174)
                #   Byte 1     : 0x0b     -> len=TCP__OPTION__ACCECN1__LEN (11)
                #   Bytes 2-4  : 0x000000 -> ee1b=0   (r.ECT(1)) - first slot in AccECN1
                #   Bytes 5-7  : 0x000000 -> eceb=0   (r.CE)
                #   Bytes 8-10 : 0x000000 -> ee0b=0   (r.ECT(0)) - third slot in AccECN1
                "__bytes__": b"\xae\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            },
        },
        {
            "_description": "TCP AccECN1 with all-max counters (UINT_24 ceiling).",
            "_kwargs": {
                "ee0b": 16777215,
                "eceb": 16777215,
                "ee1b": 16777215,
            },
            "_results": {
                "__str__": "accecn1 ect1=16777215/ce=16777215/ect0=16777215",
                "__repr__": "TcpOptionAccecn1(ee0b=16777215, eceb=16777215, ee1b=16777215)",
                # TCP AccECN1 wire frame (11 bytes):
                #   Byte 0     : 0xae     -> type=TcpOptionType.ACCECN1 (174)
                #   Byte 1     : 0x0b     -> len=11
                #   Bytes 2-4  : 0xffffff -> ee1b=UINT_24__MAX
                #   Bytes 5-7  : 0xffffff -> eceb=UINT_24__MAX
                #   Bytes 8-10 : 0xffffff -> ee0b=UINT_24__MAX
                "__bytes__": b"\xae\x0b\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            },
        },
        {
            "_description": "TCP AccECN1 with distinct counter values - exercises wire reordering.",
            "_kwargs": {
                "ee0b": 0x123456,
                "eceb": 0x789ABC,
                "ee1b": 0xDEF012,
            },
            "_results": {
                "__str__": "accecn1 ect1=14610450/ce=7903932/ect0=1193046",
                "__repr__": "TcpOptionAccecn1(ee0b=1193046, eceb=7903932, ee1b=14610450)",
                # TCP AccECN1 wire frame (11 bytes):
                #   Byte 0     : 0xae     -> type=TcpOptionType.ACCECN1 (174)
                #   Byte 1     : 0x0b     -> len=11
                #   Bytes 2-4  : 0xdef012 -> ee1b=0xdef012 (r.ECT(1)) - first slot
                #   Bytes 5-7  : 0x789abc -> eceb=0x789abc (r.CE)
                #   Bytes 8-10 : 0x123456 -> ee0b=0x123456 (r.ECT(0)) - third slot
                "__bytes__": b"\xae\x0b\xde\xf0\x12\x78\x9a\xbc\x12\x34\x56",
            },
        },
    ]
)
class TestTcpOptionAccecn1Assembler(TestCase):
    """
    The TCP AccECN1 option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the TCP AccECN1 option from the parametrized kwargs.
        """

        self._option = TcpOptionAccecn1(**self._kwargs)

    def test__tcp__option__accecn1__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__ACCECN1__LEN (11 bytes).

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__ACCECN1__LEN,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.ACCECN1.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.ACCECN1,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__ACCECN1__LEN.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__ACCECN1__LEN,
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__ee0b(self) -> None:
        """
        Ensure the 'ee0b' field exposes the provided value.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            self._option.ee0b,
            self._kwargs["ee0b"],
            msg=f"Unexpected 'ee0b' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__eceb(self) -> None:
        """
        Ensure the 'eceb' field exposes the provided value.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            self._option.eceb,
            self._kwargs["eceb"],
            msg=f"Unexpected 'eceb' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__ee1b(self) -> None:
        """
        Ensure the 'ee1b' field exposes the provided value.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        self.assertEqual(
            self._option.ee1b,
            self._kwargs["ee1b"],
            msg=f"Unexpected 'ee1b' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer()' reconstructs an equal option from
        the wire bytes produced by '__bytes__()'.

        Reference: RFC 9768 §3.2.3 (AccECN1 option wire format).
        """

        decoded = TcpOptionAccecn1.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            decoded,
            self._option,
            msg=f"Round-trip decode disagrees with assembled value for case: {self._description}",
        )


class TestTcpOptionAccecn1AbbreviatedForms(TestCase):
    """
    The TCP AccECN1 abbreviated-form tests (RFC 9768 §3.2.3
    Length 8/5/2 forms in addition to the canonical Length 11).
    """

    def test__tcp__option__accecn1__construct_length_11(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn1' with all three
        byte counters yields the canonical Length=11 wire form.

        Reference: RFC 9768 §3.2.3 (Length 11: full three-counter form).
        """

        option = TcpOptionAccecn1(ee0b=0x111111, eceb=0x222222, ee1b=0x333333)
        self.assertEqual(option.len, 11, msg=f"All three counters set MUST yield len=11. Got {option.len}.")

    def test__tcp__option__accecn1__construct_length_8(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn1' with only ee1b
        and eceb (omitting ee0b) yields the Length=8 wire form
        per the §3.2.3 abbreviation rule. AccECN1 places ee1b
        first on the wire so abbreviation drops the trailing
        ee0b first.

        Reference: RFC 9768 §3.2.3 (Length 8: ee0b omitted from the tail).
        """

        option = TcpOptionAccecn1(ee1b=0x333333, eceb=0x222222)
        self.assertEqual(option.len, 8, msg=f"ee1b+eceb set, ee0b None MUST yield len=8. Got {option.len}.")
        self.assertIsNone(option.ee0b, msg="ee0b MUST be None when omitted.")

    def test__tcp__option__accecn1__construct_length_5(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn1' with only ee1b
        (omitting eceb and ee0b) yields the Length=5 wire form.

        Reference: RFC 9768 §3.2.3 (Length 5: eceb and ee0b omitted from the tail).
        """

        option = TcpOptionAccecn1(ee1b=0x333333)
        self.assertEqual(option.len, 5, msg=f"Only ee1b set MUST yield len=5. Got {option.len}.")
        self.assertIsNone(option.eceb, msg="eceb MUST be None when omitted.")
        self.assertIsNone(option.ee0b, msg="ee0b MUST be None when omitted.")

    def test__tcp__option__accecn1__construct_length_2(self) -> None:
        """
        Ensure constructing 'TcpOptionAccecn1' with no
        counters set (all default None) yields the Length=2
        empty wire form.

        Reference: RFC 9768 §3.2.3 (Length 2: empty form for option-space pressure).
        """

        option = TcpOptionAccecn1()
        self.assertEqual(option.len, 2, msg=f"No counters set MUST yield len=2. Got {option.len}.")

    def test__tcp__option__accecn1__bytes_length_8(self) -> None:
        """
        Ensure the Length=8 form serialises to exactly 8 bytes:
        1 byte kind + 1 byte length + 2 24-bit fields (ee1b +
        eceb in that wire order).

        Reference: RFC 9768 §3.2.3 Table 5 (Length 8 wire layout: EE1B, ECEB).
        """

        option = TcpOptionAccecn1(ee1b=0x333333, eceb=0x222222)
        # AccECN1 Length=8 wire frame:
        #   Byte 0    : 0xae     -> kind=ACCECN1 (174)
        #   Byte 1    : 0x08     -> len=8
        #   Bytes 2-4 : 0x333333 -> ee1b
        #   Bytes 5-7 : 0x222222 -> eceb
        self.assertEqual(
            bytes(option),
            b"\xae\x08\x33\x33\x33\x22\x22\x22",
            msg=f"AccECN1 Length=8 wire form mismatch. Got {bytes(option)!r}.",
        )

    def test__tcp__option__accecn1__bytes_length_5(self) -> None:
        """
        Ensure the Length=5 form serialises to exactly 5 bytes:
        1 byte kind + 1 byte length + 1 24-bit field (ee1b
        only, in the AccECN1 first-slot position).

        Reference: RFC 9768 §3.2.3 Table 5 (Length 5 wire layout: EE1B only).
        """

        option = TcpOptionAccecn1(ee1b=0x333333)
        # AccECN1 Length=5 wire frame:
        #   Byte 0    : 0xae     -> kind=ACCECN1 (174)
        #   Byte 1    : 0x05     -> len=5
        #   Bytes 2-4 : 0x333333 -> ee1b
        self.assertEqual(
            bytes(option),
            b"\xae\x05\x33\x33\x33",
            msg=f"AccECN1 Length=5 wire form mismatch. Got {bytes(option)!r}.",
        )

    def test__tcp__option__accecn1__bytes_length_2(self) -> None:
        """
        Ensure the Length=2 (empty) form serialises to exactly
        2 bytes.

        Reference: RFC 9768 §3.2.3 Table 5 (Length 2 wire layout: empty).
        """

        option = TcpOptionAccecn1()
        self.assertEqual(
            bytes(option),
            b"\xae\x02",
            msg=f"AccECN1 Length=2 wire form mismatch. Got {bytes(option)!r}.",
        )

    def test__tcp__option__accecn1__from_buffer_length_8(self) -> None:
        """
        Ensure 'from_buffer()' parses a Length=8 AccECN1 wire
        form, decoding ee1b and eceb (in that wire order) and
        leaving ee0b at None.

        Reference: RFC 9768 §3.2.3 (parser MUST accept abbreviated forms).
        """

        decoded = TcpOptionAccecn1.from_buffer(b"\xae\x08\xab\xcd\xef\x12\x34\x56")

        self.assertEqual(decoded.len, 8, msg=f"Parsed len MUST be 8. Got {decoded.len}.")
        self.assertEqual(decoded.ee1b, 0xABCDEF, msg=f"ee1b MUST decode to 0xabcdef. Got {decoded.ee1b!r}.")
        self.assertEqual(decoded.eceb, 0x123456, msg=f"eceb MUST decode to 0x123456. Got {decoded.eceb!r}.")
        self.assertIsNone(decoded.ee0b, msg=f"ee0b MUST be None for Length=8. Got {decoded.ee0b!r}.")

    def test__tcp__option__accecn1__from_buffer_length_5(self) -> None:
        """
        Ensure 'from_buffer()' parses a Length=5 AccECN1 wire
        form, decoding only ee1b and leaving eceb and ee0b
        at None.

        Reference: RFC 9768 §3.2.3 (parser MUST accept Length 5).
        """

        decoded = TcpOptionAccecn1.from_buffer(b"\xae\x05\xab\xcd\xef")

        self.assertEqual(decoded.len, 5, msg=f"Parsed len MUST be 5. Got {decoded.len}.")
        self.assertEqual(decoded.ee1b, 0xABCDEF, msg=f"ee1b MUST decode. Got {decoded.ee1b!r}.")
        self.assertIsNone(decoded.eceb, msg=f"eceb MUST be None. Got {decoded.eceb!r}.")
        self.assertIsNone(decoded.ee0b, msg=f"ee0b MUST be None. Got {decoded.ee0b!r}.")

    def test__tcp__option__accecn1__from_buffer_length_2(self) -> None:
        """
        Ensure 'from_buffer()' parses a Length=2 AccECN1 wire
        form (empty option), leaving all three counters at None.

        Reference: RFC 9768 §3.2.3 (parser MUST accept Length 2).
        """

        decoded = TcpOptionAccecn1.from_buffer(b"\xae\x02")

        self.assertEqual(decoded.len, 2, msg=f"Parsed len MUST be 2. Got {decoded.len}.")
        self.assertIsNone(decoded.ee1b, msg=f"ee1b MUST be None. Got {decoded.ee1b!r}.")
        self.assertIsNone(decoded.eceb, msg=f"eceb MUST be None. Got {decoded.eceb!r}.")
        self.assertIsNone(decoded.ee0b, msg=f"ee0b MUST be None. Got {decoded.ee0b!r}.")

    def test__tcp__option__accecn1__from_buffer_invalid_length_raises(self) -> None:
        """
        Ensure 'from_buffer()' raises 'TcpIntegrityError' for
        any AccECN1 wire length not in {2, 5, 8, 11}.

        Reference: RFC 9768 §3.2.3 (Length values are an enumerated set).
        """

        with self.assertRaises(TcpIntegrityError):
            TcpOptionAccecn1.from_buffer(b"\xae\x04\x00\x00\x00")
        with self.assertRaises(TcpIntegrityError):
            TcpOptionAccecn1.from_buffer(b"\xae\x09" + b"\x00" * 9)

    def test__tcp__option__accecn1__round_trip_all_lengths(self) -> None:
        """
        Ensure assemble -> bytes -> from_buffer reconstructs
        an equal AccECN1 option for each of the four supported
        wire lengths.

        Reference: RFC 9768 §3.2.3 (round-trip semantic equivalence).
        """

        for kwargs in (
            {"ee0b": 0x111, "eceb": 0x222, "ee1b": 0x333},
            {"ee1b": 0x333, "eceb": 0x222},
            {"ee1b": 0x333},
            {},
        ):
            with self.subTest(kwargs=kwargs):
                original = TcpOptionAccecn1(**kwargs)
                decoded = TcpOptionAccecn1.from_buffer(bytes(original))
                self.assertEqual(decoded, original, msg=f"Round-trip mismatch for kwargs={kwargs}.")
