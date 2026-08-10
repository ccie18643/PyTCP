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
Module contains tests for the TCP Fast Open (kind=34) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__fastopen.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX,
    TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN,
    TCP__OPTION__FASTOPEN__LEN_MIN,
    TcpOptionFastOpen,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError
from net_proto.tests.lib.parameterized import parameterized_class


class TestTcpOptionFastOpenAsserts(TestCase):
    """
    The TCP Fast Open option constructor argument assert tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the TCP Fast Open option
        constructor so each test can override the cookie and trigger its
        assert.
        """

        self._kwargs: dict[str, Any] = {
            "cookie": b"\xde\xad\xbe\xef",
        }

    def test__tcp__option__fastopen__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions that would make the
        baseline invalid.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        option = TcpOptionFastOpen(**self._kwargs)

        self.assertEqual(
            len(option),
            TCP__OPTION__FASTOPEN__LEN_MIN + len(self._kwargs["cookie"]),
            msg="Default-constructed option must serialize to a 6-byte (4-byte cookie) FastOpen option.",
        )

    def test__tcp__option__fastopen__empty_cookie_accepted(self) -> None:
        """
        Ensure an empty cookie (the cookie-request form) is accepted
        and yields the 2-byte option, exercising the 'cookie_len == 0'
        disjunct of the length assert.

        Reference: RFC 7413 §2 (Length 2 cookie-request form).
        """

        option = TcpOptionFastOpen(cookie=b"")

        self.assertEqual(
            option.len,
            TCP__OPTION__FASTOPEN__LEN_MIN,
            msg="An empty cookie must yield a Length=2 FastOpen option.",
        )

    def test__tcp__option__fastopen__cookie_min_len_accepted(self) -> None:
        """
        Ensure a cookie of exactly COOKIE_LEN_MIN bytes is accepted,
        pinning the inclusive lower bound of the length assert.

        Reference: RFC 7413 §2 (cookie is 4..16 bytes inclusive).
        """

        option = TcpOptionFastOpen(cookie=b"\x00" * TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN)

        self.assertEqual(
            option.len,
            TCP__OPTION__FASTOPEN__LEN_MIN + TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN,
            msg="A 4-byte cookie (COOKIE_LEN_MIN) must be accepted.",
        )

    def test__tcp__option__fastopen__cookie_max_len_accepted(self) -> None:
        """
        Ensure a cookie of exactly COOKIE_LEN_MAX bytes is accepted,
        pinning the inclusive upper bound of the length assert.

        Reference: RFC 7413 §2 (cookie is 4..16 bytes inclusive).
        """

        option = TcpOptionFastOpen(cookie=b"\x00" * TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX)

        self.assertEqual(
            option.len,
            TCP__OPTION__FASTOPEN__LEN_MIN + TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX,
            msg="A 16-byte cookie (COOKIE_LEN_MAX) must be accepted.",
        )

    def test__tcp__option__fastopen__cookie_not_bytes(self) -> None:
        """
        Ensure the constructor rejects a 'cookie' field that is not a
        'bytes' object.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self._kwargs["cookie"] = value = "deadbeef"

        with self.assertRaises(AssertionError) as error:
            TcpOptionFastOpen(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cookie' field must be 'bytes'. Got: {type(value)!r}",
            msg="Unexpected assertion message for a non-'bytes' cookie.",
        )

    def test__tcp__option__fastopen__cookie_under_min(self) -> None:
        """
        Ensure the constructor rejects a non-empty cookie shorter than
        COOKIE_LEN_MIN bytes (here 3 bytes).

        Reference: RFC 7413 §2 (cookie is 4..16 bytes inclusive).
        """

        self._kwargs["cookie"] = b"\x11\x22\x33"

        with self.assertRaises(AssertionError) as error:
            TcpOptionFastOpen(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                f"The 'cookie' field must be empty or "
                f"{TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN}..{TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX} bytes. "
                f"Got: 3 bytes."
            ),
            msg="Unexpected assertion message for a cookie under COOKIE_LEN_MIN.",
        )

    def test__tcp__option__fastopen__cookie_over_max(self) -> None:
        """
        Ensure the constructor rejects a cookie longer than
        COOKIE_LEN_MAX bytes (here 17 bytes).

        Reference: RFC 7413 §2 (cookie is 4..16 bytes inclusive).
        """

        self._kwargs["cookie"] = b"\x00" * (TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX + 1)

        with self.assertRaises(AssertionError) as error:
            TcpOptionFastOpen(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                f"The 'cookie' field must be empty or "
                f"{TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN}..{TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX} bytes. "
                f"Got: 17 bytes."
            ),
            msg="Unexpected assertion message for a cookie over COOKIE_LEN_MAX.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP FastOpen cookie-request form (empty cookie).",
            "_kwargs": {"cookie": b""},
            "_results": {
                "len": 2,
                "__str__": "fastopen request",
                "__repr__": "TcpOptionFastOpen(cookie=b'')",
                # TCP FastOpen wire frame (2 bytes, request form):
                #   Byte 0 : 0x22 -> type=TcpOptionType.FASTOPEN (34)
                #   Byte 1 : 0x02 -> len=TCP__OPTION__FASTOPEN__LEN_MIN (2)
                "__bytes__": b"\x22\x02",
            },
        },
        {
            "_description": "TCP FastOpen with a 4-byte cookie (COOKIE_LEN_MIN).",
            "_kwargs": {"cookie": b"\xde\xad\xbe\xef"},
            "_results": {
                "len": 6,
                "__str__": "fastopen deadbeef",
                "__repr__": "TcpOptionFastOpen(cookie=b'\\xde\\xad\\xbe\\xef')",
                # TCP FastOpen wire frame (6 bytes):
                #   Byte 0    : 0x22     -> type=FASTOPEN (34)
                #   Byte 1    : 0x06     -> len=6 (2 header + 4 cookie)
                #   Bytes 2-5 : 0xdeadbeef -> cookie
                "__bytes__": b"\x22\x06\xde\xad\xbe\xef",
            },
        },
        {
            "_description": "TCP FastOpen with a distinct 8-byte cookie.",
            "_kwargs": {"cookie": b"\x01\x23\x45\x67\x89\xab\xcd\xef"},
            "_results": {
                "len": 10,
                "__str__": "fastopen 0123456789abcdef",
                "__repr__": "TcpOptionFastOpen(cookie=b'\\x01#Eg\\x89\\xab\\xcd\\xef')",
                # TCP FastOpen wire frame (10 bytes):
                #   Byte 0    : 0x22 -> type=FASTOPEN (34)
                #   Byte 1    : 0x0a -> len=10 (2 header + 8 cookie)
                #   Bytes 2-9 : 0x0123456789abcdef -> cookie
                "__bytes__": b"\x22\x0a\x01\x23\x45\x67\x89\xab\xcd\xef",
            },
        },
        {
            "_description": "TCP FastOpen with a 16-byte cookie (COOKIE_LEN_MAX).",
            "_kwargs": {"cookie": bytes(range(0x10, 0x20))},
            "_results": {
                "len": 18,
                "__str__": "fastopen 101112131415161718191a1b1c1d1e1f",
                "__repr__": (
                    "TcpOptionFastOpen(cookie=b'"
                    "\\x10\\x11\\x12\\x13\\x14\\x15\\x16\\x17"
                    "\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f')"
                ),
                # TCP FastOpen wire frame (18 bytes):
                #   Byte 0     : 0x22 -> type=FASTOPEN (34)
                #   Byte 1     : 0x12 -> len=18 (2 header + 16 cookie)
                #   Bytes 2-17 : 0x101112...1f -> cookie
                "__bytes__": b"\x22\x12\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
            },
        },
    ]
)
class TestTcpOptionFastOpenAssembler(TestCase):
    """
    The TCP Fast Open option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP Fast Open option from the parametrized kwargs.
        """

        self._option = TcpOptionFastOpen(**self._kwargs)

    def test__tcp__option__fastopen__len(self) -> None:
        """
        Ensure '__len__()' returns LEN_MIN + len(cookie).

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            len(self._option),
            self._results["len"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__fastopen__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__fastopen__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__fastopen__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__fastopen__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.FASTOPEN.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.FASTOPEN,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__fastopen__length(self) -> None:
        """
        Ensure the 'len' field equals LEN_MIN + len(cookie).

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__tcp__option__fastopen__cookie(self) -> None:
        """
        Ensure the 'cookie' field exposes the provided value.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        self.assertEqual(
            self._option.cookie,
            self._kwargs["cookie"],
            msg=f"Unexpected 'cookie' field for case: {self._description}",
        )

    def test__tcp__option__fastopen__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer()' reconstructs an equal option from the
        wire bytes produced by '__bytes__()'.

        Reference: RFC 7413 §2 (Fast Open Cookie option wire format).
        """

        decoded = TcpOptionFastOpen.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            decoded,
            self._option,
            msg=f"Round-trip decode disagrees with assembled value for case: {self._description}",
        )


class TestTcpOptionFastOpenParser(TestCase):
    """
    The TCP Fast Open option parser / integrity-check tests.
    """

    def test__tcp__option__fastopen__from_buffer_request_form(self) -> None:
        """
        Ensure 'from_buffer()' parses the 2-byte cookie-request form
        into an option with an empty cookie, pinning the inclusive
        minimum length boundary.

        Reference: RFC 7413 §2 (Length 2 cookie-request form).
        """

        decoded = TcpOptionFastOpen.from_buffer(b"\x22\x02")

        self.assertEqual(decoded.len, 2, msg=f"Parsed len MUST be 2. Got {decoded.len}.")
        self.assertEqual(decoded.cookie, b"", msg=f"Request-form cookie MUST be empty. Got {decoded.cookie!r}.")

    def test__tcp__option__fastopen__from_buffer_cookie_bytes(self) -> None:
        """
        Ensure 'from_buffer()' extracts the cookie bytes from the
        slice bounded by the option's own length field, pinning the
        'cookie_len = buffer[1] - LEN_MIN' subtraction and the
        'buffer[LEN_MIN:option_len]' slice offsets.

        Reference: RFC 7413 §2 (cookie occupies octets after the header).
        """

        decoded = TcpOptionFastOpen.from_buffer(b"\x22\x06\xde\xad\xbe\xef")

        self.assertEqual(decoded.len, 6, msg=f"Parsed len MUST be 6. Got {decoded.len}.")
        self.assertEqual(
            decoded.cookie,
            b"\xde\xad\xbe\xef",
            msg=f"Cookie MUST decode to 0xdeadbeef. Got {decoded.cookie!r}.",
        )

    def test__tcp__option__fastopen__from_buffer_ignores_trailing_bytes(self) -> None:
        """
        Ensure 'from_buffer()' bounds the cookie by the option's own
        length field, not by the length of the provided buffer, so a
        trailing (next-option) byte is not absorbed into the cookie.

        Reference: RFC 7413 §2 (option length delimits the cookie).
        """

        # Buffer carries a 4-byte-cookie FastOpen option (len=6) followed
        # by a trailing 0x00 (e.g. an EOL byte of the next option).
        decoded = TcpOptionFastOpen.from_buffer(b"\x22\x06\xde\xad\xbe\xef\x00")

        self.assertEqual(decoded.len, 6, msg=f"Parsed len MUST be 6, not 7. Got {decoded.len}.")
        self.assertEqual(
            decoded.cookie,
            b"\xde\xad\xbe\xef",
            msg=f"Trailing byte MUST NOT be absorbed into the cookie. Got {decoded.cookie!r}.",
        )

    def test__tcp__option__fastopen__from_buffer_max_cookie(self) -> None:
        """
        Ensure 'from_buffer()' accepts the maximum 16-byte cookie form
        (len=18), pinning the inclusive upper cookie-length boundary.

        Reference: RFC 7413 §2 (cookie is 4..16 bytes inclusive).
        """

        frame = b"\x22\x12" + bytes(range(0x10, 0x20))
        decoded = TcpOptionFastOpen.from_buffer(frame)

        self.assertEqual(decoded.len, 18, msg=f"Parsed len MUST be 18. Got {decoded.len}.")
        self.assertEqual(
            decoded.cookie,
            bytes(range(0x10, 0x20)),
            msg=f"16-byte cookie MUST decode in full. Got {decoded.cookie!r}.",
        )

    def test__tcp__option__fastopen__integrity_length_under_min(self) -> None:
        """
        Ensure '_validate_integrity()' raises when the option length
        field is below LEN_MIN (here 1), pinning the inclusive
        minimum-length integrity bound.

        Reference: RFC 7413 §2 (option length is at least 2 octets).
        """

        with self.assertRaises(TcpIntegrityError) as error:
            TcpOptionFastOpen.from_buffer(b"\x22\x01")

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][TCP] The TCP Fast Open option length value must be at least "
                f"{TCP__OPTION__FASTOPEN__LEN_MIN} bytes. Got: 1"
            ),
            msg="Unexpected integrity-error message for a length below LEN_MIN.",
        )

    def test__tcp__option__fastopen__integrity_length_over_buffer(self) -> None:
        """
        Ensure '_validate_integrity()' raises when the option length
        field exceeds the number of bytes actually provided.

        Reference: RFC 9293 §3.2 (option length must not exceed the buffer).
        """

        # len field claims 6 octets, but only 4 are present.
        with self.assertRaises(TcpIntegrityError) as error:
            TcpOptionFastOpen.from_buffer(b"\x22\x06\x11\x22")

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][TCP] The TCP Fast Open option length value must be less than or equal "
                "to the length of provided bytes (4). Got: 6"
            ),
            msg="Unexpected integrity-error message for a length exceeding the buffer.",
        )

    def test__tcp__option__fastopen__integrity_cookie_len_under_min(self) -> None:
        """
        Ensure '_validate_integrity()' raises when the implied cookie
        length is non-zero but below COOKIE_LEN_MIN (here 3 bytes,
        len field 5).

        Reference: RFC 7413 §2 (cookie is 0 or 4..16 bytes).
        """

        with self.assertRaises(TcpIntegrityError) as error:
            TcpOptionFastOpen.from_buffer(b"\x22\x05\x11\x22\x33")

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][TCP] The TCP Fast Open option cookie length must be 0 or "
                f"{TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN}..{TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX} bytes. "
                "Got: 3"
            ),
            msg="Unexpected integrity-error message for a cookie length below COOKIE_LEN_MIN.",
        )

    def test__tcp__option__fastopen__integrity_cookie_len_over_max(self) -> None:
        """
        Ensure '_validate_integrity()' raises when the implied cookie
        length exceeds COOKIE_LEN_MAX (here 17 bytes, len field 19).

        Reference: RFC 7413 §2 (cookie is 0 or 4..16 bytes).
        """

        with self.assertRaises(TcpIntegrityError) as error:
            TcpOptionFastOpen.from_buffer(b"\x22\x13" + b"\x00" * 17)

        self.assertEqual(
            str(error.exception),
            (
                "[INTEGRITY ERROR][TCP] The TCP Fast Open option cookie length must be 0 or "
                f"{TCP__OPTION__FASTOPEN__COOKIE_LEN_MIN}..{TCP__OPTION__FASTOPEN__COOKIE_LEN_MAX} bytes. "
                "Got: 17"
            ),
            msg="Unexpected integrity-error message for a cookie length above COOKIE_LEN_MAX.",
        )

    def test__tcp__option__fastopen__from_buffer_wrong_type_below(self) -> None:
        """
        Ensure 'from_buffer()' asserts the kind byte equals FASTOPEN
        and rejects a kind byte below it, pinning the equality check
        against a '<=' relaxation.

        Reference: RFC 7413 §4 (Fast Open option kind is 34).
        """

        with self.assertRaises(AssertionError):
            TcpOptionFastOpen.from_buffer(b"\x00\x02")

    def test__tcp__option__fastopen__from_buffer_wrong_type_above(self) -> None:
        """
        Ensure 'from_buffer()' rejects a kind byte above FASTOPEN,
        pinning the equality check against a '>=' relaxation.

        Reference: RFC 7413 §4 (Fast Open option kind is 34).
        """

        with self.assertRaises(AssertionError):
            TcpOptionFastOpen.from_buffer(b"\xff\x02")

    def test__tcp__option__fastopen__from_buffer_too_short(self) -> None:
        """
        Ensure 'from_buffer()' asserts the buffer holds at least the
        2-byte option header, rejecting a 1-byte buffer.

        Reference: RFC 7413 §2 (option header is 2 octets).
        """

        with self.assertRaises(AssertionError):
            TcpOptionFastOpen.from_buffer(b"\x22")
