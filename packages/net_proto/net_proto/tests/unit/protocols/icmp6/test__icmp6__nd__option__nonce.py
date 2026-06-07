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
Module contains tests for the ICMPv6 ND Nonce option per
RFC 3971 §5.3.2 (Nonce wire format) as referenced by RFC 7527
§4.1 (Enhanced DAD).

net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__nonce.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import Icmp6IntegrityError, Icmp6NdOptionNonce


@parameterized_class(
    [
        {
            "_description": "6-byte nonce (length=1, 8 bytes total).",
            "_kwargs": {"nonce": b"\xab\xcd\xef\x12\x34\x56"},
            "_results": {
                "__len__": 8,
                "__bytes__": (
                    # Type=14, Length=1, Nonce.
                    b"\x0e\x01\xab\xcd\xef\x12\x34\x56"
                ),
                "__str__": "nonce (0xabcdef123456)",
            },
        },
        {
            "_description": "All-zero nonce.",
            "_kwargs": {"nonce": b"\x00\x00\x00\x00\x00\x00"},
            "_results": {
                "__len__": 8,
                "__bytes__": b"\x0e\x01\x00\x00\x00\x00\x00\x00",
                "__str__": "nonce (0x000000000000)",
            },
        },
        {
            "_description": "All-ones nonce.",
            "_kwargs": {"nonce": b"\xff\xff\xff\xff\xff\xff"},
            "_results": {
                "__len__": 8,
                "__bytes__": b"\x0e\x01\xff\xff\xff\xff\xff\xff",
                "__str__": "nonce (0xffffffffffff)",
            },
        },
    ]
)
class TestIcmp6NdOptionNonceAssembler(TestCase):
    """
    The ICMPv6 ND Nonce option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the option from _kwargs.
        """

        self._option = Icmp6NdOptionNonce(**self._kwargs)

    def test__icmp6__nd__option__nonce__len(self) -> None:
        """
        Ensure '__len__' returns the on-wire byte length (8).

        Reference: RFC 3971 §5.3.2 (Nonce option byte length).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__icmp6__nd__option__nonce__bytes(self) -> None:
        """
        Ensure '__bytes__' produces the expected wire encoding.

        Reference: RFC 3971 §5.3.2 (Nonce wire format).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__icmp6__nd__option__nonce__str(self) -> None:
        """
        Ensure '__str__' produces the canonical log representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "6-byte nonce.",
            "_frame": b"\x0e\x01\xab\xcd\xef\x12\x34\x56",
            "_results": {"nonce": b"\xab\xcd\xef\x12\x34\x56"},
        },
        {
            "_description": "All-zero nonce.",
            "_frame": b"\x0e\x01\x00\x00\x00\x00\x00\x00",
            "_results": {"nonce": b"\x00\x00\x00\x00\x00\x00"},
        },
    ]
)
class TestIcmp6NdOptionNonceParser(TestCase):
    """
    The ICMPv6 ND Nonce option parser tests.
    """

    _description: str
    _frame: bytes
    _results: dict[str, Any]

    def test__icmp6__nd__option__nonce__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' decodes the wire bytes into the
        expected nonce-bytes value.

        Reference: RFC 3971 §5.3.2 (Nonce wire format).
        """

        option = Icmp6NdOptionNonce.from_buffer(self._frame)

        self.assertEqual(
            option.nonce,
            self._results["nonce"],
            msg=f"Unexpected nonce for case: {self._description}",
        )


class TestIcmp6NdOptionNonceAsserts(TestCase):
    """
    Constructor argument validation for the Nonce option.
    """

    def test__icmp6__nd__option__nonce__rejects_short_nonce(self) -> None:
        """
        Ensure the constructor rejects a nonce shorter than 6
        bytes — the option's fixed wire size requires at least
        a 6-octet nonce.

        Reference: RFC 7527 §3 (nonce-related state for DAD).
        """

        with self.assertRaises(AssertionError):
            Icmp6NdOptionNonce(nonce=b"\x00\x00\x00\x00\x00")

    def test__icmp6__nd__option__nonce__rejects_long_nonce(self) -> None:
        """
        Ensure the constructor rejects a nonce longer than 6
        bytes — multi-block nonces would require length > 1
        which Enhanced DAD does not use.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            Icmp6NdOptionNonce(nonce=b"\x00" * 7)


class TestIcmp6NdOptionNonceIntegrity(TestCase):
    """
    Integrity-check rejection cases for the Nonce option parser.
    """

    def test__icmp6__nd__option__nonce__from_buffer__zero_length_rejected(self) -> None:
        """
        Ensure a length-field of 0 is rejected — length=0 means
        a zero-byte option, which would loop the option
        dispatcher.

        Reference: RFC 3971 §5.3.2 (Length must be at least 1).
        """

        bad = b"\x0e\x00\x00\x00\x00\x00\x00\x00"

        with self.assertRaises(Icmp6IntegrityError):
            Icmp6NdOptionNonce.from_buffer(bad)
