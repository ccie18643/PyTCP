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
Module contains tests for the ICMPv4 Parameter Problem message
constructor asserts and 'from_buffer()' invariants.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__parameter_problem__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    IP4__PAYLOAD__MAX_LEN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4MessageParameterProblem,
    Icmp4ParameterProblemCode,
)
from net_proto.protocols.icmp4.message.icmp4__message__parameter_problem import (
    ICMP4__PARAMETER_PROBLEM__LEN,
)
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN, IP4__MIN_MTU


class TestIcmp4MessageParameterProblemAsserts(TestCase):
    """
    The ICMPv4 Parameter Problem message constructor argument assert
    tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (code=POINTER_INDICATES_ERROR,
        pointer=0, no data) used as the starting point for every
        negative/positive boundary test.
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp4ParameterProblemCode.POINTER_INDICATES_ERROR,
            "pointer": 0,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp4__message__parameter_problem__code__not_Icmp4ParameterProblemCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument that is not an
        Icmp4ParameterProblemCode.

        Reference: RFC 792 (Parameter Problem codes 0-2 only).
        """

        self._kwargs["code"] = value = "not an Icmp4ParameterProblemCode"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4ParameterProblemCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp4__message__parameter_problem__pointer__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'pointer' argument below the
        8-bit unsigned minimum.

        Reference: RFC 792 (Parameter Problem pointer field is 8 bits).
        """

        self._kwargs["pointer"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'pointer' field must be an 8-bit unsigned integer. Got: {value}",
            msg="Unexpected 'pointer' lower-bound assert message.",
        )

    def test__icmp4__message__parameter_problem__pointer__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'pointer' argument above the
        8-bit unsigned maximum.

        Reference: RFC 792 (Parameter Problem pointer field is 8 bits).
        """

        self._kwargs["pointer"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'pointer' field must be an 8-bit unsigned integer. Got: {value}",
            msg="Unexpected 'pointer' upper-bound assert message.",
        )

    def test__icmp4__message__parameter_problem__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the
        16-bit unsigned minimum.

        Reference: RFC 792 (ICMP message header checksum is 16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp4__message__parameter_problem__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the
        16-bit unsigned maximum.

        Reference: RFC 792 (ICMP message header checksum is 16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp4__message__parameter_problem__data_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument whose length
        exceeds IP4__PAYLOAD__MAX_LEN minus the 8-byte Parameter Problem
        header.

        Reference: RFC 792 (Parameter Problem carries Internet header +
        first 8 octets of original datagram).
        """

        value = IP4__PAYLOAD__MAX_LEN - ICMP4__PARAMETER_PROBLEM__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP4__PAYLOAD__MAX_LEN - ICMP4__PARAMETER_PROBLEM__LEN}. "
                f"Got: {value}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp4__message__parameter_problem__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure the constructor silently truncates oversized 'data' to fit
        inside the minimum IPv4 MTU.

        Reference: RFC 1812 §4.3.2.3 (576-byte cap on ICMP error message).
        """

        cap = IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__PARAMETER_PROBLEM__LEN
        self._kwargs["data"] = b"X" * (cap + 100)

        message = Icmp4MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            len(message.data),
            cap,
            msg=f"'data' must be silently truncated to {cap} bytes.",
        )

    def test__icmp4__message__parameter_problem__all_codes_accepted(self) -> None:
        """
        Ensure the constructor accepts every defined Parameter Problem
        code: 0 (pointer indicates error), 1 (required option missing),
        2 (bad length).

        Reference: RFC 792 (Parameter Problem code 0).
        Reference: RFC 1122 §3.2.2.5 (Parameter Problem code 1 — missing option).
        Reference: RFC 1812 §5.2.7.1 (Parameter Problem code 2 — bad length).
        """

        for code in Icmp4ParameterProblemCode:
            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code)
                message = Icmp4MessageParameterProblem(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} must be accepted verbatim.",
                )


class TestIcmp4MessageParameterProblemFromBufferAsserts(TestCase):
    """
    The ICMPv4 Parameter Problem message 'from_buffer()' assert tests.
    """

    def test__icmp4__message__parameter_problem__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp4MessageParameterProblem.from_buffer()' refuses to
        parse a buffer whose first byte is not PARAMETER_PROBLEM (12).

        Reference: RFC 792 (Parameter Problem type field is 12).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageParameterProblem.from_buffer(
                # ICMPv4 (wrong type for Parameter Problem)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Pointer + unused : 0x00000000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp4Type.PARAMETER_PROBLEM: 12>. Got: <Icmp4Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp4__message__parameter_problem__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp4MessageParameterProblem.from_buffer()' accepts a
        buffer whose first byte is PARAMETER_PROBLEM (12).

        Reference: RFC 792 (Parameter Problem type field is 12).
        """

        message = Icmp4MessageParameterProblem.from_buffer(
            # ICMPv4 Parameter Problem (minimal, code=0, pointer=0)
            #   Type     : 12 (Parameter Problem)
            #   Code     : 0 (Pointer indicates error)
            #   Checksum : 0x0000
            #   Pointer  : 0
            #   Unused   : 0x000000
            b"\x0c\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp4MessageParameterProblem,
            msg="from_buffer() must return an Icmp4MessageParameterProblem instance.",
        )
