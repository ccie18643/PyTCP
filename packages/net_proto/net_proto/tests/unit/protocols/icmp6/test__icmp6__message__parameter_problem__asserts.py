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
Module contains tests for the ICMPv6 Parameter Problem message
constructor asserts and 'from_buffer()' invariants.

net_proto/tests/unit/protocols/icmp6/test__icmp6__message__parameter_problem__asserts.py

ver 3.0.9
"""

from typing import Any, override
from unittest import TestCase

from net_proto import (
    IP6__PAYLOAD__MAX_LEN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
    Icmp6MessageParameterProblem,
    Icmp6ParameterProblemCode,
)
from net_proto.protocols.icmp6.message.icmp6__message__parameter_problem import (
    ICMP6__PARAMETER_PROBLEM__LEN,
)
from net_proto.protocols.ip6.ip6__header import IP6__HEADER__LEN, IP6__MIN_MTU


class TestIcmp6MessageParameterProblemAsserts(TestCase):
    """
    The ICMPv6 Parameter Problem message constructor argument assert
    tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a valid kwargs baseline (code=ERRONEOUS_HEADER_FIELD,
        pointer=0, no data).
        """

        self._kwargs: dict[str, Any] = {
            "code": Icmp6ParameterProblemCode.ERRONEOUS_HEADER_FIELD,
            "pointer": 0,
            "cksum": 0,
            "data": b"",
        }

    def test__icmp6__message__parameter_problem__code__not_Icmp6ParameterProblemCode(self) -> None:
        """
        Ensure the constructor rejects a 'code' argument that is not an
        Icmp6ParameterProblemCode.

        Reference: RFC 4443 §3.4 (Parameter Problem codes 0-2 only).
        """

        self._kwargs["code"] = value = "not an Icmp6ParameterProblemCode"

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp6ParameterProblemCode. Got: {type(value)!r}",
            msg="Unexpected 'code' type assert message.",
        )

    def test__icmp6__message__parameter_problem__pointer__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'pointer' argument below the
        32-bit unsigned minimum.

        Reference: RFC 4443 §3.4 (Parameter Problem pointer field is
        32 bits — wider than the 8-bit ICMPv4 equivalent).
        """

        self._kwargs["pointer"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'pointer' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'pointer' lower-bound assert message.",
        )

    def test__icmp6__message__parameter_problem__pointer__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'pointer' argument above the
        32-bit unsigned maximum.

        Reference: RFC 4443 §3.4 (Parameter Problem pointer field is
        32 bits).
        """

        self._kwargs["pointer"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'pointer' field must be a 32-bit unsigned integer. Got: {value}",
            msg="Unexpected 'pointer' upper-bound assert message.",
        )

    def test__icmp6__message__parameter_problem__cksum__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument below the
        16-bit unsigned minimum.

        Reference: RFC 4443 §2.1 (ICMPv6 message header checksum is
        16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' lower-bound assert message.",
        )

    def test__icmp6__message__parameter_problem__cksum__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'cksum' argument above the
        16-bit unsigned maximum.

        Reference: RFC 4443 §2.1 (ICMPv6 message header checksum is
        16 bits).
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'cksum' upper-bound assert message.",
        )

    def test__icmp6__message__parameter_problem__data_len__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'data' argument whose length
        exceeds IP6__PAYLOAD__MAX_LEN minus the 8-byte Parameter
        Problem header.

        Reference: RFC 4443 §3.4 (Parameter Problem carries as much of
        invoking packet as fits in MIN_MTU).
        """

        value = IP6__PAYLOAD__MAX_LEN - ICMP6__PARAMETER_PROBLEM__LEN + 1
        self._kwargs["data"] = b"X" * value

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            (
                "The 'data' field length must be a 16-bit unsigned integer less than "
                f"or equal to {IP6__PAYLOAD__MAX_LEN - ICMP6__PARAMETER_PROBLEM__LEN}. "
                f"Got: {value!r}"
            ),
            msg="Unexpected 'data' length over-max assert message.",
        )

    def test__icmp6__message__parameter_problem__data_truncated_to_min_mtu(self) -> None:
        """
        Ensure the constructor silently truncates oversized 'data' to
        fit inside the IPv6 minimum MTU.

        Reference: RFC 4443 §3.4 (data field MUST NOT exceed MIN_MTU
        after IPv6 + ICMPv6 headers).
        """

        cap = IP6__MIN_MTU - IP6__HEADER__LEN - ICMP6__PARAMETER_PROBLEM__LEN
        self._kwargs["data"] = b"X" * (cap + 100)

        message = Icmp6MessageParameterProblem(**self._kwargs)

        self.assertEqual(
            len(message.data),
            cap,
            msg=f"'data' must be silently truncated to {cap} bytes.",
        )

    def test__icmp6__message__parameter_problem__all_codes_accepted(self) -> None:
        """
        Ensure the constructor accepts every defined Parameter Problem
        code: 0 (erroneous header field), 1 (unrecognized Next Header),
        2 (unrecognized IPv6 option).

        Reference: RFC 4443 §3.4 (Parameter Problem codes 0/1/2).
        """

        for code in Icmp6ParameterProblemCode:
            with self.subTest(code=code):
                kwargs = dict(self._kwargs, code=code)
                message = Icmp6MessageParameterProblem(**kwargs)
                self.assertEqual(
                    message.code,
                    code,
                    msg=f"Code {code!r} must be accepted verbatim.",
                )


class TestIcmp6MessageParameterProblemFromBufferAsserts(TestCase):
    """
    The ICMPv6 Parameter Problem message 'from_buffer()' assert tests.
    """

    def test__icmp6__message__parameter_problem__from_buffer__wrong_type(self) -> None:
        """
        Ensure 'Icmp6MessageParameterProblem.from_buffer()' refuses to
        parse a buffer whose first byte is not PARAMETER_PROBLEM (4).

        Reference: RFC 4443 §3.4 (Parameter Problem type field is 4).
        """

        with self.assertRaises(AssertionError) as error:
            Icmp6MessageParameterProblem.from_buffer(
                # ICMPv6 (wrong type for Parameter Problem)
                #   Type     : 255 (Unknown)
                #   Code     : 0
                #   Checksum : 0xff00 (ignored by from_buffer)
                #   Pointer  : 0x00000000
                b"\xff\x00\xff\x00\x00\x00\x00\x00"
            )

        self.assertEqual(
            str(error.exception),
            "The 'type' field must be <Icmp6Type.PARAMETER_PROBLEM: 4>. Got: <Icmp6Type.UNKNOWN_255: 255>",
            msg="Unexpected wrong-type assert message.",
        )

    def test__icmp6__message__parameter_problem__from_buffer__correct_type_accepted(self) -> None:
        """
        Ensure 'Icmp6MessageParameterProblem.from_buffer()' accepts a
        buffer whose first byte is PARAMETER_PROBLEM (4).

        Reference: RFC 4443 §3.4 (Parameter Problem type field is 4).
        """

        message = Icmp6MessageParameterProblem.from_buffer(
            # ICMPv6 Parameter Problem (minimal, code=0, pointer=0)
            #   Type     : 4 (Parameter Problem)
            #   Code     : 0 (Erroneous Header Field)
            #   Checksum : 0x0000
            #   Pointer  : 0x00000000
            b"\x04\x00\x00\x00\x00\x00\x00\x00"
        )

        self.assertIsInstance(
            message,
            Icmp6MessageParameterProblem,
            msg="from_buffer() must return an Icmp6MessageParameterProblem instance.",
        )
