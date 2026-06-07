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
Module contains tests for the DHCPv4 Parameter Request List option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__param_req_list.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionParamReqList,
    Dhcp4OptionType,
)


class TestDhcp4OptionParamReqListAsserts(TestCase):
    """
    The DHCPv4 Parameter Request List option constructor argument assert tests.
    """

    def test__dhcp4__option__param_req_list__not_list(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'param_req_list' argument is not a list.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        value = "not a list"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'param_req_list' field must be a list. Got: {type(value)!r}",
            msg="Unexpected 'param_req_list' type assert message.",
        )

    def test__dhcp4__option__param_req_list__rejects_tuple(self) -> None:
        """
        Ensure the constructor rejects a tuple of Dhcp4OptionType values —
        only a bare list is allowed.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        value = (Dhcp4OptionType.HOST_NAME,)

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'param_req_list' field must be a list. Got: {type(value)!r}",
            msg="Unexpected 'param_req_list' type assert message for tuple.",
        )

    def test__dhcp4__option__param_req_list__contains_wrong_types(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'param_req_list' contains an element that is not a Dhcp4OptionType.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        value: list[Any] = [
            Dhcp4OptionType.HOST_NAME,
            "not an option type",
        ]

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(value)

        self.assertEqual(
            str(error.exception),
            f"The 'param_req_list' field must be a list of Dhcp4OptionType elements. "
            f"Got: {[type(element) for element in value]!r}",
            msg="Unexpected 'param_req_list' element type assert message.",
        )

    def test__dhcp4__option__param_req_list__rejects_raw_ints(self) -> None:
        """
        Ensure the constructor rejects a list of raw ints (values must be
        wrapped in Dhcp4OptionType).

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        value: list[Any] = [12, 53]

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(value)

        self.assertEqual(
            str(error.exception),
            f"The 'param_req_list' field must be a list of Dhcp4OptionType elements. "
            f"Got: {[type(element) for element in value]!r}",
            msg="Unexpected 'param_req_list' element type assert message for raw ints.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Parameter Request List option (one element).",
            "_args": [[Dhcp4OptionType.HOST_NAME]],
            "_results": {
                "__len__": 3,
                "__str__": "param_req_list ['HOST_NAME']",
                "__repr__": "Dhcp4OptionParamReqList(param_req_list=[<Dhcp4OptionType.HOST_NAME: 12>])",
                "__bytes__": (
                    # DHCPv4 Parameter Request List option [RFC 2132]
                    #   Code : 0x37 (55, Parameter Request List)
                    #   Len  : 0x01 (1 byte)
                    #   Data : 0c   (12, Host Name)
                    b"\x37\x01\x0c"
                ),
                "param_req_list": [Dhcp4OptionType.HOST_NAME],
                "type": Dhcp4OptionType.PARAM_REQ_LIST,
                "len": 3,
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (two elements).",
            "_args": [[Dhcp4OptionType.HOST_NAME, Dhcp4OptionType.MESSAGE_TYPE]],
            "_results": {
                "__len__": 4,
                "__str__": "param_req_list ['HOST_NAME', 'MESSAGE_TYPE']",
                "__repr__": (
                    "Dhcp4OptionParamReqList(param_req_list=[<Dhcp4OptionType.HOST_NAME: 12>, "
                    "<Dhcp4OptionType.MESSAGE_TYPE: 53>])"
                ),
                "__bytes__": (
                    # DHCPv4 Parameter Request List option [RFC 2132]
                    #   Code : 0x37 (55, Parameter Request List)
                    #   Len  : 0x02 (2 bytes)
                    #   Data : 0c 35   (12 Host Name, 53 Message Type)
                    b"\x37\x02\x0c\x35"
                ),
                "param_req_list": [
                    Dhcp4OptionType.HOST_NAME,
                    Dhcp4OptionType.MESSAGE_TYPE,
                ],
                "type": Dhcp4OptionType.PARAM_REQ_LIST,
                "len": 4,
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (multiple elements).",
            "_args": [
                [
                    Dhcp4OptionType.SUBNET_MASK,
                    Dhcp4OptionType.ROUTER,
                    Dhcp4OptionType.HOST_NAME,
                    Dhcp4OptionType.LEASE_TIME,
                    Dhcp4OptionType.SERVER_ID,
                ]
            ],
            "_results": {
                "__len__": 7,
                "__str__": "param_req_list ['SUBNET_MASK', 'ROUTER', 'HOST_NAME', 'LEASE_TIME', 'SERVER_ID']",
                "__repr__": (
                    "Dhcp4OptionParamReqList(param_req_list=[<Dhcp4OptionType.SUBNET_MASK: 1>, "
                    "<Dhcp4OptionType.ROUTER: 3>, <Dhcp4OptionType.HOST_NAME: 12>, "
                    "<Dhcp4OptionType.LEASE_TIME: 51>, <Dhcp4OptionType.SERVER_ID: 54>])"
                ),
                "__bytes__": (
                    # DHCPv4 Parameter Request List option [RFC 2132]
                    #   Code : 0x37 (55, Parameter Request List)
                    #   Len  : 0x05 (5 bytes)
                    #   Data : 01 03 0c 33 36
                    #          (1 Subnet Mask, 3 Router, 12 Host Name,
                    #           51 Lease Time, 54 Server ID)
                    b"\x37\x05\x01\x03\x0c\x33\x36"
                ),
                "param_req_list": [
                    Dhcp4OptionType.SUBNET_MASK,
                    Dhcp4OptionType.ROUTER,
                    Dhcp4OptionType.HOST_NAME,
                    Dhcp4OptionType.LEASE_TIME,
                    Dhcp4OptionType.SERVER_ID,
                ],
                "type": Dhcp4OptionType.PARAM_REQ_LIST,
                "len": 7,
            },
        },
    ]
)
class TestDhcp4OptionParamReqListAssembler(TestCase):
    """
    The DHCPv4 Parameter Request List option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Parameter Request List option object with
        testcase arguments.
        """

        self._option = Dhcp4OptionParamReqList(*self._args)

    def test__dhcp4__option__param_req_list__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + per-element bytes.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__field(self) -> None:
        """
        Ensure the 'param_req_list' field reflects the constructor argument.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            self._option.param_req_list,
            self._results["param_req_list"],
            msg=f"Unexpected 'param_req_list' for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__type(self) -> None:
        """
        Ensure the 'type' field is always PARAM_REQ_LIST (55).

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__len_field(self) -> None:
        """
        Ensure the 'len' field matches __len__().

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__param_req_list__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            Dhcp4OptionParamReqList.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Parameter Request List option (one element).",
            "_args": [b"\x37\x01\x0c" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME]),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (two elements).",
            "_args": [b"\x37\x02\x0c\x35" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME, Dhcp4OptionType.MESSAGE_TYPE]),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (multiple elements).",
            "_args": [b"\x37\x05\x01\x03\x0c\x33\x36" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                        Dhcp4OptionType.HOST_NAME,
                        Dhcp4OptionType.LEASE_TIME,
                        Dhcp4OptionType.SERVER_ID,
                    ]
                ),
            },
        },
    ]
)
class TestDhcp4OptionParamReqListParser(TestCase):
    """
    The DHCPv4 Parameter Request List option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__param_req_list__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        option = Dhcp4OptionParamReqList.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionParamReqListParserErrors(TestCase):
    """
    The DHCPv4 Parameter Request List option parser error tests.
    """

    def test__dhcp4__option__param_req_list__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList.from_buffer(b"\x37")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Parameter Request List option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__param_req_list__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 55.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList.from_buffer(b"\xfe\x00")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Parameter Request List option type must be {Dhcp4OptionType.PARAM_REQ_LIST!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__param_req_list__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionParamReqList.from_buffer(b"\x37\x02")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Parameter Request List option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 4",
            msg="Unexpected integrity-error message.",
        )

    def test__dhcp4__option__param_req_list__wire_len_zero_rejected(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the wire Length
        byte is 0, which violates the option's one-octet minimum-length
        contract.

        Reference: RFC 2132 §9.8 (Parameter Request List minimum length 1).
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionParamReqList.from_buffer(b"\x37\x00")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Parameter Request List option minimum length is "
            "1 octet (RFC 2132 §9.8). Got: 0",
            msg="Unexpected minimum-length integrity error message.",
        )


class TestDhcp4OptionParamReqListBounds(TestCase):
    """
    The DHCPv4 Parameter Request List option construction-time bounds tests.
    """

    def test__dhcp4__option__param_req_list__empty_list_rejected(self) -> None:
        """
        Ensure the constructor refuses an empty 'param_req_list' — the option
        carries at least one requested option code on the wire.

        Reference: RFC 2132 §9.8 (Parameter Request List minimum length 1).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList([])

        self.assertEqual(
            str(error.exception),
            "The 'param_req_list' field must carry at least 1 entry (RFC 2132 §9.8 " "minimum length 1 octet). Got: 0",
            msg="Unexpected empty-list assert message.",
        )

    def test__dhcp4__option__param_req_list__over_255_rejected(self) -> None:
        """
        Ensure the constructor refuses a list with more than 255 entries — the
        Length byte is a single octet and 256 entries would overflow it.

        Reference: RFC 2132 §9.8 (Parameter Request List length is one octet).
        """

        oversized = [Dhcp4OptionType.HOST_NAME] * 256

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(oversized)

        self.assertEqual(
            str(error.exception),
            "The 'param_req_list' field must carry at most 255 entries (RFC 2132 §9.8 "
            "length is a single octet). Got: 256",
            msg="Unexpected over-limit assert message.",
        )

    def test__dhcp4__option__param_req_list__boundary_1_entry_accepted(self) -> None:
        """
        Ensure the constructor accepts the minimum-valid length (1 entry).

        Reference: RFC 2132 §9.8 (Parameter Request List minimum length 1).
        """

        option = Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME])

        self.assertEqual(
            len(option.param_req_list),
            1,
            msg="Minimum-valid 1-entry list must be accepted at construction.",
        )

    def test__dhcp4__option__param_req_list__boundary_255_entries_accepted(self) -> None:
        """
        Ensure the constructor accepts the maximum-valid length (255 entries).

        Reference: RFC 2132 §9.8 (Parameter Request List length is one octet).
        """

        max_list = [Dhcp4OptionType.HOST_NAME] * 255
        option = Dhcp4OptionParamReqList(max_list)

        self.assertEqual(
            len(option.param_req_list),
            255,
            msg="Maximum-valid 255-entry list must be accepted at construction.",
        )


class TestDhcp4OptionParamReqListBehavior(TestCase):
    """
    The DHCPv4 Parameter Request List option behavioral tests.
    """

    def test__dhcp4__option__param_req_list__equality(self) -> None:
        """
        Ensure two options with equal 'param_req_list' compare equal.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertEqual(
            Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME]),
            Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME]),
            msg="Options with identical param_req_list must compare equal.",
        )

    def test__dhcp4__option__param_req_list__inequality(self) -> None:
        """
        Ensure two options with different 'param_req_list' compare unequal.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        self.assertNotEqual(
            Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME]),
            Dhcp4OptionParamReqList([Dhcp4OptionType.MESSAGE_TYPE]),
            msg="Options with different param_req_list must not compare equal.",
        )

    def test__dhcp4__option__param_req_list__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        option = Dhcp4OptionParamReqList([Dhcp4OptionType.HOST_NAME])

        with self.assertRaises(FrozenInstanceError):
            option.param_req_list = [Dhcp4OptionType.MESSAGE_TYPE]  # type: ignore[misc]

    def test__dhcp4__option__param_req_list__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).

        Reference: RFC 2132 §9.8 (Parameter Request List option).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionParamReqList(  # type: ignore[call-arg]
                [Dhcp4OptionType.HOST_NAME],
                type=Dhcp4OptionType.PARAM_REQ_LIST,
            )
