#!/usr/bin/env python3


############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# tests/unit/icmp4_ps.py -  Tests specific for ICMPv4 PS module.
#
# ver 3.0.0
#

from testslide import StrictMock, TestCase

from pytcp.protocols.icmp4.icmp4__base import (
    ICMP4_MESSAGE_LEN__ECHO_REPLY,
    ICMP4_MESSAGE_LEN__ECHO_REQUEST,
    ICMP4_MESSAGE_LEN__UNREACHABLE,
    Icmp4,
    Icmp4Code,
    Icmp4EchoReplyMessage,
    Icmp4EchoRequestMessage,
    Icmp4Message,
    Icmp4PortUnreachableMessage,
    Icmp4Type,
)

ICMP4_ECHO_REPLY__ID = 0x1234
ICMP4_ECHO_REPLY__SEQ = 0x5678
ICMP4_ECHO_REPLY__DATA = b"1234567890"
ICMP4_ECHO_REPLY__TEST_FRAME = (
    b"\x00\x00\x00\x00\x12\x34\x56\x78\x31\x32\x33\x34\x35\x36\x37\x38"
    b"\x39\x30"
)

ICMP4_PORT_UNREACHABLE__DATA = b"1234567890"
ICMP4_PORT_UNREACHABLE__TEST_FRAME = (
    b"\x03\x03\x00\x00\x00\x00\x00\x00\x31\x32\x33\x34\x35\x36\x37\x38"
    b"\x39\x30"
)

ICMP4_ECHO_REQUEST__ID = 0x1234
ICMP4_ECHO_REQUEST__SEQ = 0x5678
ICMP4_ECHO_REQUEST__DATA = b"1234567890"
ICMP4_ECHO_REQUEST__TEST_FRAME = (
    b"\x08\x00\x00\x00\x12\x34\x56\x78\x31\x32\x33\x34\x35\x36\x37\x38"
    b"\x39\x30"
)


class TestIcmp4(TestCase):
    """
    ICMPv4 unit test class.
    """

    class _Icmp4Init(Icmp4):
        def __init__(self, *, message: StrictMock) -> None:
            self._message = message  # type: ignore

        def __len__(self) -> int:
            raise NotImplementedError

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._mock__Icmp4Message = StrictMock(Icmp4Message)

        self._icmp4 = self._Icmp4Init(message=self._mock__Icmp4Message)

    def test__icmp4_ps____str__(self) -> None:
        """
        Verify that the '__str__()' dunder calls the same dunder
        from the carried icmp4 message.
        """

        icmp4__str = "test_log_string"

        self.mock_callable(
            target=self._mock__Icmp4Message,
            method="__str__",
        ).for_call().to_return_value(icmp4__str).and_assert_called_once()

        self.assertIs(str(self._icmp4), icmp4__str)

    def test__icmp4_ps____repr__(self) -> None:
        """
        Verify that the '__repr__()' dunder calls the same dunder
        from the carried icmp4 message.
        """

        icmp4__repr = "test_representation_string"

        self.mock_callable(
            target=self._mock__Icmp4Message,
            method="__repr__",
        ).for_call().to_return_value(icmp4__repr).and_assert_called_once()

        self.assertIs(repr(self._icmp4), icmp4__repr)

    def test__icmp4_ps____bytes__(self) -> None:
        """
        Verify that the '__bytes__()' dunder calls the same dunder
        from the carried icmp4 message.
        """

        icmp4__bytes = b"test_bytes"

        self.mock_callable(
            target=self._mock__Icmp4Message,
            method="__bytes__",
        ).for_call().to_return_value(icmp4__bytes).and_assert_called_once()

        self.assertIs(bytes(self._icmp4), icmp4__bytes)

    def test__icmp4_ps__getter__type(self) -> None:
        """
        Validate that the '_type' attribute getter provides the type
        value from carried icmp4 message.
        """

        icmp4__type = StrictMock(template=Icmp4Type)

        self.patch_attribute(
            target=self._mock__Icmp4Message,
            attribute="type",
            new_value=icmp4__type,
        )

        self.assertIs(self._icmp4.type, icmp4__type)

    def test__icmp4_ps__getter__code(self) -> None:
        """
        Validate that the '_code' attribute getter provides the code
        value from carried icmp4 message.
        """

        icmp4__code = StrictMock(template=int)

        self.patch_attribute(
            target=self._mock__Icmp4Message,
            attribute="code",
            new_value=icmp4__code,
        )

        self.assertIs(self._icmp4.code, icmp4__code)

    def test__icmp4_ps__getter__checksum(self) -> None:
        """
        Validate that the '_checksum' attribute getter provides the cksum
        value from carried icmp4 message.
        """

        icmp4__cksum = StrictMock(template=int)

        self.patch_attribute(
            target=self._mock__Icmp4Message,
            attribute="cksum",
            new_value=icmp4__cksum,
        )

        self.assertIs(self._icmp4.cksum, icmp4__cksum)

    def test__icmp4_ps__getter__message(self) -> None:
        """
        Validate that the '_message' attribute getter provides the
        carried message.
        """

        self.assertIs(self._icmp4.message, self._mock__Icmp4Message)


class TestIcmp4Message(TestCase):
    """
    ICMPv4 message unit test class.
    """

    _ICMP4__TYPE = StrictMock(template=Icmp4Type)
    _ICMP4__CODE = StrictMock(template=Icmp4Code)
    _ICMP4__CKSUM = StrictMock(template=int)

    class _Icmp4MessageInit(Icmp4Message):
        def __init__(self) -> None:
            self._type = TestIcmp4Message._ICMP4__TYPE  # type: ignore
            self._code = TestIcmp4Message._ICMP4__CODE  # type: ignore
            self._cksum = TestIcmp4Message._ICMP4__CKSUM  # type: ignore

        def __len__(self) -> int:
            raise NotImplementedError

        def __str__(self) -> str:
            raise NotImplementedError

        def __repr__(self) -> str:
            raise NotImplementedError

        def __bytes__(self) -> bytes:
            raise NotImplementedError

    def test__icmp4_message_ps__getter__type(self) -> None:
        """
        Validate that the '_type' attribute getter provides correct value.
        """

        self.assertIs(self._Icmp4MessageInit().type, self._ICMP4__TYPE)

    def test__icmp4_message_ps__getter__code(self) -> None:
        """
        Validate that the '_code' attribute getter provides correct value.
        """

        self.assertIs(self._Icmp4MessageInit().code, self._ICMP4__CODE)

    def test__icmp4_message_ps__getter__checksum(self) -> None:
        """
        Validate that the '_checksum' attribute getter provides correct value.
        """

        self.assertIs(self._Icmp4MessageInit().cksum, self._ICMP4__CKSUM)


class TestIcmp4EchoReplyMessage(TestCase):
    """
    ICMPv4 Echo Reply message unit test class.
    """

    class _Icmp4EchoReplyMessage(Icmp4EchoReplyMessage):
        def __init__(self) -> None:
            self._id = ICMP4_ECHO_REQUEST__ID
            self._seq = ICMP4_ECHO_REQUEST__SEQ
            self._data = ICMP4_ECHO_REQUEST__DATA

        def __len__(self) -> int:
            return ICMP4_MESSAGE_LEN__ECHO_REPLY + len(self._data)

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._message = self._Icmp4EchoReplyMessage()

        self._icmp4_echo_reply__id = ICMP4_ECHO_REPLY__ID
        self._icmp4_echo_reply__seq = ICMP4_ECHO_REPLY__SEQ
        self._icmp4_echo_reply__data = ICMP4_ECHO_REPLY__DATA
        self._icmp4_echo_reply__test_frame = ICMP4_ECHO_REPLY__TEST_FRAME

    def test__icmp4_echo_reply_ps____str__(self) -> None:
        """
        Verify that the '__str__()' dunder generates valid log string.
        """

        self.assertEqual(
            str(self._message),
            "ICMPv4 Echo Reply, "
            f"id {self._icmp4_echo_reply__id}, "
            f"seq {self._icmp4_echo_reply__seq}, "
            f"dlen {len(self._icmp4_echo_reply__data)}",
        )

    def test__icmp4_echo_reply_ps____repr__(self) -> None:
        """
        Verify that the '__repr__()' dunder generates valid representation string.
        """

        self.assertEqual(
            repr(self._message),
            "Icmp4EchoReplyMessage("
            f"id={self._icmp4_echo_reply__id!r}, "
            f"seq={self._icmp4_echo_reply__seq!r}, "
            f"data={self._icmp4_echo_reply__data!r})",
        )

    def test__icmp4_echo_reply_ps____bytes__(self) -> None:
        """
        Verify that the '__bytes__()' dunder generates valid raw packet.
        """

        self.assertEqual(
            bytes(self._message), self._icmp4_echo_reply__test_frame
        )

    def test__icmp4_echo_reply_ps__getter__id(self) -> None:
        """
        Validate that the '_id' attribute getter provides correct value.
        """

        self.assertIs(self._message.id, self._icmp4_echo_reply__id)

    def test__icmp4_echo_reply_ps__getter__seq(self) -> None:
        """
        Validate that the '_seq' attribute getter provides correct value.
        """

        self.assertIs(self._message.seq, self._icmp4_echo_reply__seq)

    def test__icmp4_echo_reply_ps__getter__data(self) -> None:
        """
        Validate that the '_seq' attribute getter provides correct value.
        """

        self.assertIs(self._message.data, self._icmp4_echo_reply__data)


class TestIcmp4PortUnreachableMessage(TestCase):
    """
    ICMPv4 Port Unreachable message unit test class.
    """

    class _Icmp4PortUnreachableMessage(Icmp4PortUnreachableMessage):
        def __init__(self) -> None:
            self._data = ICMP4_PORT_UNREACHABLE__DATA

        def __len__(self) -> int:
            return ICMP4_MESSAGE_LEN__UNREACHABLE + len(self._data)

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._message = self._Icmp4PortUnreachableMessage()

        self._icmp4_port_unreachable__data = ICMP4_PORT_UNREACHABLE__DATA
        self._icmp4_port_unreachable__test_frame = (
            ICMP4_PORT_UNREACHABLE__TEST_FRAME
        )

    def test__icmp4_port_unreachable_ps____str__(self) -> None:
        """
        Verify that the '__str__()' dunder generates valid log string.
        """

        self.assertEqual(
            str(self._message),
            "ICMPv4 Port Unreachable, "
            f"dlen {len(self._icmp4_port_unreachable__data)}",
        )

    def test__icmp4_port_unreachable_ps____repr__(self) -> None:
        """
        Verify that the '__repr__()' dunder generates valid representation string.
        """

        self.assertEqual(
            repr(self._message),
            "Icmp4PortUnreachableMessage("
            f"data={self._icmp4_port_unreachable__data!r})",
        )

    def test__icmp4_port_unreachable_ps____bytes__(self) -> None:
        """
        Verify that the '__bytes__()' dunder generates valid raw packet.
        """

        self.assertEqual(
            bytes(self._message), self._icmp4_port_unreachable__test_frame
        )

    def test__icmp4_port_unreachable_ps__getter__data(self) -> None:
        """
        Validate that the '_seq' attribute getter provides correct value.
        """

        self.assertIs(self._message.data, self._icmp4_port_unreachable__data)


class TestIcmp4EchoRequest(TestCase):
    """
    ICMPv4 Echo Request unit test class.
    """

    class _Icmp4EchoRequestMessage(Icmp4EchoRequestMessage):
        def __init__(self) -> None:
            self._id = ICMP4_ECHO_REQUEST__ID
            self._seq = ICMP4_ECHO_REQUEST__SEQ
            self._data = ICMP4_ECHO_REQUEST__DATA

        def __len__(self) -> int:
            return ICMP4_MESSAGE_LEN__ECHO_REQUEST + len(self._data)

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._message = self._Icmp4EchoRequestMessage()

        self._icmp4_echo_request__id = ICMP4_ECHO_REQUEST__ID
        self._icmp4_echo_request__seq = ICMP4_ECHO_REQUEST__SEQ
        self._icmp4_echo_request__data = ICMP4_ECHO_REQUEST__DATA
        self._icmp4_echo_request__test_frame = ICMP4_ECHO_REQUEST__TEST_FRAME

    def test__icmp4_echo_request_ps____str__(self) -> None:
        """
        Verify that the '__str__()' dunder generates valid log string.
        """

        self.assertEqual(
            str(self._message),
            "ICMPv4 Echo Request, "
            f"id {self._icmp4_echo_request__id}, "
            f"seq {self._icmp4_echo_request__seq}, "
            f"dlen {len(self._icmp4_echo_request__data)}",
        )

    def test__icmp4_echo_request_ps____repr__(self) -> None:
        """
        Verify that the '__repr__()' dunder generates valid representation string.
        """

        self.assertEqual(
            repr(self._message),
            "Icmp4EchoRequestMessage("
            f"id={self._icmp4_echo_request__id!r}, "
            f"seq={self._icmp4_echo_request__seq!r}, "
            f"data={self._icmp4_echo_request__data!r})",
        )

    def test__icmp4_echo_request_ps____bytes__(self) -> None:
        """
        Verify that the '__bytes__()' dunder generates valid raw packet.
        """

        self.assertEqual(
            bytes(self._message), self._icmp4_echo_request__test_frame
        )

    def test__icmp4_echo_request_ps__getter__id(self) -> None:
        """
        Validate that the '_id' attribute getter provides correct value.
        """

        self.assertIs(self._message.id, self._icmp4_echo_request__id)

    def test__icmp4_echo_request_ps__getter__seq(self) -> None:
        """
        Validate that the '_seq' attribute getter provides correct value.
        """

        self.assertIs(self._message.seq, self._icmp4_echo_request__seq)

    def test__icmp4_echo_request_ps__getter__data(self) -> None:
        """
        Validate that the '_seq' attribute getter provides correct value.
        """

        self.assertIs(self._message.data, self._icmp4_echo_request__data)
