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
# tests/unit/icmp4_fpa.py -  Tests specific for ICMPv4 FPA module.
#
# ver 3.0.0
#

from testslide import StrictMock, TestCase

from pytcp.lib.tracker import Tracker
from pytcp.protocols.icmp4.icmp4__assembler import (
    Icmp4Assembler,
    Icmp4EchoReplyMessageAssembler,
    Icmp4EchoRequestMessageAssembler,
    Icmp4PortUnreachableMessageAssembler,
)
from pytcp.protocols.icmp4.icmp4__base import (
    ICMP4_MESSAGE_LEN__ECHO_REPLY,
    ICMP4_MESSAGE_LEN__ECHO_REQUEST,
    ICMP4_MESSAGE_LEN__UNREACHABLE,
    Icmp4Message,
)
from pytcp.protocols.ip4.ip4__base import IP4__HEADER__LEN
from tests.unit.protocols__icmp4__ps import (
    ICMP4_ECHO_REPLY__DATA,
    ICMP4_ECHO_REPLY__ID,
    ICMP4_ECHO_REPLY__SEQ,
    ICMP4_ECHO_REQUEST__DATA,
    ICMP4_ECHO_REQUEST__ID,
    ICMP4_ECHO_REQUEST__SEQ,
    ICMP4_PORT_UNREACHABLE__DATA,
)


class TestIcmp4Assembler(TestCase):
    """
    ICMPv4 Assembler unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._mock__Icmp4Message = StrictMock(template=Icmp4Message)
        self._mock__Tracker = StrictMock(template=Tracker)

        self._packet = Icmp4Assembler(
            message=self._mock__Icmp4Message,  # type: ignore
            echo_tracker=self._mock__Tracker,  # type: ignore
        )

    def test__icmp4_fpa____init__(self) -> None:
        """
        Validate that the class constructor creates packet matching
        provided arguments.
        """

        self.assertIs(self._packet._message, self._mock__Icmp4Message)

    def test__icmp4_fpa____len__(self) -> None:
        """
        Verify that the '__len__()' dunder executes the same dunder
        the carried from message.
        """

        packet_len = 123

        self.mock_callable(
            target=self._mock__Icmp4Message,
            method="__len__",
        ).for_call().to_return_value(packet_len).and_assert_called_once()

        self.assertEqual(len(self._packet), packet_len)

    def test__icmp4_fpa__tracker(self) -> None:
        """
        Validate that the '_tracker' attribute getter provides correct value.
        """

        # TODO: Add test.

    def test__icmp4_fpa__assemble(self) -> None:
        """
        Validate that the 'assemble()' method behaves properly.
        """

        # TODO: Add test.


class TestIcmp4EchoReplyMessageAssembler(TestCase):
    """
    ICMPv4 Echo Reply assembler unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._icmp4__id = ICMP4_ECHO_REPLY__ID
        self._icmp4__seq = ICMP4_ECHO_REPLY__SEQ
        self._icmp4__data = ICMP4_ECHO_REPLY__DATA

    def test__icmp4_echo_reply_fpa____init__(self) -> None:
        """
        Validate that the class constructor creates packet matching
        provided arguments.
        """

        message = Icmp4EchoReplyMessageAssembler(
            id=self._icmp4__id,
            seq=self._icmp4__seq,
            data=self._icmp4__data,
        )

        self.assertEqual(message._id, self._icmp4__id)
        self.assertEqual(message._seq, self._icmp4__seq)
        self.assertEqual(message._data, self._icmp4__data)

    def test__icmp4_echo_reply_fpa____init____defaults(self) -> None:
        """
        Validate that the class constructor creates packet matching
        default arguments.
        """

        message = Icmp4EchoReplyMessageAssembler()

        self.assertEqual(message._id, 0)
        self.assertEqual(message._seq, 0)
        self.assertEqual(message._data, b"")

    def test__icmp4_echo_reply_fpa____init____assert_id__under(
        self,
    ) -> None:
        """
        Validate the assertion when the 'id' argument is below
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoReplyMessageAssembler(
                id=0x0000 - 1,
            )

    def test__icmp4_echo_reply_fpa____init____assert_id__over(
        self,
    ) -> None:
        """
        Validate the assertion when the 'id' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoReplyMessageAssembler(
                id=0xFFFF + 1,
            )

    def test__icmp4_echo_reply_fpa____init____assert_seq__under(
        self,
    ) -> None:
        """
        Validate the assertion when the 'seq' argument is below
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoReplyMessageAssembler(
                seq=0x0000 - 1,
            )

    def test__icmp4_echo_reply_fpa____init____assert_seq__over(
        self,
    ) -> None:
        """
        Validate the assertion when the 'seq' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoReplyMessageAssembler(
                seq=0xFFFF + 1,
            )

    def test__icmp4_echo_reply_fpa____init____assert_data_len__over(
        self,
    ) -> None:
        """
        Validate the assertion when the length of 'data' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoReplyMessageAssembler(
                data=b"X"
                * (0xFFFF - IP4__HEADER__LEN - ICMP4_MESSAGE_LEN__ECHO_REPLY)
                + b"Y",
            )


class TestIcmp4PortUnreachableMessageAssembler(TestCase):
    """
    ICMPv4 Port Unreachable assembler unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._icmp4__data = ICMP4_PORT_UNREACHABLE__DATA

    def test__icmp4_port_unrechable_fpa____init__(self) -> None:
        """
        Validate that the class constructor creates packet matching
        provided arguments.
        """

        message = Icmp4PortUnreachableMessageAssembler(
            data=self._icmp4__data,
        )

        self.assertEqual(message._reserved, 0)
        self.assertEqual(message._data, self._icmp4__data)

    def test__icmp4_port_unreachable_fpa____init____defaults(self) -> None:
        """
        Validate that the class constructor creates packet matching
        default arguments.
        """

        message = Icmp4PortUnreachableMessageAssembler()

        self.assertEqual(message._reserved, 0)
        self.assertEqual(message._data, b"")

    def test__icmp4_echo_reply_fpa____init____assert_data_len__over(
        self,
    ) -> None:
        """
        Validate the assertion when the length of 'data' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4PortUnreachableMessageAssembler(
                data=b"X"
                * (0xFFFF - IP4__HEADER__LEN - ICMP4_MESSAGE_LEN__UNREACHABLE)
                + b"Y",
            )


class TestIcmp4EchoRequestMessageAssembler(TestCase):
    """
    ICMPv4 Echo Request assembler unit test class.
    """

    def setUp(self) -> None:
        """
        Set up the test environment.
        """

        super().setUp()

        self._icmp4__id = ICMP4_ECHO_REQUEST__ID
        self._icmp4__seq = ICMP4_ECHO_REQUEST__SEQ
        self._icmp4__data = ICMP4_ECHO_REQUEST__DATA

    def test__icmp4_echo_request_fpa____init____defaults(self) -> None:
        """
        Validate that the class constructor creates packet matching
        default arguments.
        """

        message = Icmp4EchoRequestMessageAssembler()

        self.assertEqual(message._id, 0)
        self.assertEqual(message._seq, 0)
        self.assertEqual(message._data, b"")

    def test__icmp4_echo_request_fpa____init__(self) -> None:
        """
        Validate that the class constructor creates packet matching
        provided arguments.
        """

        message = Icmp4EchoRequestMessageAssembler(
            id=self._icmp4__id,
            seq=self._icmp4__seq,
            data=self._icmp4__data,
        )

        self.assertEqual(message._id, self._icmp4__id)
        self.assertEqual(message._seq, self._icmp4__seq)
        self.assertEqual(message._data, self._icmp4__data)

    def test__icmp4_echo_request_fpa____init____assert_id__under(
        self,
    ) -> None:
        """
        Validate the assertion when the 'id' argument is below
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoRequestMessageAssembler(
                id=0x0000 - 1,
            )

    def test__icmp4_echo_request_fpa____init____assert_id__over(
        self,
    ) -> None:
        """
        Validate the assertion when the 'id' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoRequestMessageAssembler(
                id=0xFFFF + 1,
            )

    def test__icmp4_echo_request_fpa____init____assert_seq__under(
        self,
    ) -> None:
        """
        Validate the assertion when the 'seq' argument is below
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoRequestMessageAssembler(
                seq=0x0000 - 1,
            )

    def test__icmp4_echo_request_fpa____init____assert_seq__over(
        self,
    ) -> None:
        """
        Validate the assertion when the 'seq' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoRequestMessageAssembler(
                seq=0xFFFF + 1,
            )

    def test__icmp4_echo_request_fpa____init____assert_data_len__over(
        self,
    ) -> None:
        """
        Validate the assertion when the length of 'data' argument is over
        acceptable range.
        """

        with self.assertRaises(AssertionError):
            Icmp4EchoRequestMessageAssembler(
                data=b"X"
                * (0xFFFF - IP4__HEADER__LEN - ICMP4_MESSAGE_LEN__ECHO_REQUEST)
                + b"Y",
            )


'''
class TestIcmp4Assembler(TestCase):
    """
    ICMPv4 Assembler unit test class.
    """

    def test_icmp4_fpa__ip4_proto_icmp4(self) -> None:
        """
        Make sure the 'Icmp4Assembler' class has the proper 'ip4_proto' set.
        """
        self.assertEqual(Icmp4Assembler.ip4_proto, IP4_PROTO_ICMP4)

    def test_icmp4_fpa____init____echo_request(self) -> None:
        """
        Test the packet constructor for the 'Echo Request' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoRequestMessageAssembler(
                id=12345,
                seq=54321,
                data=b"0123456789ABCDEF",
            ),
            echo_tracker=Tracker(prefix="TX"),
        )
        assert isinstance(packet.message, Icmp4EchoRequestMessage)
        self.assertEqual(packet.message.id, 12345)
        self.assertEqual(packet.message.seq, 54321)
        self.assertEqual(packet.message.data, b"0123456789ABCDEF")
        self.assertTrue(
            repr(packet.tracker._echo_tracker).startswith(
                "Tracker(serial='<lr>TX"
            )
        )

    def test_icmp4_fpa____init____echo_request__assert_ec_seq__under(
        self,
    ) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Icmp4Assembler(
                message=Icmp4EchoRequestMessageAssembler(
                    seq=-1,
                ),
            )

    def test_icmp4_fpa____init____echo_request__assert_ec_seq__over(
        self,
    ) -> None:
        """
        Test assertion for the 'seq' argument.
        """
        with self.assertRaises(AssertionError):
            Icmp4Assembler(
                message=Icmp4EchoRequestMessageAssembler(
                    seq=0x10000,
                ),
            )

    def test_icmp4_fpa____init____unreachable_port(self) -> None:
        """
        Test packet constructor for the 'Unreachable Port' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4PortUnreachableMessageAssembler(
                data=b"0123456789ABCDEF" * 50,
            ),
            echo_tracker=Tracker(prefix="TX"),
        )
        assert isinstance(packet.message, Icmp4PortUnreachableMessage)
        self.assertEqual(packet.message.data, (b"0123456789ABCDEF" * 50)[:520])
        self.assertTrue(
            repr(packet.tracker._echo_tracker).startswith(
                "Tracker(serial='<lr>TX"
            )
        )

    def test_icmp4_fpa____init____echo_reply(self) -> None:
        """
        Test packet constructor for the 'Echo Reply' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoReplyMessageAssembler(
                id=12345,
                seq=54321,
                data=b"0123456789ABCDEF",
            ),
            echo_tracker=Tracker(prefix="TX"),
        )
        assert isinstance(packet.message, Icmp4EchoReplyMessage)
        self.assertEqual(packet.message.id, 12345)
        self.assertEqual(packet.message.seq, 54321)
        self.assertEqual(packet.message.data, b"0123456789ABCDEF")
        self.assertTrue(
            repr(packet.tracker._echo_tracker).startswith(
                "Tracker(serial='<lr>TX"
            )
        )

    def test_icmp4_fpa____init____echo_reply__assert_ec_id__under(self) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Icmp4Assembler(
                message=Icmp4EchoReplyMessageAssembler(
                    id=-1,
                ),
            )

    def test_icmp4_fpa____init____echo_reply__assert_ec_id__over(self) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Icmp4Assembler(
                message=Icmp4EchoReplyMessageAssembler(
                    id=0x10000,
                ),
            )

    def test_icmp4_fpa____init____echo_reply__assert_ec_seq__under(
        self,
    ) -> None:
        """
        Test assertion for the 'id' argument.
        """
        with self.assertRaises(AssertionError):
            Icmp4Assembler(
                message=Icmp4EchoReplyMessageAssembler(
                    seq=-1,
                ),
            )

    def test_icmp4_fpa____init____echo_reply__assert_ec_seq__over(self) -> None:
        """
        Test assertion for the 'ec_seq' argument.
        """
        with self.assertRaises(AssertionError):
            Icmp4Assembler(
                message=Icmp4EchoReplyMessageAssembler(
                    seq=0x10000,
                ),
            )

    def test_icmp4_fpa____len____echo_reply(self) -> None:
        """
        Test the '__len__()' dunder for the 'Echo Reply' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoReplyMessageAssembler(
                data=b"0123456789ABCDEF",
            ),
        )
        self.assertEqual(len(packet), ICMP4_MESSAGE_LEN__ECHO_REPLY + 16)

    def test_icmp4_fpa____len____unreachable_port(self) -> None:
        """
        Test the '__len__()' dunder for the 'Unreachable Port' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4PortUnreachableMessageAssembler(
                data=b"0123456789ABCDEF",
            ),
        )
        self.assertEqual(len(packet), ICMP4_MESSAGE_LEN__UNREACHABLE + 16)

    def test_icmp4_fpa____len____echo_request(self) -> None:
        """
        Test the '__len__() dudner for the 'Echo Request' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoRequestMessageAssembler(
                data=b"0123456789ABCDEF",
            ),
        )
        self.assertEqual(len(packet), ICMP4_MESSAGE_LEN__ECHO_REQUEST + 16)

    def test_icmp4_fpa____str____echo_reply(self) -> None:
        """
        Test the '__str__()' dunder for the 'Echo Reply' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoReplyMessageAssembler(
                id=12345,
                seq=54321,
                data=b"0123456789ABCDEF",
            ),
        )
        self.assertEqual(
            str(packet), "ICMPv4 Echo Reply, id 12345, seq 54321, dlen 16"
        )

    def test_icmp4_fpa____str____unreachable_port(self) -> None:
        """
        Test the '__str__() dunder for the 'Unreachable Port' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4PortUnreachableMessageAssembler(
                data=b"0123456789ABCDEF",
            ),
        )
        self.assertEqual(str(packet), "ICMPv4 Port Unreachable, dlen 16")

    def test_icmp4_fpa____str____echo_request(self) -> None:
        """
        Test the '__str__()' dunder for the 'Echo Request' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoRequestMessageAssembler(
                id=12345,
                seq=54321,
                data=b"0123456789ABCDEF",
            ),
        )
        self.assertEqual(
            str(packet),
            "ICMPv4 Echo Request, id 12345, seq 54321, dlen 16",
        )

    def test_icmp4_fpa__tracker_getter(self) -> None:
        """
        Test the '_tracker' attribute getter.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoRequestMessageAssembler(),
        )
        self.assertTrue(
            repr(packet.tracker).startswith("Tracker(serial='<lr>TX")
        )

    def test_icmp4_fpa__assemble__echo_reply(self) -> None:
        """
        Test the 'assemble()' method for the 'Echo Reply' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoReplyMessageAssembler(
                id=12345,
                seq=54321,
                data=b"0123456789ABCDEF",
            ),
        )
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)
        self.assertEqual(bytes(frame), b"\x00\x00,\xbe09\xd410123456789ABCDEF")

    def test_icmp4_fpa__asssemble__unreachable_port(self) -> None:
        """
        Test the 'assemble()' method for the 'Unreachable Port' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4PortUnreachableMessageAssembler(
                data=b"0123456789ABCDEF",
            ),
        )
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)
        self.assertEqual(
            bytes(frame), b"\x03\x03.&\x00\x00\x00\x000123456789ABCDEF"
        )

    def test_icmp4_fpa__assemble__echo_request(self) -> None:
        """
        Test the 'assemble()' method for the 'Echo Request' message.
        """
        packet = Icmp4Assembler(
            message=Icmp4EchoRequestMessageAssembler(
                id=12345,
                seq=54321,
                data=b"0123456789ABCDEF",
            ),
        )
        frame = memoryview(bytearray(len(packet)))
        packet.assemble(frame)
        self.assertEqual(bytes(frame), b"\x08\x00$\xbe09\xd410123456789ABCDEF")
'''
