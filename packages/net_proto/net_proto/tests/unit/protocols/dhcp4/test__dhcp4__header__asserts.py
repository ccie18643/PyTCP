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
This module contains tests for the DHCPv4 header fields and asserts.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__header__asserts.py

ver 3.0.8
"""

from dataclasses import FrozenInstanceError
from typing import Any, override
from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from net_proto import (
    DHCP4__HEADER__FILE__MAX_LEN,
    DHCP4__HEADER__LEN,
    DHCP4__HEADER__SNAME__MAX_LEN,
    UINT_8__MAX,
    UINT_8__MIN,
    UINT_16__MAX,
    UINT_16__MIN,
    UINT_32__MAX,
    UINT_32__MIN,
    Dhcp4Header,
    Dhcp4IntegrityError,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__enums import (
    DHCP4__HARDWARE_LEN__ETHERNET,
    Dhcp4HardwareType,
)
from net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__MAGIC_COOKIE


class TestDhcp4HeaderAsserts(TestCase):
    """
    The DHCPv4 header fields asserts tests.
    """

    @override
    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 header constructor.
        """

        self._kwargs: dict[str, Any] = {
            "operation": Dhcp4Operation.REQUEST,
            "hops": 0,
            "xid": 0x12345678,
            "secs": 0,
            "flag_b": False,
            "ciaddr": Ip4Address(),
            "yiaddr": Ip4Address(),
            "siaddr": Ip4Address(),
            "giaddr": Ip4Address(),
            "chaddr": MacAddress(),
            "sname": "",
            "file": "",
        }

    def test__dhcp4__header__operation__not_Dhcp4Operation(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'operation' argument is not a Dhcp4Operation.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["operation"] = value = "not a Dhcp4Operation"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'operation' field must be a Dhcp4Operation. Got: {type(value)!r}",
            msg="Unexpected 'operation' assert message.",
        )

    def test__dhcp4__header__hops__under_min(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'hops' argument is lower than the minimum supported value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["hops"] = value = UINT_8__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hops' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'hops' under-min assert message.",
        )

    def test__dhcp4__header__hops__over_max(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'hops' argument is higher than the maximum supported value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["hops"] = value = UINT_8__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'hops' field must be an 8-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'hops' over-max assert message.",
        )

    def test__dhcp4__header__xid__under_min(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'xid' argument is lower than the minimum supported value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["xid"] = value = UINT_32__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'xid' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'xid' under-min assert message.",
        )

    def test__dhcp4__header__xid__over_max(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'xid' argument is higher than the maximum supported value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["xid"] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'xid' field must be a 32-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'xid' over-max assert message.",
        )

    def test__dhcp4__header__secs__under_min(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'secs' argument is lower than the minimum supported value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["secs"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'secs' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'secs' under-min assert message.",
        )

    def test__dhcp4__header__secs__over_max(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'secs' argument is higher than the maximum supported value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["secs"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'secs' field must be a 16-bit unsigned integer. Got: {value!r}",
            msg="Unexpected 'secs' over-max assert message.",
        )

    def test__dhcp4__header__flag_b__not_boolean(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'flag_b' argument is not a boolean.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["flag_b"] = value = "not a boolean"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'flag_b' field must be a boolean. Got: {type(value)!r}",
            msg="Unexpected 'flag_b' assert message.",
        )

    def test__dhcp4__header__ciaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'ciaddr' argument is not an Ip4Address.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["ciaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ciaddr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'ciaddr' assert message.",
        )

    def test__dhcp4__header__yiaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'yiaddr' argument is not an Ip4Address.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["yiaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'yiaddr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'yiaddr' assert message.",
        )

    def test__dhcp4__header__siaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'siaddr' argument is not an Ip4Address.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["siaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'siaddr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'siaddr' assert message.",
        )

    def test__dhcp4__header__giaddr__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'giaddr' argument is not an Ip4Address.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["giaddr"] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'giaddr' field must be an Ip4Address. Got: {type(value)!r}",
            msg="Unexpected 'giaddr' assert message.",
        )

    def test__dhcp4__header__chaddr__not_MacAddress(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'chaddr' argument is not a MacAddress.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["chaddr"] = value = "not a MacAddress"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'chaddr' field must be a MacAddress. Got: {type(value)!r}",
            msg="Unexpected 'chaddr' assert message.",
        )

    def test__dhcp4__header__sname__not_string(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'sname' argument is not a string.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["sname"] = value = b"not a string"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sname' field must be a string. Got: {type(value)!r}",
            msg="Unexpected 'sname' type assert message.",
        )

    def test__dhcp4__header__sname__over_max_len(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        length of provided 'sname' argument is over maximum allowable value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["sname"] = value = "X" * (DHCP4__HEADER__SNAME__MAX_LEN + 1)

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'sname' field length must be less than or equal to "
            f"{DHCP4__HEADER__SNAME__MAX_LEN!r}. Got: {len(value)!r}",
            msg="Unexpected 'sname' length assert message.",
        )

    def test__dhcp4__header__sname__at_max_len_accepted(self) -> None:
        """
        Ensure the DHCPv4 header constructor accepts 'sname' of exactly the
        maximum allowable length.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["sname"] = "X" * DHCP4__HEADER__SNAME__MAX_LEN

        header = Dhcp4Header(**self._kwargs)

        self.assertEqual(
            len(header.sname),
            DHCP4__HEADER__SNAME__MAX_LEN,
            msg="'sname' of exactly DHCP4__HEADER__SNAME__MAX_LEN must be accepted.",
        )

    def test__dhcp4__header__file__not_string(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        provided 'file' argument is not a string.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["file"] = value = b"not a string"

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'file' field must be a string. Got: {type(value)!r}",
            msg="Unexpected 'file' type assert message.",
        )

    def test__dhcp4__header__file__over_max_len(self) -> None:
        """
        Ensure the DHCPv4 header constructor raises an exception when the
        length of provided 'file' argument is over maximum allowable value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["file"] = value = "X" * (DHCP4__HEADER__FILE__MAX_LEN + 1)

        with self.assertRaises(AssertionError) as error:
            Dhcp4Header(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'file' field length must be less than or equal to "
            f"{DHCP4__HEADER__FILE__MAX_LEN!r}. Got: {len(value)!r}",
            msg="Unexpected 'file' length assert message.",
        )

    def test__dhcp4__header__file__at_max_len_accepted(self) -> None:
        """
        Ensure the DHCPv4 header constructor accepts 'file' of exactly the
        maximum allowable length.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self._kwargs["file"] = "X" * DHCP4__HEADER__FILE__MAX_LEN

        header = Dhcp4Header(**self._kwargs)

        self.assertEqual(
            len(header.file),
            DHCP4__HEADER__FILE__MAX_LEN,
            msg="'file' of exactly DHCP4__HEADER__FILE__MAX_LEN must be accepted.",
        )


class TestDhcp4HeaderDefaults(TestCase):
    """
    The DHCPv4 header immutable default-field tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a minimal valid DHCPv4 header for inspection.
        """

        self._header = Dhcp4Header(
            operation=Dhcp4Operation.REQUEST,
            hops=0,
            xid=0x12345678,
            secs=0,
            flag_b=False,
            ciaddr=Ip4Address(),
            yiaddr=Ip4Address(),
            siaddr=Ip4Address(),
            giaddr=Ip4Address(),
            chaddr=MacAddress(),
            sname="",
            file="",
        )

    def test__dhcp4__header__hrtype_default(self) -> None:
        """
        Ensure the 'hrtype' field defaults to Dhcp4HardwareType.ETHERNET.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self.assertEqual(
            self._header.hrtype,
            Dhcp4HardwareType.ETHERNET,
            msg="Default 'hrtype' must be Dhcp4HardwareType.ETHERNET.",
        )

    def test__dhcp4__header__hrlen_default(self) -> None:
        """
        Ensure the 'hrlen' field defaults to the Ethernet MAC length (6).

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self.assertEqual(
            self._header.hrlen,
            DHCP4__HARDWARE_LEN__ETHERNET,
            msg="Default 'hrlen' must match DHCP4__HARDWARE_LEN__ETHERNET.",
        )

    def test__dhcp4__header__magic_cookie_default(self) -> None:
        """
        Ensure the 'magic_cookie' field defaults to the RFC 2131 value.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        self.assertEqual(
            self._header.magic_cookie,
            DHCP4__HEADER__MAGIC_COOKIE,
            msg="Default 'magic_cookie' must be 0x63825363.",
        )

    def test__dhcp4__header__hrtype_cannot_be_overridden(self) -> None:
        """
        Ensure 'hrtype' cannot be supplied via the constructor (init=False).

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        with self.assertRaises(TypeError):
            Dhcp4Header(
                hrtype=Dhcp4HardwareType.ETHERNET,  # type: ignore[call-arg]
                operation=Dhcp4Operation.REQUEST,
                hops=0,
                xid=0,
                secs=0,
                flag_b=False,
                ciaddr=Ip4Address(),
                yiaddr=Ip4Address(),
                siaddr=Ip4Address(),
                giaddr=Ip4Address(),
                chaddr=MacAddress(),
                sname="",
                file="",
            )


class TestDhcp4HeaderOperation(TestCase):
    """
    The DHCPv4 header construction, equality, and buffer-protocol tests.
    """

    def _valid_kwargs(self) -> dict[str, Any]:
        """
        Return a reference set of valid DHCPv4 header constructor kwargs.
        """

        return {
            "operation": Dhcp4Operation.REQUEST,
            "hops": 1,
            "xid": 0xAABBCCDD,
            "secs": 0x1122,
            "flag_b": True,
            "ciaddr": Ip4Address("10.0.0.1"),
            "yiaddr": Ip4Address("10.0.0.2"),
            "siaddr": Ip4Address("10.0.0.3"),
            "giaddr": Ip4Address("10.0.0.4"),
            "chaddr": MacAddress("01:02:03:04:05:06"),
            "sname": "server.example.com",
            "file": "bootfile.bin",
        }

    def test__dhcp4__header__construction(self) -> None:
        """
        Ensure a valid DHCPv4 header instance can be constructed and its fields
        are exposed exactly as provided.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        kwargs = self._valid_kwargs()

        header = Dhcp4Header(**kwargs)

        self.assertEqual(header.operation, kwargs["operation"], msg="Unexpected 'operation'.")
        self.assertEqual(header.hops, kwargs["hops"], msg="Unexpected 'hops'.")
        self.assertEqual(header.xid, kwargs["xid"], msg="Unexpected 'xid'.")
        self.assertEqual(header.secs, kwargs["secs"], msg="Unexpected 'secs'.")
        self.assertEqual(header.flag_b, kwargs["flag_b"], msg="Unexpected 'flag_b'.")
        self.assertEqual(header.ciaddr, kwargs["ciaddr"], msg="Unexpected 'ciaddr'.")
        self.assertEqual(header.yiaddr, kwargs["yiaddr"], msg="Unexpected 'yiaddr'.")
        self.assertEqual(header.siaddr, kwargs["siaddr"], msg="Unexpected 'siaddr'.")
        self.assertEqual(header.giaddr, kwargs["giaddr"], msg="Unexpected 'giaddr'.")
        self.assertEqual(header.chaddr, kwargs["chaddr"], msg="Unexpected 'chaddr'.")
        self.assertEqual(header.sname, kwargs["sname"], msg="Unexpected 'sname'.")
        self.assertEqual(header.file, kwargs["file"], msg="Unexpected 'file'.")

    def test__dhcp4__header__len(self) -> None:
        """
        Ensure 'len()' on the header returns the canonical 240-byte size.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        header = Dhcp4Header(**self._valid_kwargs())

        self.assertEqual(
            len(header),
            DHCP4__HEADER__LEN,
            msg="DHCPv4 header length must be 240 bytes.",
        )

    def test__dhcp4__header__buffer_protocol(self) -> None:
        """
        Ensure the DHCPv4 header buffer representation matches the wire format.

        The DHCPv4 packet [RFC 2131] is laid out as:
          Operation     : 1 (BOOTREQUEST)
          HW Type       : 1 (Ethernet)
          HW Len        : 6
          Hops          : 0
          XID           : 0x12345678
          Secs          : 0
          Flags         : 0x0000 (unicast, B=0)
          CIADDR        : 0.0.0.0
          YIADDR        : 0.0.0.0
          SIADDR        : 0.0.0.0
          GIADDR        : 0.0.0.0
          CHADDR        : 01:02:03:04:05:06 (padded to 16 bytes)
          SNAME         : "" (padded to 64 bytes)
          FILE          : "" (padded to 128 bytes)
          Magic Cookie  : 0x63825363

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        header = Dhcp4Header(
            operation=Dhcp4Operation.REQUEST,
            hops=0,
            xid=0x12345678,
            secs=0,
            flag_b=False,
            ciaddr=Ip4Address(),
            yiaddr=Ip4Address(),
            siaddr=Ip4Address(),
            giaddr=Ip4Address(),
            chaddr=MacAddress("01:02:03:04:05:06"),
            sname="",
            file="",
        )

        frame = bytes(memoryview(header))

        self.assertEqual(len(frame), DHCP4__HEADER__LEN, msg="Buffer must be 240 bytes long.")
        self.assertEqual(frame[:4], b"\x01\x01\x06\x00", msg="Unexpected op/htype/hlen/hops bytes.")
        self.assertEqual(frame[4:8], b"\x12\x34\x56\x78", msg="Unexpected 'xid' bytes.")
        self.assertEqual(frame[8:12], b"\x00\x00\x00\x00", msg="Unexpected 'secs'/'flags' bytes.")
        self.assertEqual(frame[12:28], b"\x00" * 16, msg="CIADDR/YIADDR/SIADDR/GIADDR must be zero.")
        self.assertEqual(
            frame[28:44],
            b"\x01\x02\x03\x04\x05\x06" + b"\x00" * 10,
            msg="CHADDR must be the MAC padded to 16 bytes with zeros.",
        )
        self.assertEqual(frame[44:108], b"\x00" * 64, msg="SNAME must be 64 zero bytes.")
        self.assertEqual(frame[108:236], b"\x00" * 128, msg="FILE must be 128 zero bytes.")
        self.assertEqual(
            frame[236:240],
            DHCP4__HEADER__MAGIC_COOKIE,
            msg="Magic cookie must be 0x63825363.",
        )

    def test__dhcp4__header__flag_b_true_sets_broadcast_bit(self) -> None:
        """
        Ensure 'flag_b=True' sets the high bit of the 16-bit flags word.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        header = Dhcp4Header(
            operation=Dhcp4Operation.REQUEST,
            hops=0,
            xid=0,
            secs=0,
            flag_b=True,
            ciaddr=Ip4Address(),
            yiaddr=Ip4Address(),
            siaddr=Ip4Address(),
            giaddr=Ip4Address(),
            chaddr=MacAddress(),
            sname="",
            file="",
        )

        frame = bytes(memoryview(header))

        self.assertEqual(
            frame[10:12],
            b"\x80\x00",
            msg="flag_b=True must set the broadcast bit (0x8000) in the flags word.",
        )

    def test__dhcp4__header__from_buffer_roundtrip(self) -> None:
        """
        Ensure 'from_buffer(bytes(header))' rebuilds an equivalent header.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        original = Dhcp4Header(**self._valid_kwargs())

        rebuilt = Dhcp4Header.from_buffer(bytes(memoryview(original)))

        self.assertEqual(
            rebuilt,
            original,
            msg="Roundtrip through from_buffer must preserve equality.",
        )

    def test__dhcp4__header__from_buffer_consumes_prefix(self) -> None:
        """
        Ensure 'from_buffer()' reads only the first DHCP4__HEADER__LEN bytes and
        ignores any trailing data.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        original = Dhcp4Header(**self._valid_kwargs())
        padded = bytes(memoryview(original)) + b"\xde\xad\xbe\xef"

        rebuilt = Dhcp4Header.from_buffer(padded)

        self.assertEqual(
            rebuilt,
            original,
            msg="Trailing bytes must not affect from_buffer output.",
        )

    def test__dhcp4__header__from_buffer_rejects_bad_hrtype(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the
        hardware type is not Ethernet.

        Reference: RFC 2131 §2 (BOOTP htype field).
        """

        original = Dhcp4Header(**self._valid_kwargs())
        frame = bytearray(bytes(memoryview(original)))
        frame[1] = 0x00  # clobber hrtype

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Header.from_buffer(bytes(frame))

        self.assertIn(
            "Invalid DHCPv4 hardware type",
            str(error.exception),
            msg="from_buffer must reject non-Ethernet hardware types with Dhcp4IntegrityError.",
        )

    def test__dhcp4__header__from_buffer_rejects_bad_hrlen(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the
        hardware length is not 6.

        Reference: RFC 2131 §2 (BOOTP hlen field; hlen=6 for Ethernet).
        """

        original = Dhcp4Header(**self._valid_kwargs())
        frame = bytearray(bytes(memoryview(original)))
        frame[2] = 0x08  # clobber hrlen

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Header.from_buffer(bytes(frame))

        self.assertIn(
            "Invalid DHCPv4 hardware length",
            str(error.exception),
            msg="from_buffer must reject non-6 hardware lengths with Dhcp4IntegrityError.",
        )

    def test__dhcp4__header__from_buffer_rejects_bad_magic_cookie(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the
        magic cookie is wrong.

        Reference: RFC 2131 §3 / RFC 2132 §2 (DHCP magic cookie 0x63825363).
        """

        original = Dhcp4Header(**self._valid_kwargs())
        frame = bytearray(bytes(memoryview(original)))
        frame[236:240] = b"\xde\xad\xbe\xef"

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Header.from_buffer(bytes(frame))

        self.assertIn(
            "Invalid DHCPv4 magic cookie",
            str(error.exception),
            msg="from_buffer must reject frames with bad magic cookie with Dhcp4IntegrityError.",
        )

    def test__dhcp4__header__equality(self) -> None:
        """
        Ensure two DHCPv4 headers with identical field values compare equal.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        kwargs = self._valid_kwargs()

        self.assertEqual(
            Dhcp4Header(**kwargs),
            Dhcp4Header(**kwargs),
            msg="Equal field sets must compare equal.",
        )

    def test__dhcp4__header__inequality_on_operation(self) -> None:
        """
        Ensure headers differing only in 'operation' compare unequal.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        base = self._valid_kwargs()
        base.pop("operation")

        self.assertNotEqual(
            Dhcp4Header(operation=Dhcp4Operation.REQUEST, **base),
            Dhcp4Header(operation=Dhcp4Operation.REPLY, **base),
            msg="Headers differing in 'operation' must not compare equal.",
        )

    def test__dhcp4__header__is_hashable(self) -> None:
        """
        Ensure DHCPv4 headers can be used as keys in a set/dict.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        header = Dhcp4Header(**self._valid_kwargs())

        self.assertIn(header, {header}, msg="DHCPv4 header must be hashable.")

    def test__dhcp4__header__is_frozen(self) -> None:
        """
        Ensure DHCPv4 header fields cannot be mutated after construction.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        header = Dhcp4Header(**self._valid_kwargs())

        with self.assertRaises(FrozenInstanceError):
            header.hops = 99  # type: ignore[misc]

    def test__dhcp4__header__rejects_positional_args(self) -> None:
        """
        Ensure the DHCPv4 header constructor rejects positional arguments.

        Reference: RFC 2131 §2 (BOOTP/DHCP message header fields).
        """

        with self.assertRaises(TypeError):
            Dhcp4Header(  # type: ignore[misc]
                Dhcp4Operation.REQUEST,
                0,
                0,
                0,
                False,
                Ip4Address(),
                Ip4Address(),
                Ip4Address(),
                Ip4Address(),
                MacAddress(),
                "",
                "",
            )
