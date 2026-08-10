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
This module contains tests for the NetProto EtherType and IpProto enums.

net_proto/tests/unit/lib/test__lib__enums.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase
from unittest.mock import MagicMock

from net_proto.lib.enums import EtherType, IpProto
from net_proto.lib.proto import Proto
from net_proto.protocols.arp.arp__base import Arp
from net_proto.protocols.icmp4.icmp4__base import Icmp4
from net_proto.protocols.icmp6.icmp6__base import Icmp6
from net_proto.protocols.igmp.igmp__base import Igmp
from net_proto.protocols.ip4.ip4__base import Ip4
from net_proto.protocols.ip6.ip6__base import Ip6
from net_proto.protocols.ip6_frag.ip6_frag__base import Ip6Frag
from net_proto.protocols.raw.raw__base import Raw
from net_proto.protocols.tcp.tcp__base import Tcp
from net_proto.protocols.udp.udp__base import Udp
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "EtherType.ARP known value.",
            "_member": EtherType.ARP,
            "_results": {"value": 0x0806, "__str__": "ARP", "is_unknown": False},
        },
        {
            "_description": "EtherType.IP4 known value.",
            "_member": EtherType.IP4,
            "_results": {"value": 0x0800, "__str__": "IPv4", "is_unknown": False},
        },
        {
            "_description": "EtherType.IP6 known value.",
            "_member": EtherType.IP6,
            "_results": {"value": 0x86DD, "__str__": "IPv6", "is_unknown": False},
        },
        {
            "_description": "EtherType.RAW known value.",
            "_member": EtherType.RAW,
            "_results": {"value": 0xFFFF, "__str__": "Raw", "is_unknown": False},
        },
    ]
)
class TestNetProtoLibEnumsEtherTypeKnown(TestCase):
    """
    The NetProto EtherType known-value tests.
    """

    _description: str
    _member: EtherType
    _results: dict[str, Any]

    def test__net_proto__lib__enums__ether_type__value(self) -> None:
        """
        Ensure each known EtherType member maps to the documented numeric value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._member.value,
            self._results["value"],
            msg=f"{self._description}: wrong numeric value.",
        )

    def test__net_proto__lib__enums__ether_type__str(self) -> None:
        """
        Ensure the human-readable label matches the documented one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._member),
            self._results["__str__"],
            msg=f"{self._description}: wrong string label.",
        )

    def test__net_proto__lib__enums__ether_type__is_unknown_false(self) -> None:
        """
        Ensure known EtherType members report 'is_unknown' as False.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._member.is_unknown,
            msg=f"{self._description}: must not be flagged as unknown.",
        )

    def test__net_proto__lib__enums__ether_type__bytes_is_two_bytes(self) -> None:
        """
        Ensure the EtherType serializes to a 2-byte big-endian representation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._member),
            int(self._member.value).to_bytes(2, "big"),
            msg=f"{self._description}: wrong byte representation.",
        )


class TestNetProtoLibEnumsEtherTypeUnknown(TestCase):
    """
    The NetProto EtherType unknown-value tests.
    """

    def test__net_proto__lib__enums__ether_type__unknown_registers_as_member(
        self,
    ) -> None:
        """
        Ensure an unknown EtherType is registered and exposes 'is_unknown=True'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        unknown = EtherType.from_int(0x1234)

        self.assertEqual(unknown.value, 0x1234)
        self.assertTrue(unknown.is_unknown)

    def test__net_proto__lib__enums__ether_type__unknown_str_is_hex(self) -> None:
        """
        Ensure unknown EtherType members render as zero-padded 4-digit hex.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        unknown = EtherType.from_int(0x1234)
        self.assertEqual(str(unknown), "0x1234")

    def test__net_proto__lib__enums__ether_type__unknown_lowest_value(self) -> None:
        """
        Ensure an EtherType value of 0 renders with leading zeros.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        unknown = EtherType.from_int(0x0000)
        self.assertEqual(str(unknown), "0x0000")
        self.assertTrue(unknown.is_unknown)


@parameterized_class(
    [
        {
            "_description": "Arp instance must map to EtherType.ARP.",
            "_spec": Arp,
            "_expected": EtherType.ARP,
        },
        {
            "_description": "Ip4 instance must map to EtherType.IP4.",
            "_spec": Ip4,
            "_expected": EtherType.IP4,
        },
        {
            "_description": "Ip6 instance must map to EtherType.IP6.",
            "_spec": Ip6,
            "_expected": EtherType.IP6,
        },
    ]
)
class TestNetProtoLibEnumsEtherTypeFromProto(TestCase):
    """
    The NetProto EtherType.from_proto() tests for known protocol types.
    """

    _description: str
    _spec: type
    _expected: EtherType

    def test__net_proto__lib__enums__ether_type__from_proto(self) -> None:
        """
        Ensure 'from_proto()' returns the documented EtherType for the input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        proto = MagicMock(spec=self._spec)

        self.assertIs(
            EtherType.from_proto(proto),
            self._expected,
            msg=self._description,
        )


class TestNetProtoLibEnumsEtherTypeFromProtoRaw(TestCase):
    """
    The NetProto EtherType.from_proto() tests for the Raw protocol.
    """

    def test__net_proto__lib__enums__ether_type__from_proto__raw_forwards_ether_type(
        self,
    ) -> None:
        """
        Ensure Raw proxies the 'ether_type' attribute through 'from_proto()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        raw = MagicMock(spec=Raw)
        raw.ether_type = EtherType.IP4

        self.assertIs(EtherType.from_proto(raw), EtherType.IP4)

        raw.ether_type = EtherType.ARP
        self.assertIs(EtherType.from_proto(raw), EtherType.ARP)

    def test__net_proto__lib__enums__ether_type__from_proto__unknown_raises(
        self,
    ) -> None:
        """
        Ensure an unsupported Proto subclass triggers the assertion failure.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class ForeignProto(Proto):
            @override
            def __len__(self) -> int:
                return 0

            @override
            def __str__(self) -> str:
                return ""

            @override
            def __repr__(self) -> str:
                return ""

            @override
            def __buffer__(self, _: int) -> memoryview:
                return memoryview(b"")

        with self.assertRaises(AssertionError):
            EtherType.from_proto(ForeignProto())


@parameterized_class(
    [
        {
            "_description": "IpProto.IP4 known value (RFC 2003 IPv4-in-IPv4 protocol number).",
            "_member": IpProto.IP4,
            "_results": {"value": 4, "__str__": "IPv4"},
        },
        {
            "_description": "IpProto.IP6_HBH known value (RFC 8200 §4.3 Hop-by-Hop Options).",
            "_member": IpProto.IP6_HBH,
            "_results": {"value": 0, "__str__": "IPv6_HBH"},
        },
        {
            "_description": "IpProto.ICMP4 known value.",
            "_member": IpProto.ICMP4,
            "_results": {"value": 1, "__str__": "ICMPv4"},
        },
        {
            "_description": "IpProto.IGMP known value (RFC 1112 / 3376 multicast group management).",
            "_member": IpProto.IGMP,
            "_results": {"value": 2, "__str__": "IGMP"},
        },
        {
            "_description": "IpProto.IP6_ROUTING known value (RFC 8200 §4.4 Routing Header).",
            "_member": IpProto.IP6_ROUTING,
            "_results": {"value": 43, "__str__": "IPv6_Routing"},
        },
        {
            "_description": "IpProto.IP6_NO_NEXT_HEADER known value (RFC 8200 §4.7 No Next Header).",
            "_member": IpProto.IP6_NO_NEXT_HEADER,
            "_results": {"value": 59, "__str__": "IPv6_NoNextHeader"},
        },
        {
            "_description": "IpProto.IP6_DEST_OPTS known value (RFC 8200 §4.6 Destination Options).",
            "_member": IpProto.IP6_DEST_OPTS,
            "_results": {"value": 60, "__str__": "IPv6_DestOpts"},
        },
        {
            "_description": "IpProto.TCP known value.",
            "_member": IpProto.TCP,
            "_results": {"value": 6, "__str__": "TCP"},
        },
        {
            "_description": "IpProto.UDP known value.",
            "_member": IpProto.UDP,
            "_results": {"value": 17, "__str__": "UDP"},
        },
        {
            "_description": "IpProto.IP6 known value.",
            "_member": IpProto.IP6,
            "_results": {"value": 41, "__str__": "IPv6"},
        },
        {
            "_description": "IpProto.IP6_FRAG known value.",
            "_member": IpProto.IP6_FRAG,
            "_results": {"value": 44, "__str__": "IPv6_Frag"},
        },
        {
            "_description": "IpProto.ICMP6 known value.",
            "_member": IpProto.ICMP6,
            "_results": {"value": 58, "__str__": "ICMPv6"},
        },
        {
            "_description": "IpProto.RAW known value.",
            "_member": IpProto.RAW,
            "_results": {"value": 255, "__str__": "Raw"},
        },
    ]
)
class TestNetProtoLibEnumsIpProtoKnown(TestCase):
    """
    The NetProto IpProto known-value tests.
    """

    _description: str
    _member: IpProto
    _results: dict[str, Any]

    def test__net_proto__lib__enums__ip_proto__value(self) -> None:
        """
        Ensure each known IpProto member maps to the documented numeric value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._member.value,
            self._results["value"],
            msg=f"{self._description}: wrong numeric value.",
        )

    def test__net_proto__lib__enums__ip_proto__str(self) -> None:
        """
        Ensure the human-readable label matches the documented one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._member),
            self._results["__str__"],
            msg=f"{self._description}: wrong string label.",
        )

    def test__net_proto__lib__enums__ip_proto__is_unknown_false(self) -> None:
        """
        Ensure known IpProto members report 'is_unknown' as False.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._member.is_unknown,
            msg=f"{self._description}: must not be flagged as unknown.",
        )

    def test__net_proto__lib__enums__ip_proto__bytes_is_one_byte(self) -> None:
        """
        Ensure the IpProto serializes to a single byte.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            bytes(self._member),
            int(self._member.value).to_bytes(1, "big"),
            msg=f"{self._description}: wrong byte representation.",
        )


class TestNetProtoLibEnumsIpProtoUnknown(TestCase):
    """
    The NetProto IpProto unknown-value tests.
    """

    def test__net_proto__lib__enums__ip_proto__unknown_registers_as_member(
        self,
    ) -> None:
        """
        Ensure an unknown IpProto is registered and exposes 'is_unknown=True'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        unknown = IpProto.from_int(55)

        self.assertEqual(unknown.value, 55)
        self.assertTrue(unknown.is_unknown)

    def test__net_proto__lib__enums__ip_proto__unknown_str_is_int(self) -> None:
        """
        Ensure unknown IpProto members render as the decimal integer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        unknown = IpProto.from_int(55)
        self.assertEqual(str(unknown), "55")


@parameterized_class(
    [
        {
            "_description": "from_int(0) returns IpProto.IP6_HBH (Hop-by-Hop Options).",
            "_value": 0,
            "_expected_name": "IP6_HBH",
        },
        {
            "_description": "from_int(43) returns IpProto.IP6_ROUTING (Routing Header).",
            "_value": 43,
            "_expected_name": "IP6_ROUTING",
        },
        {
            "_description": "from_int(59) returns IpProto.IP6_NO_NEXT_HEADER.",
            "_value": 59,
            "_expected_name": "IP6_NO_NEXT_HEADER",
        },
        {
            "_description": "from_int(60) returns IpProto.IP6_DEST_OPTS (Destination Options).",
            "_value": 60,
            "_expected_name": "IP6_DEST_OPTS",
        },
    ]
)
class TestNetProtoLibEnumsIpProtoIpv6ExtensionFromInt(TestCase):
    """
    The NetProto IpProto from_int() coverage for the IPv6 extension-
    header next-header values added in Phase 0.
    """

    _description: str
    _value: int
    _expected_name: str

    def test__net_proto__lib__enums__ip_proto__ipv6_extension_from_int(self) -> None:
        """
        Ensure the IpProto enum exposes a typed member at the IANA
        next-header value for each IPv6 extension header. Without
        this, 'from_int' would dynamically synthesise an 'UNKNOWN_X'
        sentinel and the chain-walker dispatch in Phase 8 would have
        no enum to match against.

        Reference: RFC 8200 §4.3 (Hop-by-Hop Options, value 0).
        Reference: RFC 8200 §4.4 (Routing Header, value 43).
        Reference: RFC 8200 §4.6 (Destination Options, value 60).
        Reference: RFC 8200 §4.7 (No Next Header, value 59).
        """

        member = IpProto.from_int(self._value)

        self.assertEqual(
            member.name,
            self._expected_name,
            msg=f"{self._description}: from_int returned wrong member.",
        )
        self.assertFalse(
            member.is_unknown,
            msg=f"{self._description}: must be a known member, not a synthesised UNKNOWN_X.",
        )


class TestNetProtoLibEnumsIpProtoIgmpFromInt(TestCase):
    """
    The NetProto IpProto from_int() coverage for the IGMP next-header value.
    """

    def test__net_proto__lib__enums__ip_proto__igmp_from_int(self) -> None:
        """
        Ensure the IpProto enum exposes a typed member at the IANA
        IGMP protocol number (2) so the IPv4 RX proto-demux can match
        against it rather than a synthesised 'UNKNOWN_2' sentinel.

        Reference: RFC 1112 §7.2 (IGMP carried as IP protocol 2).
        Reference: RFC 3376 §4 (IGMP messages, protocol number 2).
        """

        member = IpProto.from_int(2)

        self.assertIs(
            member,
            IpProto.IGMP,
            msg="from_int(2) must return the typed IpProto.IGMP member.",
        )
        self.assertFalse(
            member.is_unknown,
            msg="IpProto.IGMP must be a known member, not a synthesised UNKNOWN_2.",
        )


@parameterized_class(
    [
        {
            "_description": "Ip4 instance must map to IpProto.IP4.",
            "_spec": Ip4,
            "_expected": IpProto.IP4,
        },
        {
            "_description": "Icmp4 instance must map to IpProto.ICMP4.",
            "_spec": Icmp4,
            "_expected": IpProto.ICMP4,
        },
        {
            "_description": "Igmp instance must map to IpProto.IGMP.",
            "_spec": Igmp,
            "_expected": IpProto.IGMP,
        },
        {
            "_description": "Tcp instance must map to IpProto.TCP.",
            "_spec": Tcp,
            "_expected": IpProto.TCP,
        },
        {
            "_description": "Udp instance must map to IpProto.UDP.",
            "_spec": Udp,
            "_expected": IpProto.UDP,
        },
        {
            "_description": "Ip6Frag instance must map to IpProto.IP6_FRAG.",
            "_spec": Ip6Frag,
            "_expected": IpProto.IP6_FRAG,
        },
        {
            "_description": "Icmp6 instance must map to IpProto.ICMP6.",
            "_spec": Icmp6,
            "_expected": IpProto.ICMP6,
        },
    ]
)
class TestNetProtoLibEnumsIpProtoFromProto(TestCase):
    """
    The NetProto IpProto.from_proto() tests for known protocol types.
    """

    _description: str
    _spec: type
    _expected: IpProto

    def test__net_proto__lib__enums__ip_proto__from_proto(self) -> None:
        """
        Ensure 'from_proto()' returns the documented IpProto for the input.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        proto = MagicMock(spec=self._spec)

        self.assertIs(
            IpProto.from_proto(proto),
            self._expected,
            msg=self._description,
        )


class TestNetProtoLibEnumsIpProtoFromProtoSpecialCases(TestCase):
    """
    The NetProto IpProto.from_proto() tests for Raw and foreign protocols.
    """

    def test__net_proto__lib__enums__ip_proto__from_proto__raw_forwards_ip_proto(
        self,
    ) -> None:
        """
        Ensure Raw proxies the 'ip_proto' attribute through 'from_proto()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        raw = MagicMock(spec=Raw)
        raw.ip_proto = IpProto.UDP
        self.assertIs(IpProto.from_proto(raw), IpProto.UDP)

        raw.ip_proto = IpProto.ICMP6
        self.assertIs(IpProto.from_proto(raw), IpProto.ICMP6)

    def test__net_proto__lib__enums__ip_proto__from_proto__ip6(self) -> None:
        """
        Ensure Ip6 is currently mapped through 'from_proto()'. Documents the
        live behavior of the function for the Ip6 branch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ip6 = MagicMock(spec=Ip6)

        result = IpProto.from_proto(ip6)

        self.assertIsInstance(result, IpProto)

    def test__net_proto__lib__enums__ip_proto__from_proto__unknown_raises(
        self,
    ) -> None:
        """
        Ensure an unsupported Proto subclass trips the unreachable-fallback
        assertion.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        class ForeignProto(Proto):
            @override
            def __len__(self) -> int:
                return 0

            @override
            def __str__(self) -> str:
                return ""

            @override
            def __repr__(self) -> str:
                return ""

            @override
            def __buffer__(self, _: int) -> memoryview:
                return memoryview(b"")

        with self.assertRaises(AssertionError) as error:
            IpProto.from_proto(ForeignProto())

        self.assertIn("Unknown protocol", str(error.exception))


class TestNetProtoLibEnumsRoundtrip(TestCase):
    """
    The NetProto EtherType/IpProto round-trip serialization tests.
    """

    def test__net_proto__lib__enums__ether_type__from_bytes_roundtrip(self) -> None:
        """
        Ensure EtherType members round-trip through 'from_bytes(bytes(x))'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for member in (EtherType.ARP, EtherType.IP4, EtherType.IP6, EtherType.RAW):
            with self.subTest(member=member):
                self.assertIs(EtherType.from_bytes(bytes(member)), member)

    def test__net_proto__lib__enums__ip_proto__from_bytes_roundtrip(self) -> None:
        """
        Ensure IpProto members round-trip through 'from_bytes(bytes(x))'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for member in (
            IpProto.IP6_HBH,
            IpProto.ICMP4,
            IpProto.IGMP,
            IpProto.IP4,
            IpProto.TCP,
            IpProto.UDP,
            IpProto.IP6,
            IpProto.IP6_ROUTING,
            IpProto.IP6_FRAG,
            IpProto.ICMP6,
            IpProto.IP6_NO_NEXT_HEADER,
            IpProto.IP6_DEST_OPTS,
            IpProto.RAW,
        ):
            with self.subTest(member=member):
                self.assertIs(IpProto.from_bytes(bytes(member)), member)
