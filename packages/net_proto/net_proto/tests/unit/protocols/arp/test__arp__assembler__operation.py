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
This module contains tests for the ARP protocol packet assembling functionality.

net_proto/tests/unit/protocols/arp/test__arp__assembler__operation.py

ver 3.0.8
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto import (
    ARP__HARDWARE_LEN__ETHERNET,
    ARP__HEADER__LEN,
    ARP__PROTOCOL_LEN__IP4,
    ArpAssembler,
    ArpHardwareType,
    ArpHeader,
    ArpOperation,
    EtherType,
    Tracker,
)
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "ARP Request.",
            "_kwargs": {
                "arp__oper": ArpOperation.REQUEST,
                "arp__sha": MacAddress("01:02:03:04:05:06"),
                "arp__spa": Ip4Address("11.22.33.44"),
                "arp__tha": MacAddress("0a:0b:0c:0d:0e:0f"),
                "arp__tpa": Ip4Address("101.102.103.104"),
            },
            "_results": {
                "__len__": ARP__HEADER__LEN,
                "__str__": "ARP Request 11.22.33.44 / 01:02:03:04:05:06 > 101.102.103.104 / 0a:0b:0c:0d:0e:0f, len 28",
                "__repr__": (
                    "ArpAssembler(header=ArpHeader(oper=<ArpOperation.REQUEST: 1>, "
                    "sha=MacAddress('01:02:03:04:05:06'), spa=Ip4Address('11.22.33.44'), "
                    "tha=MacAddress('0a:0b:0c:0d:0e:0f'), tpa=Ip4Address('101.102.103.104')))"
                ),
                "__bytes__": (
                    # ARP (Ethernet/IPv4)
                    #   Hardware type : 0x0001 (Ethernet)
                    #   Protocol type : 0x0800 (IPv4)
                    #   HLEN / PLEN   : 6 / 4
                    #   Operation     : 1 (Request)
                    #   Sender MAC    : 01:02:03:04:05:06
                    #   Sender IP     : 11.22.33.44
                    #   Target MAC    : 0a:0b:0c:0d:0e:0f
                    #   Target IP     : 101.102.103.104
                    #
                    #   Summary       : Unicast ARP request — "Who has 101.102.103.104? Tell 11.22.33.44."
                    b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x02\x03\x04\x05\x06\x0b\x16"
                    b"\x21\x2c\x0a\x0b\x0c\x0d\x0e\x0f\x65\x66\x67\x68"
                ),
                "hrtype": ArpHardwareType.ETHERNET,
                "prtype": EtherType.IP4,
                "hrlen": ARP__HARDWARE_LEN__ETHERNET,
                "prlen": ARP__PROTOCOL_LEN__IP4,
                "oper": ArpOperation.REQUEST,
                "sha": MacAddress("01:02:03:04:05:06"),
                "spa": Ip4Address("11.22.33.44"),
                "tha": MacAddress("0a:0b:0c:0d:0e:0f"),
                "tpa": Ip4Address("101.102.103.104"),
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("01:02:03:04:05:06"),
                    spa=Ip4Address("11.22.33.44"),
                    tha=MacAddress("0a:0b:0c:0d:0e:0f"),
                    tpa=Ip4Address("101.102.103.104"),
                ),
            },
        },
        {
            "_description": "ARP Reply.",
            "_kwargs": {
                "arp__oper": ArpOperation.REPLY,
                "arp__sha": MacAddress("a1:b2:c3:d4:e5:f6"),
                "arp__spa": Ip4Address("5.5.5.5"),
                "arp__tha": MacAddress("7a:7b:7c:7d:7e:7f"),
                "arp__tpa": Ip4Address("7.7.7.7"),
            },
            "_results": {
                "__len__": ARP__HEADER__LEN,
                "__str__": "ARP Reply 5.5.5.5 / a1:b2:c3:d4:e5:f6 > 7.7.7.7 / 7a:7b:7c:7d:7e:7f, len 28",
                "__repr__": (
                    "ArpAssembler(header=ArpHeader(oper=<ArpOperation.REPLY: 2>, "
                    "sha=MacAddress('a1:b2:c3:d4:e5:f6'), spa=Ip4Address('5.5.5.5'), "
                    "tha=MacAddress('7a:7b:7c:7d:7e:7f'), tpa=Ip4Address('7.7.7.7')))"
                ),
                "__bytes__": (
                    # ARP (Ethernet/IPv4)
                    #   Hardware type : 0x0001 (Ethernet)
                    #   Protocol type : 0x0800 (IPv4)
                    #   HLEN / PLEN   : 6 / 4
                    #   Operation     : 2 (Reply)
                    #   Sender MAC    : a1:b2:c3:d4:e5:f6
                    #   Sender IP     : 5.5.5.5
                    #   Target MAC    : 7a:7b:7c:7d:7e:7f
                    #   Target IP     : 7.7.7.7
                    #
                    #   Summary       : Unicast ARP reply — "5.5.5.5 is at a1:b2:c3:d4:e5:f6."
                    b"\x00\x01\x08\x00\x06\x04\x00\x02\xa1\xb2\xc3\xd4\xe5\xf6\x05\x05"
                    b"\x05\x05\x7a\x7b\x7c\x7d\x7e\x7f\x07\x07\x07\x07"
                ),
                "hrtype": ArpHardwareType.ETHERNET,
                "prtype": EtherType.IP4,
                "hrlen": ARP__HARDWARE_LEN__ETHERNET,
                "prlen": ARP__PROTOCOL_LEN__IP4,
                "oper": ArpOperation.REPLY,
                "sha": MacAddress("a1:b2:c3:d4:e5:f6"),
                "spa": Ip4Address("5.5.5.5"),
                "tha": MacAddress("7a:7b:7c:7d:7e:7f"),
                "tpa": Ip4Address("7.7.7.7"),
                "header": ArpHeader(
                    oper=ArpOperation.REPLY,
                    sha=MacAddress("a1:b2:c3:d4:e5:f6"),
                    spa=Ip4Address("5.5.5.5"),
                    tha=MacAddress("7a:7b:7c:7d:7e:7f"),
                    tpa=Ip4Address("7.7.7.7"),
                ),
            },
        },
        {
            "_description": "ARP Probe (Request with unspecified SPA, zero THA).",
            "_kwargs": {
                "arp__oper": ArpOperation.REQUEST,
                "arp__sha": MacAddress("02:00:00:00:00:91"),
                "arp__spa": Ip4Address("0.0.0.0"),
                "arp__tha": MacAddress("00:00:00:00:00:00"),
                "arp__tpa": Ip4Address("10.0.1.7"),
            },
            "_results": {
                "__len__": ARP__HEADER__LEN,
                "__str__": "ARP Request 0.0.0.0 / 02:00:00:00:00:91 > 10.0.1.7 / 00:00:00:00:00:00, len 28",
                "__repr__": (
                    "ArpAssembler(header=ArpHeader(oper=<ArpOperation.REQUEST: 1>, "
                    "sha=MacAddress('02:00:00:00:00:91'), spa=Ip4Address('0.0.0.0'), "
                    "tha=MacAddress('00:00:00:00:00:00'), tpa=Ip4Address('10.0.1.7')))"
                ),
                "__bytes__": (
                    # ARP (Ethernet/IPv4) — ARP Probe [RFC 5227]
                    #   Hardware type : 0x0001 (Ethernet)
                    #   Protocol type : 0x0800 (IPv4)
                    #   HLEN / PLEN   : 6 / 4
                    #   Operation     : 1 (Request)
                    #   Sender MAC    : 02:00:00:00:00:91
                    #   Sender IP     : 0.0.0.0   (unspecified — probe in progress)
                    #   Target MAC    : 00:00:00:00:00:00   (unknown — filled by reply)
                    #   Target IP     : 10.0.1.7
                    #
                    #   Summary       : ARP Probe — claimant checks whether 10.0.1.7 is in use.
                    b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x00\x00"
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07"
                ),
                "hrtype": ArpHardwareType.ETHERNET,
                "prtype": EtherType.IP4,
                "hrlen": ARP__HARDWARE_LEN__ETHERNET,
                "prlen": ARP__PROTOCOL_LEN__IP4,
                "oper": ArpOperation.REQUEST,
                "sha": MacAddress("02:00:00:00:00:91"),
                "spa": Ip4Address("0.0.0.0"),
                "tha": MacAddress("00:00:00:00:00:00"),
                "tpa": Ip4Address("10.0.1.7"),
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("02:00:00:00:00:91"),
                    spa=Ip4Address("0.0.0.0"),
                    tha=MacAddress("00:00:00:00:00:00"),
                    tpa=Ip4Address("10.0.1.7"),
                ),
            },
        },
    ]
)
class TestArpAssemblerPackets(TestCase):
    """
    The ARP packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Initialize the ARP packet assembler object with testcase arguments.
        """

        self._arp__assembler = ArpAssembler(**self._kwargs)

    def test__arp__assembler__len(self) -> None:
        """
        Ensure the ARP packet assembler 'len()' returns the 28-byte header size.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            len(self._arp__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__arp__assembler__str(self) -> None:
        """
        Ensure the ARP packet assembler '__str__()' method renders the canonical
        log line.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            str(self._arp__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__arp__assembler__repr(self) -> None:
        """
        Ensure the ARP packet assembler '__repr__()' wraps the ArpHeader repr.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            repr(self._arp__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__arp__assembler__bytes(self) -> None:
        """
        Ensure 'bytes()' on the assembler yields the exact 28-byte wire image.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            bytes(self._arp__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__arp__assembler__memoryview(self) -> None:
        """
        Ensure the assembler supports the buffer protocol and reproduces the
        same bytes as 'bytes(assembler)'.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            bytes(memoryview(self._arp__assembler)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__arp__assembler__hrtype(self) -> None:
        """
        Ensure the assembler 'hrtype' property is always Ethernet.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.hrtype,
            self._results["hrtype"],
            msg=f"Unexpected 'hrtype' for case: {self._description}",
        )

    def test__arp__assembler__prtype(self) -> None:
        """
        Ensure the assembler 'prtype' property is always IPv4.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.prtype,
            self._results["prtype"],
            msg=f"Unexpected 'prtype' for case: {self._description}",
        )

    def test__arp__assembler__hrlen(self) -> None:
        """
        Ensure the assembler 'hrlen' property is always 6.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.hrlen,
            self._results["hrlen"],
            msg=f"Unexpected 'hrlen' for case: {self._description}",
        )

    def test__arp__assembler__prlen(self) -> None:
        """
        Ensure the assembler 'prlen' property is always 4.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.prlen,
            self._results["prlen"],
            msg=f"Unexpected 'prlen' for case: {self._description}",
        )

    def test__arp__assembler__oper(self) -> None:
        """
        Ensure the assembler 'oper' property reflects the constructor argument.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.oper,
            self._results["oper"],
            msg=f"Unexpected 'oper' for case: {self._description}",
        )

    def test__arp__assembler__sha(self) -> None:
        """
        Ensure the assembler 'sha' property reflects the constructor argument.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.sha,
            self._results["sha"],
            msg=f"Unexpected 'sha' for case: {self._description}",
        )

    def test__arp__assembler__spa(self) -> None:
        """
        Ensure the assembler 'spa' property reflects the constructor argument.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.spa,
            self._results["spa"],
            msg=f"Unexpected 'spa' for case: {self._description}",
        )

    def test__arp__assembler__tha(self) -> None:
        """
        Ensure the assembler 'tha' property reflects the constructor argument.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.tha,
            self._results["tha"],
            msg=f"Unexpected 'tha' for case: {self._description}",
        )

    def test__arp__assembler__tpa(self) -> None:
        """
        Ensure the assembler 'tpa' property reflects the constructor argument.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.tpa,
            self._results["tpa"],
            msg=f"Unexpected 'tpa' for case: {self._description}",
        )

    def test__arp__assembler__header(self) -> None:
        """
        Ensure the assembler 'header' property returns the expected ArpHeader.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            self._arp__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__arp__assembler__assemble(self) -> None:
        """
        Ensure the 'assemble()' method appends the header bytes to the buffers
        list without replacing its existing contents.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        prefix = b"\xde\xad\xbe\xef"
        buffers: list[Buffer] = [bytearray(prefix)]

        self._arp__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            prefix + self._results["__bytes__"],
            msg=f"Unexpected assemble() output for case: {self._description}",
        )

    def test__arp__assembler__roundtrip_through_header(self) -> None:
        """
        Ensure the assembled wire image parses back into an equivalent ArpHeader.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        self.assertEqual(
            ArpHeader.from_buffer(bytes(self._arp__assembler)),
            self._results["header"],
            msg=f"Unexpected roundtrip header for case: {self._description}",
        )


class TestArpAssemblerDefaults(TestCase):
    """
    The ARP packet assembler default-value tests.
    """

    def test__arp__assembler__defaults(self) -> None:
        """
        Ensure constructing the assembler without arguments yields a REQUEST
        with unspecified MAC and IPv4 addresses.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        assembler = ArpAssembler()

        self.assertEqual(assembler.oper, ArpOperation.REQUEST, msg="Default 'oper' must be REQUEST.")
        self.assertEqual(assembler.sha, MacAddress(), msg="Default 'sha' must be the unspecified MAC.")
        self.assertEqual(assembler.spa, Ip4Address(), msg="Default 'spa' must be the unspecified IPv4 address.")
        self.assertEqual(assembler.tha, MacAddress(), msg="Default 'tha' must be the unspecified MAC.")
        self.assertEqual(assembler.tpa, Ip4Address(), msg="Default 'tpa' must be the unspecified IPv4 address.")
        self.assertEqual(len(assembler), ARP__HEADER__LEN, msg="Default assembler length must be 28 bytes.")
        self.assertEqual(
            bytes(assembler),
            b"\x00\x01\x08\x00\x06\x04\x00\x01" + b"\x00" * 20,
            msg="Default assembler bytes must describe a Request with all address fields cleared.",
        )

    def test__arp__assembler__rejects_positional_args(self) -> None:
        """
        Ensure the assembler constructor rejects positional arguments.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        with self.assertRaises(TypeError):
            ArpAssembler(ArpOperation.REQUEST)  # type: ignore[misc]


class TestArpAssemblerTracker(TestCase):
    """
    The ARP packet assembler tracker behavior tests.
    """

    def test__arp__assembler__tracker_prefix(self) -> None:
        """
        Ensure the assembler's tracker serial carries the 'TX' prefix.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        assembler = ArpAssembler()

        self.assertIn(
            "TX",
            str(assembler.tracker),
            msg="ArpAssembler tracker serial must include the 'TX' prefix.",
        )

    def test__arp__assembler__echo_tracker_stored(self) -> None:
        """
        Ensure the assembler preserves the supplied 'echo_tracker'.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        echo_tracker = Tracker(prefix="RX")

        assembler = ArpAssembler(echo_tracker=echo_tracker)

        self.assertIs(
            assembler.tracker.echo_tracker,
            echo_tracker,
            msg="ArpAssembler must keep the exact echo_tracker instance it was given.",
        )

    def test__arp__assembler__no_echo_tracker_by_default(self) -> None:
        """
        Ensure an assembler built without 'echo_tracker' has no echo reference.

        Reference: RFC 826 (ARP wire format — Ethernet/IPv4 28-byte packet).
        """

        assembler = ArpAssembler()

        self.assertIsNone(
            assembler.tracker.echo_tracker,
            msg="ArpAssembler tracker must default to having no echo_tracker.",
        )


class TestArpAssemblerUnknownOperReject(TestCase):
    """
    The ARP assembler TX-strict enum-domain enforcement tests.

    ProtoEnum '_missing_' materialises any unknown wire
    Operation byte as an `UNKNOWN_<value>` pseudo-member so
    the parser can surface it via `validate_sanity`. The
    assembler is the strict-TX boundary and MUST refuse to
    emit a frame whose Operation field carries such a
    pseudo-member.
    """

    def test__arp__assembler__unknown_oper_rejected(self) -> None:
        """
        Ensure constructing an ArpAssembler with an Operation
        value outside the defined REQUEST / REPLY set raises
        AssertionError. Mirrors the parser-side rejection at
        `ArpParser._validate_sanity` so PyTCP itself cannot
        originate an undefined-Operation frame.

        Reference: RFC 826 (only REQUEST and REPLY defined).
        Reference: RFC 5494 §3 (reserved Operation values).
        """

        unknown_oper = ArpOperation.from_int(99)
        self.assertTrue(
            unknown_oper.is_unknown,
            msg="Test fixture sanity: 99 must materialise as UNKNOWN_99.",
        )

        with self.assertRaises(AssertionError) as error:
            ArpAssembler(arp__oper=unknown_oper)

        self.assertIn(
            "must be a known ArpOperation member",
            str(error.exception),
            msg="AssertionError must cite the closed-set ArpOperation domain.",
        )

    def test__arp__assembler__request_and_reply_accepted(self) -> None:
        """
        Ensure the canonical happy path — REQUEST and REPLY
        Operation values — passes the TX-strict check.

        Reference: RFC 826 (REQUEST=1 and REPLY=2 are the only
        defined Operation values).
        """

        for oper in (ArpOperation.REQUEST, ArpOperation.REPLY):
            with self.subTest(oper=oper):
                # Should not raise.
                ArpAssembler(arp__oper=oper)
