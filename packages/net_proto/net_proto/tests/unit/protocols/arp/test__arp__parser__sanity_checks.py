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
This module contains tests for the ARP packet parser sanity checks.

net_proto/tests/unit/protocols/arp/test__arp__parser__sanity_checks.py

ver 3.0.8
"""

from typing import Any, cast, override
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import MacAddress
from net_proto import ArpParser, ArpSanityError, PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser


@parameterized_class(
    [
        {
            "_description": "The 'oper' field value is unknown (0).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 0 (invalid, triggers sanity error)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : Malformed ARP header with undefined operation code 0.
                b"\x00\x01\x08\x00\x06\x04\x00\x00\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'oper' field value must be one of [1, 2]. Got: 0.",
            },
        },
        {
            "_description": "The 'oper' field value is unknown (3).",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 3 (invalid: neither Request nor Reply)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : Malformed ARP header with undefined operation code 3.
                b"\x00\x01\x08\x00\x06\x04\x00\x03\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'oper' field value must be one of [1, 2]. Got: 3.",
            },
        },
        {
            "_description": "The SHA address is unspecified.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 00:00:00:00:00:00
                #   Sender IP     : 0.0.0.0
                #   Target MAC    : 00:00:00:00:00:00
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Request with unspecified sender MAC address.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'sha' field value 00:00:00:00:00:00 must not be an unspecified MAC address.",
            },
        },
        {
            "_description": "The SHA address is multicast.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 01:00:5e:00:00:01  (IPv4 multicast OUI)
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Request sent from multicast MAC address.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x00\x5e\x00\x00\x01\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'sha' field value 01:00:5e:00:00:01 must not be a multicast MAC address.",
            },
        },
        {
            "_description": "The SHA address is broadcast.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : ff:ff:ff:ff:ff:ff  (broadcast)
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:00
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Request claiming broadcast MAC as sender.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\xff\xff\xff\xff\xff\xff\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'sha' field value ff:ff:ff:ff:ff:ff must not be a broadcast MAC address.",
            },
        },
        {
            "_description": "The SPA field is unspecified in an ARP Reply.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 2 (Reply)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 0.0.0.0
                #   Target MAC    : 02:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Reply advertising unspecified sender IPv4 address.
                b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x00\x00"
                b"\x00\x00\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": (
                    "The 'spa' field value 0.0.0.0 must not be an unspecified IPv4 address for an ARP Reply."
                ),
            },
        },
        {
            "_description": "The SPA address is multicast.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 2 (Reply)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 224.0.0.1  (multicast)
                #   Target MAC    : 02:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Reply advertising multicast sender IPv4 address.
                b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\xe0\x00"
                b"\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'spa' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The SPA address is limited broadcast.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 2 (Reply)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 255.255.255.255  (limited broadcast)
                #   Target MAC    : 02:00:00:00:00:07
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Reply claiming limited broadcast sender IP address.
                b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\xff\xff"
                b"\xff\xff\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'spa' field value 255.255.255.255 must not be a limited broadcast IPv4 address.",
            },
        },
        {
            "_description": "The SPA address is loopback.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 127.0.0.1  (loopback)
                #   Target MAC    : 00:00:00:00:00:00
                #   Target IP     : 10.0.1.7
                #
                #   Summary       : ARP Request claiming loopback sender IPv4 address.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x7f\x00"
                b"\x00\x01\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07"
            ),
            "_results": {
                "error_message": "The 'spa' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The TPA address is multicast.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:00
                #   Target IP     : 224.0.0.1  (multicast — RFC 1112 maps directly to MAC 01:00:5e:00:00:01)
                #
                #   Summary       : Malformed ARP Request asking about a multicast IPv4 address.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x01"
            ),
            "_results": {
                "error_message": "The 'tpa' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The TPA address is limited broadcast.",
            "_frame_rx": (
                # ARP (Ethernet/IPv4)
                #   Hardware type : 0x0001 (Ethernet)
                #   Protocol type : 0x0800 (IPv4)
                #   HLEN / PLEN   : 6 / 4
                #   Operation     : 1 (Request)
                #   Sender MAC    : 02:00:00:00:00:91
                #   Sender IP     : 10.0.1.91
                #   Target MAC    : 00:00:00:00:00:00
                #   Target IP     : 255.255.255.255  (limited broadcast — never resolved via ARP)
                #
                #   Summary       : Malformed ARP Request asking about the limited broadcast address.
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff"
            ),
            "_results": {
                "error_message": "The 'tpa' field value 255.255.255.255 must not be a limited broadcast IPv4 address.",
            },
        },
    ]
)
class TestArpParserSanityChecks(TestCase):
    """
    The ARP packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Wrap the raw frame in a PacketRx.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__arp__parser__sanity_error(self) -> None:
        """
        Ensure the ARP packet parser raises ArpSanityError on logically
        inconsistent frames and reports the expected message.

        Reference: RFC 826 (ARP — sender-hardware-address-of-itself, REQUEST/REPLY opcodes).
        Reference: RFC 1112 §6.4 (IPv4 multicast → MAC mapping bypasses ARP).
        Reference: RFC 1122 §3.2.1.3 (forbidden IPv4 source addresses).
        Reference: RFC 5227 §1.1 (ARP Probe spa=0.0.0.0; sha must be the interface MAC).
        Reference: RFC 5494 §3 (reserved ARP opcodes 0 and 65535).
        """

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ARP] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )


class TestArpParserSanityHappyPaths(TestCase):
    """
    Happy-path sanity tests — valid frames must pass without raising.
    """

    def test__arp__parser__sanity__valid_reply_parses_cleanly(self) -> None:
        """
        Ensure a structurally valid ARP Reply passes the sanity validator.

        Wire contents:
          Hardware type : 0x0001 (Ethernet)
          Protocol type : 0x0800 (IPv4)
          HLEN / PLEN   : 6 / 4
          Operation     : 2 (Reply)
          Sender MAC    : 02:00:00:00:00:07
          Sender IP     : 10.0.1.7
          Target MAC    : 02:00:00:00:00:91
          Target IP     : 10.0.1.91

        Reference: RFC 826 (ARP Reply packet format and Packet Reception algorithm).
        """

        frame = (
            b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00"
            b"\x01\x07\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
        )
        packet_rx = PacketRx(frame)

        parser = ArpParser(packet_rx)

        self.assertIs(packet_rx.arp, parser, msg="PacketRx.arp must reference the new ArpParser instance.")

    def test__arp__parser__sanity__sha_mismatch_with_ethernet_src_allowed(self) -> None:
        """
        Ensure an ARP frame whose 'sha' differs from the parent Ethernet
        'src' parses cleanly. Cross-layer consistency between ARP sha and
        the Ethernet source MAC is not normative under any ARP RFC and is
        not enforced by Linux's net/ipv4/arp.c::arp_rcv; PyTCP follows the
        Linux behavior.

        Wire contents:
          Hardware type : 0x0001 (Ethernet)
          Protocol type : 0x0800 (IPv4)
          HLEN / PLEN   : 6 / 4
          Operation     : 2 (Reply)
          Sender MAC    : 02:00:00:00:00:91   (ARP sha)
          Sender IP     : 10.0.1.91
          Target MAC    : 02:00:00:00:00:07
          Target IP     : 10.0.1.7
          (Parent Ethernet src is set to 02:00:00:00:00:07 — deliberately differs from sha.)

        Reference: RFC 826 (ARP wire format — silent on cross-layer MAC consistency).
        """

        frame = (
            b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00"
            b"\x01\x5b\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
        )
        packet_rx = PacketRx(frame)
        packet_rx.ethernet = cast(
            EthernetParser,
            EthernetAssembler(ethernet__src=MacAddress("02:00:00:00:00:07")),
        )

        parser = ArpParser(packet_rx)

        self.assertIs(packet_rx.arp, parser, msg="PacketRx.arp must reference the new ArpParser instance.")

    def test__arp__parser__sanity__request_with_unspecified_spa_allowed(self) -> None:
        """
        Ensure an ARP Request with an unspecified SPA (ARP Probe) passes the
        sanity validator — only Replies forbid the unspecified SPA.

        Wire contents:
          Hardware type : 0x0001 (Ethernet)
          Protocol type : 0x0800 (IPv4)
          HLEN / PLEN   : 6 / 4
          Operation     : 1 (Request)
          Sender MAC    : 02:00:00:00:00:91
          Sender IP     : 0.0.0.0   (probe)
          Target MAC    : 00:00:00:00:00:00
          Target IP     : 10.0.1.7

        Reference: RFC 5227 §1.1 (ARP Probe — Request with all-zero 'sender IP address').
        """

        frame = (
            b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07"
        )

        ArpParser(PacketRx(frame))
