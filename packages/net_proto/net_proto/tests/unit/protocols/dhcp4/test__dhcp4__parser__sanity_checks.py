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
This module contains tests for the DHCPv4 packet parser sanity checks.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__sanity_checks.py

ver 3.0.8
"""

from typing import Any
from unittest import TestCase

from net_proto import DHCP4__HEADER__LEN, Dhcp4Parser, Dhcp4SanityError
from net_proto.protocols.dhcp4.dhcp4__header import DHCP4__HEADER__MAGIC_COOKIE
from net_proto.tests.lib.parameterized import parameterized_class

# Minimum-valid options block: DHCP Message Type = ACK +
# Server Identifier (10.0.1.1) + IP Address Lease Time (3600s)
# + End. Every sanity-rejection fixture appends this so:
#
# - RFC 2131 §3 "Message Type option MUST be present" sanity
#   check does not fire before the field-specific sanity
#   assertion the test is targeting.
# - RFC 2131 §3 Table 3 / §4.3.6 "server-response messages
#   MUST carry the Server Identifier option" sanity check
#   does not fire either (the default frame is BOOTREPLY/ACK).
# - Lease time (§4.3.1) is present so an alternate fixture
#   that uses OFFER does not trip the OFFER-specific check.
_DHCP4_OPTIONS_MIN_VALID = (
    b"\x35\x01\x05"  # Message Type: ACK
    b"\x36\x04\x0a\x00\x01\x01"  # Server Identifier: 10.0.1.1
    b"\x33\x04\x00\x00\x0e\x10"  # IP Address Lease Time: 3600s
    b"\xff"  # End
)


def _dhcp4_frame(
    *,
    op: int = 0x02,  # BOOTREPLY
    htype: int = 0x01,
    hlen: int = 0x06,
    hops: int = 0x00,
    xid: int = 0x12345678,
    secs: int = 0x0000,
    flags: int = 0x0000,
    ciaddr: bytes = b"\x00\x00\x00\x00",
    yiaddr: bytes = b"\x0a\x00\x01\x07",  # 10.0.1.7 (valid unicast)
    siaddr: bytes = b"\x0a\x00\x01\x01",  # 10.0.1.1 (valid unicast)
    giaddr: bytes = b"\x00\x00\x00\x00",
    chaddr_mac: bytes = b"\x02\x00\x00\x00\x00\x07",
    options: bytes = _DHCP4_OPTIONS_MIN_VALID,
) -> memoryview:
    """
    Build a minimal valid DHCPv4 frame (240-byte header + DHCP magic cookie
    + minimum-valid options block carrying a Message Type option). Callers
    override one field to provoke a sanity error; the default options block
    keeps the new RFC 2131 §3 Message Type presence check satisfied.
    """

    assert len(chaddr_mac) == 6, f"Ethernet MAC must be 6 bytes. Got: {len(chaddr_mac)}"
    chaddr = chaddr_mac + b"\x00" * (16 - 6)

    sname_bytes = b"\x00" * 64
    file_bytes = b"\x00" * 128

    frame = bytes([op, htype, hlen, hops])
    frame += xid.to_bytes(4, "big")
    frame += secs.to_bytes(2, "big") + flags.to_bytes(2, "big")
    frame += ciaddr + yiaddr + siaddr + giaddr
    frame += chaddr + sname_bytes + file_bytes + DHCP4__HEADER__MAGIC_COOKIE

    assert len(frame) == DHCP4__HEADER__LEN, f"Got frame len {len(frame)}, expected {DHCP4__HEADER__LEN}"

    return memoryview(frame + options)


_MCAST_IP = b"\xe0\x00\x00\x01"  # 224.0.0.1
_LOOPBACK_IP = b"\x7f\x00\x00\x01"  # 127.0.0.1
_LIMITED_BCAST_IP = b"\xff\xff\xff\xff"  # 255.255.255.255
_MCAST_MAC = b"\x01\x00\x5e\x00\x00\x01"  # IPv4-multicast OUI
_BCAST_MAC = b"\xff\xff\xff\xff\xff\xff"


@parameterized_class(
    [
        {
            "_description": "The 'operation' field value is unknown (0).",
            "_args": [_dhcp4_frame(op=0)],
            "_results": {
                "error_message": "The 'operation' field value must be one of [1, 2]. Got: 0.",
            },
        },
        {
            "_description": "The 'operation' field value is unknown (3).",
            "_args": [_dhcp4_frame(op=3)],
            "_results": {
                "error_message": "The 'operation' field value must be one of [1, 2]. Got: 3.",
            },
        },
        {
            "_description": "The 'yiaddr' field is multicast.",
            "_args": [_dhcp4_frame(yiaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'yiaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'yiaddr' field is loopback.",
            "_args": [_dhcp4_frame(yiaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'yiaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'yiaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(yiaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'yiaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'ciaddr' field is multicast.",
            "_args": [_dhcp4_frame(ciaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'ciaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'ciaddr' field is loopback.",
            "_args": [_dhcp4_frame(ciaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'ciaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'ciaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(ciaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'ciaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'siaddr' field is multicast.",
            "_args": [_dhcp4_frame(siaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'siaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'siaddr' field is loopback.",
            "_args": [_dhcp4_frame(siaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'siaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'siaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(siaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'siaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'giaddr' field is multicast.",
            "_args": [_dhcp4_frame(giaddr=_MCAST_IP)],
            "_results": {
                "error_message": "The 'giaddr' field value 224.0.0.1 must not be a multicast IPv4 address.",
            },
        },
        {
            "_description": "The 'giaddr' field is loopback.",
            "_args": [_dhcp4_frame(giaddr=_LOOPBACK_IP)],
            "_results": {
                "error_message": "The 'giaddr' field value 127.0.0.1 must not be a loopback IPv4 address.",
            },
        },
        {
            "_description": "The 'giaddr' field is limited broadcast.",
            "_args": [_dhcp4_frame(giaddr=_LIMITED_BCAST_IP)],
            "_results": {
                "error_message": (
                    "The 'giaddr' field value 255.255.255.255 must not be a limited broadcast IPv4 address."
                ),
            },
        },
        {
            "_description": "The 'chaddr' field is multicast.",
            "_args": [_dhcp4_frame(chaddr_mac=_MCAST_MAC)],
            "_results": {
                "error_message": "The 'chaddr' field value 01:00:5e:00:00:01 must not be a multicast MAC address.",
            },
        },
        {
            "_description": "The 'chaddr' field is broadcast.",
            "_args": [_dhcp4_frame(chaddr_mac=_BCAST_MAC)],
            "_results": {
                "error_message": "The 'chaddr' field value ff:ff:ff:ff:ff:ff must not be a broadcast MAC address.",
            },
        },
    ]
)
class TestDhcp4ParserSanityChecks(TestCase):
    """
    The DHCPv4 packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__parser__sanity_error(self) -> None:
        """
        Ensure the DHCPv4 packet parser raises Dhcp4SanityError on logically
        inconsistent frames and reports the expected message.

        Reference: RFC 951 §8 / RFC 2131 §2 (BOOTREQUEST=1, BOOTREPLY=2 — only defined op values).
        Reference: RFC 1122 §3.2.1.3 (forbidden IPv4 addresses for host/relay endpoints).
        Reference: RFC 2131 §2 (chaddr is the client hardware address — implicit unicast).
        """

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(*self._args)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][DHCPv4] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )


class TestDhcp4ParserSanityHappyPath(TestCase):
    """
    Happy-path sanity tests — valid frames must pass without raising.
    """

    def test__dhcp4__parser__sanity__valid_frame_parses_cleanly(self) -> None:
        """
        Ensure a structurally valid DHCPv4 REPLY frame (unicast addresses
        across yiaddr/siaddr, zeroed ciaddr/giaddr, unicast chaddr) passes
        the sanity validator without raising.

        Reference: RFC 2131 §2 (BOOTP/DHCP packet format and field semantics).
        """

        Dhcp4Parser(_dhcp4_frame())


class TestDhcp4ParserSanityMessageTypePresence(TestCase):
    """
    The DHCPv4 parser DHCP Message Type option presence sanity
    tests. RFC 2131 §3 mandates "DHCP messages MUST contain a
    'DHCP message type' option"; a magic-cookie-bearing BOOTP
    frame without option 53 cannot be classified as a DHCP
    message and must be rejected with Dhcp4SanityError.
    """

    def test__dhcp4__parser__sanity__no_message_type_rejected(self) -> None:
        """
        Ensure a structurally valid magic-cookie-bearing frame
        whose options block does NOT carry a Message Type option
        (53) is rejected with Dhcp4SanityError.

        Reference: RFC 2131 §3 (DHCP messages MUST contain a Message Type option).
        Reference: RFC 2132 §9.6 (Message Type option code 53).
        """

        # Options block: just an End marker; no Message Type.
        frame = _dhcp4_frame(options=b"\xff")

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(frame)

        self.assertEqual(
            str(error.exception),
            "[SANITY ERROR][DHCPv4] DHCP messages MUST contain a Message Type option "
            "(RFC 2131 §3 / RFC 2132 §9.6). Got: magic-cookie-bearing frame without option 53.",
            msg="Unexpected message-type-absent sanity error message.",
        )

    def test__dhcp4__parser__sanity__message_type_present_accepted(self) -> None:
        """
        Ensure a frame with the minimum-valid options block
        (Message Type + Server Identifier + Lease Time + End)
        passes the sanity check.

        Reference: RFC 2131 §3 (Message Type presence is the canonical DHCP indicator).
        """

        # Default _dhcp4_frame() options block carries the Message Type,
        # Server Identifier, and Lease Time required for an ACK reply.
        Dhcp4Parser(_dhcp4_frame())


class TestDhcp4ParserSanityRequiredServerResponseOptions(TestCase):
    """
    The DHCPv4 parser per-message-type required-options sanity
    tests. RFC 2131 §3 Table 3 / §4.3.6 mandate that
    server-emitted DHCPOFFER, DHCPACK, and DHCPNAK MUST carry
    the Server Identifier option (54); DHCPOFFER additionally
    MUST carry the IP Address Lease Time option (51). The
    parser raises Dhcp4SanityError when any of these required
    options is absent for the corresponding message type.
    """

    @staticmethod
    def _options_for(message_type: int, *, with_server_id: bool, with_lease_time: bool) -> bytes:
        """
        Build a custom options block for the sanity tests.
        """

        block = bytes([0x35, 0x01, message_type])  # Message Type
        if with_server_id:
            block += b"\x36\x04\x0a\x00\x01\x01"  # Server Identifier 10.0.1.1
        if with_lease_time:
            block += b"\x33\x04\x00\x00\x0e\x10"  # Lease Time 3600s
        block += b"\xff"  # End
        return block

    def test__dhcp4__parser__sanity__offer_missing_server_id_rejected(self) -> None:
        """
        Ensure an OFFER frame that omits the Server Identifier
        option (54) is rejected with Dhcp4SanityError.

        Reference: RFC 2131 §3 Table 3 / §4.3.6 (DHCPOFFER MUST include Server Identifier).
        """

        frame = _dhcp4_frame(options=self._options_for(0x02, with_server_id=False, with_lease_time=True))

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "DHCPv4 OFFER message MUST carry a Server Identifier option",
            str(error.exception),
            msg="OFFER without Server Identifier must be rejected with cited message.",
        )

    def test__dhcp4__parser__sanity__offer_missing_lease_time_rejected(self) -> None:
        """
        Ensure an OFFER frame that omits the IP Address Lease
        Time option (51) is rejected with Dhcp4SanityError.

        Reference: RFC 2131 §3 Table 3 / §4.3.1 (DHCPOFFER MUST include IP Address Lease Time).
        """

        frame = _dhcp4_frame(options=self._options_for(0x02, with_server_id=True, with_lease_time=False))

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "DHCPv4 OFFER message MUST carry an IP Address Lease Time option",
            str(error.exception),
            msg="OFFER without Lease Time must be rejected with cited message.",
        )

    def test__dhcp4__parser__sanity__ack_missing_server_id_rejected(self) -> None:
        """
        Ensure an ACK frame that omits the Server Identifier
        option (54) is rejected with Dhcp4SanityError.

        Reference: RFC 2131 §3 Table 3 / §4.3.6 (DHCPACK MUST include Server Identifier).
        """

        frame = _dhcp4_frame(options=self._options_for(0x05, with_server_id=False, with_lease_time=True))

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "DHCPv4 ACK message MUST carry a Server Identifier option",
            str(error.exception),
            msg="ACK without Server Identifier must be rejected with cited message.",
        )

    def test__dhcp4__parser__sanity__nak_missing_server_id_rejected(self) -> None:
        """
        Ensure a NAK frame that omits the Server Identifier
        option (54) is rejected with Dhcp4SanityError.

        Reference: RFC 2131 §3 Table 3 / §4.3.6 (DHCPNAK MUST include Server Identifier).
        """

        frame = _dhcp4_frame(options=self._options_for(0x06, with_server_id=False, with_lease_time=False))

        with self.assertRaises(Dhcp4SanityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "DHCPv4 NAK message MUST carry a Server Identifier option",
            str(error.exception),
            msg="NAK without Server Identifier must be rejected with cited message.",
        )

    def test__dhcp4__parser__sanity__discover_without_server_id_accepted(self) -> None:
        """
        Ensure a DISCOVER frame (client-emitted message type)
        does NOT require the Server Identifier option — only
        server-response messages do.

        Reference: RFC 2131 §3 Table 3 (Server Identifier is REQUIRED only on OFFER/ACK/NAK).
        """

        # DISCOVER (message type 1), no server_id, no lease_time.
        # Per RFC 2131 the client emits DISCOVER without these.
        frame = _dhcp4_frame(
            op=0x01,  # BOOTREQUEST
            options=self._options_for(0x01, with_server_id=False, with_lease_time=False),
        )

        Dhcp4Parser(frame)

    def test__dhcp4__parser__sanity__nak_with_server_id_accepted(self) -> None:
        """
        Ensure a NAK frame that carries the Server Identifier
        option but no Lease Time passes the sanity check — the
        RFC mandates Server Identifier on NAK but explicitly
        forbids Lease Time on NAK.

        Reference: RFC 2131 §3 Table 3 (DHCPNAK requires Server Identifier; MUST NOT include Lease Time).
        """

        frame = _dhcp4_frame(options=self._options_for(0x06, with_server_id=True, with_lease_time=False))

        Dhcp4Parser(frame)
