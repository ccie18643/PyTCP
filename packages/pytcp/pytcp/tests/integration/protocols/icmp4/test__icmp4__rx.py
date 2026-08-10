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
Fluent integration tests for the IPv4/ICMPv4 RX path. Mirrors the
parametrized cases in
'pytcp/tests/integration/packet_handler/test__packet_handler__icmp4__rx.py' onto
the 'IcmpTestCase' harness so subsequent ICMP-related work has a
maintainable behaviour-pin and so the legacy byte-equality matrix
can be retired once parity is proven through Phase 8.

pytcp/tests/integration/protocols/icmp4/test__icmp4__rx.py

ver 3.0.10
"""

from net_addr import Ip4Address, MacAddress
from net_proto import Icmp4Type
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

# 64-byte echo data payload — timestamp prefix + 0x10..0x3f pattern.
_ECHO_DATA: bytes = (
    b"\x88\x9f\xba\x60\x00\x00\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00"
    b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
)

# ICMPv4 Echo Request from host A to the stack.
#   Ethernet : dst=02:00:00:00:00:07, src=02:00:00:00:00:91, type=0x0800
#   IPv4     : src=10.0.1.91, dst=10.0.1.7, ttl=64, proto=1, total_len=92, DF=1
#   ICMPv4   : type=8, code=0, cksum=0xd97d, id=0x0007, seq=0x000a, data=_ECHO_DATA
_FRAME_RX__ECHO_REQUEST: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x5c\x3a\x2f\x40\x00\x40\x01\xea\x10\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x08\x00\xd9\x7d\x00\x07\x00\x0a"
) + _ECHO_DATA

# ICMPv4 Echo Reply from host A to the stack with no matching raw
# socket installed.
#   IPv4     : src=10.0.1.91, dst=10.0.1.7, ttl=64, total_len=33
#   ICMPv4   : type=0, code=0, cksum=0xbc1c, id=0x0007, seq=0x000a, data="hello"
_FRAME_RX__ECHO_REPLY_NO_SOCKET: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x21\x00\x00\x00\x00\x40\x01\x64\x7b\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x00\x00\xbc\x1c\x00\x07\x00\x0a\x68\x65\x6c\x6c\x6f"
)

# ICMPv4 frame carrying an unhandled type code (99).
#   IPv4     : total_len=24
#   ICMPv4   : type=99, code=0, cksum=0x9cff, no payload
_FRAME_RX__UNKNOWN_TYPE: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x18\x00\x00\x00\x00\x40\x01\x64\x84\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x63\x00\x9c\xff"
)

# ICMPv4 Source Quench (Type 4) — deprecated by RFC 6633.
#   IPv4     : total_len=24
#   ICMPv4   : type=4, code=0, cksum=0xfbff, no payload
# RFC 6633 §3 mandates silent discard. PyTCP's Icmp4Type enum has
# no SOURCE_QUENCH member, so Type 4 falls through to the unknown
# handler — which is exactly the spec-required behaviour.
_FRAME_RX__SOURCE_QUENCH: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x18\x00\x00\x00\x00\x40\x01\x64\x84\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x04\x00\xfb\xff"
)

# ICMPv4 Address Mask Request (Type 17) — deprecated by RFC 6918.
#   IPv4     : total_len=24
#   ICMPv4   : type=17, code=0, cksum=0xeeff, no payload
# Representative of the 15 ICMPv4 types that RFC 6918 deprecated
# en block. PyTCP's Icmp4Type enum has no entries for any of them,
# so they all fall through to the unknown handler. This frame pins
# the most well-known deprecated type as a regression guard.
_FRAME_RX__ADDR_MASK_REQUEST: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x18\x00\x00\x00\x00\x40\x01\x64\x84\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x11\x00\xee\xff"
)

# ICMPv4 Destination Unreachable carrying a valid embedded IPv4+UDP
# header but no UDP socket matches the resulting metadata.
#   IPv4     : total_len=56
#   ICMPv4   : type=3 (Destination Unreachable), code=3 (Port), cksum=0x8cf9
#              data = original IPv4 (20B) + UDP header (8B):
#                IPv4 : src=10.0.1.7, dst=10.0.1.91, total_len=28
#                UDP  : sport=12345, dport=54321, len=8, cksum=0
_FRAME_RX__DST_UNREACH_NO_SOCKET: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x38\x00\x00\x00\x00\x40\x01\x64\x64\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x03\x03\x8c\xf9\x00\x00\x00\x00\x45\x00\x00\x1c\x00\x00"
    b"\x40\x00\x40\x11\x90\x00\x0a\x00\x01\x07\x0a\x00\x01\x5b\x30\x39"
    b"\xd4\x31\x00\x08\x00\x00"
)

# ICMPv4 Destination Unreachable whose embedded data is 28 zero
# bytes (frame[0] >> 4 == 0, fails the 'IPv4 version' integrity
# check inside the embedded-header parse).
_FRAME_RX__DST_UNREACH_BAD_EMBEDDED: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x38\x00\x00\x00\x00\x40\x01\x64\x64\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x03\x03\xfc\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x00\x00\x00\x00\x00\x00"
)

# ICMPv4 message truncated to 4 bytes — below the 8-byte minimum
# Icmp4Parser expects for an Echo. Triggers a parse failure.
_FRAME_RX__TRUNCATED: bytes = (
    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
    b"\x00\x18\x00\x00\x00\x00\x40\x01\x64\x84\x0a\x00\x01\x5b\x0a\x00"
    b"\x01\x07\x08\x00\x00\x00"
)


class TestIcmp4Rx__EchoRequest(IcmpTestCase):
    """
    The IPv4 Echo Request → Echo Reply roundtrip.
    """

    def test__icmp4__rx__echo_request__emits_one_reply(self) -> None:
        """
        Ensure an inbound Echo Request produces exactly one TX frame.

        Reference: RFC 792 (Echo / Echo Reply messages).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)

        self.assertEqual(
            len(frames_tx),
            1,
            msg=f"Expected exactly one TX frame for Echo Request, got {len(frames_tx)}: {frames_tx!r}",
        )

    def test__icmp4__rx__echo_request__reply_message_fields(self) -> None:
        """
        Ensure the Echo Reply mirrors the request's id, seq and data
        and uses ICMPv4 type=0 / code=0.

        Reference: RFC 792 (Echo / Echo Reply messages).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)
        probe = self._parse_tx_icmp4(frames_tx[0])

        self._assert_icmp4_message(
            probe,
            type=int(Icmp4Type.ECHO_REPLY),
            code=0,
            id=7,
            seq=10,
            mtu=None,
            data=_ECHO_DATA,
        )

    def test__icmp4__rx__echo_request__reply_ip_layer(self) -> None:
        """
        Ensure the Echo Reply carries the expected IPv4 source and
        destination (swapped relative to the request), TTL=64,
        Identification=0, DSCP=0, ECN=0, and DF/MF/offset=0.

        Reference: RFC 792 (Echo / Echo Reply messages).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)
        probe = self._parse_tx_icmp4(frames_tx[0])

        self._assert_icmp4_message(
            probe,
            ip_src=Ip4Address("10.0.1.7"),
            ip_dst=Ip4Address("10.0.1.91"),
            ip_ttl=64,
            ip_id=0,
            ip_dscp=0,
            ip_ecn=0,
            ip_df=False,
            ip_mf=False,
            ip_offset=0,
        )

    def test__icmp4__rx__echo_request__reply_ethernet(self) -> None:
        """
        Ensure the Echo Reply Ethernet src/dst reflect the stack's
        MAC and the request sender's MAC respectively.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frames_tx = self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)
        probe = self._parse_tx_icmp4(frames_tx[0])

        self._assert_icmp4_message(
            probe,
            eth_src=MacAddress("02:00:00:00:00:07"),
            eth_dst=MacAddress("02:00:00:00:00:91"),
        )

    def test__icmp4__rx__echo_request__packet_stats_rx(self) -> None:
        """
        Ensure the inbound Echo Request bumps exactly the RX counters
        the legacy byte-equality matrix used to pin.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__echo_request__respond_echo_reply=1,
        )

    def test__icmp4__rx__echo_request__packet_stats_tx(self) -> None:
        """
        Ensure the outbound Echo Reply bumps exactly the TX counters
        the legacy byte-equality matrix used to pin.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REQUEST)

        self._assert_packet_stats_tx(
            icmp4__pre_assemble=1,
            icmp4__echo_reply__send=1,
            ip4__pre_assemble=1,
            ip4__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip4_lookup=1,
            ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
        )


class TestIcmp4Rx__EchoReplyNoSocket(IcmpTestCase):
    """
    Inbound Echo Reply with no RAW socket installed.
    """

    def test__icmp4__rx__echo_reply_no_socket__no_tx(self) -> None:
        """
        Ensure an Echo Reply with no matching RAW socket produces no
        TX frames — the stack swallows it silently.

        Reference: RFC 792 (Echo Reply).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REPLY_NO_SOCKET)

        self._assert_no_tx()

    def test__icmp4__rx__echo_reply_no_socket__packet_stats_rx(self) -> None:
        """
        Ensure the Echo Reply increments 'icmp4__echo_reply' but
        nothing else beyond the ethernet/IP RX accounting.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REPLY_NO_SOCKET)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__echo_reply=1,
        )

    def test__icmp4__rx__echo_reply_no_socket__packet_stats_tx(self) -> None:
        """
        Ensure no TX-side counters are bumped when the Echo Reply has
        nowhere to land.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__ECHO_REPLY_NO_SOCKET)

        self._assert_packet_stats_tx()


class TestIcmp4Rx__UnknownType(IcmpTestCase):
    """
    Inbound ICMPv4 frame carrying an unhandled type.
    """

    def test__icmp4__rx__unknown_type__no_tx(self) -> None:
        """
        Ensure an unknown ICMPv4 type produces no TX frames.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__UNKNOWN_TYPE)

        self._assert_no_tx()

    def test__icmp4__rx__unknown_type__packet_stats_rx(self) -> None:
        """
        Ensure an unhandled type is rejected at ICMPv4 parser sanity
        (bumps 'icmp4__failed_parse__drop' rather than falling through to
        a downstream dispatch).

        Reference: RFC 1122 §3.2.2 (hosts MUST silently discard unknown-type ICMP).
        """

        self._drive_rx(frame=_FRAME_RX__UNKNOWN_TYPE)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__failed_parse__drop=1,
        )

    def test__icmp4__rx__unknown_type__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the unknown-type path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__UNKNOWN_TYPE)

        self._assert_packet_stats_tx()


class TestIcmp4Rx__SourceQuench__Rfc6633(IcmpTestCase):
    """
    Inbound ICMPv4 Source Quench (Type 4) — formally deprecated by
    RFC 6633. PyTCP's Icmp4Type enum has no SOURCE_QUENCH member,
    so Type 4 falls through to the unknown-type handler, which
    silently discards the message. These tests pin that behaviour
    so a future enum addition cannot regress spec compliance.
    """

    def test__icmp4__rx__source_quench__no_tx(self) -> None:
        """
        Ensure an inbound Source Quench (Type 4) produces no TX
        frames — neither a transport-layer reaction nor an ICMP
        error.

        Reference: RFC 6633 §3 (host MUST NOT react to Source
        Quench; IP layer MAY silently discard).
        Reference: RFC 6633 §5 (UDP MUST silently discard).
        Reference: RFC 6633 §6 (other transports MUST silently
        ignore).
        """

        self._drive_rx(frame=_FRAME_RX__SOURCE_QUENCH)

        self._assert_no_tx()

    def test__icmp4__rx__source_quench__packet_stats_rx(self) -> None:
        """
        Ensure an inbound Source Quench is rejected at ICMPv4 parser
        sanity (bumps 'icmp4__failed_parse__drop') — Source Quench is
        deprecated and PyTCP's Icmp4Type enum has no entry for it, so
        the parser treats it as an unknown ICMPv4 type and silently
        discards at sanity.

        Reference: RFC 6633 §9 (Type 4 marked Deprecated in IANA ICMP Parameters registry).
        Reference: RFC 1122 §3.2.2 (unknown-type ICMP — silent discard at sanity).
        """

        self._drive_rx(frame=_FRAME_RX__SOURCE_QUENCH)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__failed_parse__drop=1,
        )

    def test__icmp4__rx__source_quench__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped when a Source Quench is
        received — the host neither generates an ICMP error in
        response nor signals a transport-layer reaction.

        Reference: RFC 6633 §3 (host MUST NOT send ICMP Source
        Quench, MUST NOT react to received Source Quench).
        """

        self._drive_rx(frame=_FRAME_RX__SOURCE_QUENCH)

        self._assert_packet_stats_tx()


class TestIcmp4Rx__DeprecatedTypes__Rfc6918(IcmpTestCase):
    """
    Inbound ICMPv4 message types deprecated en block by RFC 6918
    (15 types: 6, 15, 16, 17, 18, 30, 31, 32, 33, 34, 35, 36, 37,
    38, 39). PyTCP's Icmp4Type enum has no entries for any of
    them, so each falls through to the unknown-type handler and
    is silently discarded. Address Mask Request (Type 17) is the
    most well-known of the set and serves as a representative
    regression guard.
    """

    def test__icmp4__rx__addr_mask_request__no_tx(self) -> None:
        """
        Ensure an inbound Address Mask Request (Type 17) produces
        no TX frames — the host neither replies with an Address
        Mask Reply nor reacts to the deprecated message in any
        observable way.

        Reference: RFC 6918 §3 (IANA registry deprecation of 15
        ICMPv4 message types including Address Mask Request).
        Reference: RFC 6918 §2.4 (Address Mask Request superseded
        by DHCP).
        """

        self._drive_rx(frame=_FRAME_RX__ADDR_MASK_REQUEST)

        self._assert_no_tx()

    def test__icmp4__rx__addr_mask_request__packet_stats_rx(self) -> None:
        """
        Ensure an inbound Address Mask Request is rejected at ICMPv4
        parser sanity (bumps 'icmp4__failed_parse__drop') — Type 17 is
        deprecated and PyTCP's Icmp4Type enum has no entry for it.

        Reference: RFC 6918 §3 (Type 17 deprecated en block).
        Reference: RFC 1122 §3.2.2 (unknown-type ICMP — silent discard at sanity).
        """

        self._drive_rx(frame=_FRAME_RX__ADDR_MASK_REQUEST)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__failed_parse__drop=1,
        )


class TestIcmp4Rx__DestUnreachableNoSocket(IcmpTestCase):
    """
    Inbound ICMPv4 Destination Unreachable carrying a well-formed
    embedded IPv4+UDP that does not match any UDP socket.
    """

    def test__icmp4__rx__dst_unreach_no_socket__no_tx(self) -> None:
        """
        Ensure a Destination Unreachable that fails to find a UDP
        socket produces no TX frames.

        Reference: RFC 792 (Destination Unreachable Message).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_NO_SOCKET)

        self._assert_no_tx()

    def test__icmp4__rx__dst_unreach_no_socket__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp4__destination_unreachable' is incremented even
        when no UDP socket matches the embedded metadata.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_NO_SOCKET)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__destination_unreachable=1,
        )

    def test__icmp4__rx__dst_unreach_no_socket__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the unmatched
        Destination Unreachable path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_NO_SOCKET)

        self._assert_packet_stats_tx()


class TestIcmp4Rx__DestUnreachableBadEmbedded(IcmpTestCase):
    """
    Inbound ICMPv4 Destination Unreachable whose embedded data fails
    the IPv4-version integrity check inside the demux.
    """

    def test__icmp4__rx__dst_unreach_bad_embedded__no_tx(self) -> None:
        """
        Ensure a Destination Unreachable whose embedded data is not
        a valid IPv4 packet (version nibble = 0) produces no TX
        frames — the integrity gauntlet rejects it before any
        socket lookup.

        Reference: RFC 792 (Destination Unreachable Message).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_BAD_EMBEDDED)

        self._assert_no_tx()

    def test__icmp4__rx__dst_unreach_bad_embedded__packet_stats_rx(self) -> None:
        """
        Ensure 'icmp4__destination_unreachable' is incremented even
        when the embedded data is malformed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_BAD_EMBEDDED)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__destination_unreachable=1,
        )

    def test__icmp4__rx__dst_unreach_bad_embedded__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped when the embedded payload
        of a Destination Unreachable is malformed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__DST_UNREACH_BAD_EMBEDDED)

        self._assert_packet_stats_tx()


class TestIcmp4Rx__Truncated(IcmpTestCase):
    """
    Inbound ICMPv4 message truncated below the parser's minimum.
    """

    def test__icmp4__rx__truncated__no_tx(self) -> None:
        """
        Ensure a truncated ICMPv4 frame produces no TX — the parser
        raises before any message-type dispatch runs.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__TRUNCATED)

        self._assert_no_tx()

    def test__icmp4__rx__truncated__packet_stats_rx(self) -> None:
        """
        Ensure a truncated ICMPv4 frame bumps
        'icmp4__failed_parse__drop' and skips message dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__TRUNCATED)

        self._assert_packet_stats_rx(
            ethernet__pre_parse=1,
            ethernet__dst_unicast=1,
            ip4__pre_parse=1,
            ip4__dst_unicast=1,
            icmp4__pre_parse=1,
            icmp4__failed_parse__drop=1,
        )

    def test__icmp4__rx__truncated__packet_stats_tx(self) -> None:
        """
        Ensure no TX counters are bumped on the truncated-frame path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive_rx(frame=_FRAME_RX__TRUNCATED)

        self._assert_packet_stats_tx()
