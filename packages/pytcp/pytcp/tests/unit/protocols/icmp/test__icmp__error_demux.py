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
Unit tests for the embedded-header parser at
'pytcp/protocols/icmp/icmp__error_demux.py'. Pins the IP+L4
4-tuple extraction the upcoming ICMP demux phases rely on, plus the
RFC 5927 §4 sequence-in-window guard substrate (the embedded TCP
seq is exposed via 'embedded_seq').

pytcp/tests/unit/protocols/icmp/test__icmp__error_demux.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto import IpProto
from pytcp.protocols.icmp.icmp__error_demux import (
    EmbeddedL4,
    parse_embedded_l4,
)

# Embedded IPv4 + UDP (28 bytes total).
#   IPv4: ver=4, IHL=5, total_len=28, ttl=64, proto=17 (UDP)
#         src=10.0.1.7, dst=10.0.1.91
#   UDP : sport=12345, dport=54321, len=8, cksum=0
_EMBEDDED__IP4_UDP: bytes = (
    b"\x45\x00\x00\x1c\x00\x00\x40\x00\x40\x11\x90\x00\x0a\x00\x01\x07"
    b"\x0a\x00\x01\x5b\x30\x39\xd4\x31\x00\x08\x00\x00"
)

# Embedded IPv4 + TCP (40 bytes — IPv4 header + 20-byte TCP header).
#   IPv4: ver=4, IHL=5, total_len=40, ttl=64, proto=6 (TCP)
#         src=10.0.1.7, dst=10.0.1.91
#   TCP : sport=12345, dport=80, seq=0xdeadbeef, ack=0,
#         hlen=5, flags=SYN, win=65535, cksum=0, urp=0
_EMBEDDED__IP4_TCP: bytes = (
    b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x90\x0b\x0a\x00\x01\x07"
    b"\x0a\x00\x01\x5b\x30\x39\x00\x50\xde\xad\xbe\xef\x00\x00\x00\x00"
    b"\x50\x02\xff\xff\x00\x00\x00\x00"
)

# Embedded IPv6 + UDP (48 bytes — IPv6 header + UDP header).
#   IPv6: ver=6, plen=8, next=17 (UDP), hop=64
#         src=2001:db8:0:1::7, dst=2001:db8:0:1::91
#   UDP : sport=12345, dport=54321, len=8, cksum=0
_EMBEDDED__IP6_UDP: bytes = (
    b"\x60\x00\x00\x00\x00\x08\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x91\x30\x39\xd4\x31\x00\x08\x00\x00"
)

# Embedded IPv6 + TCP (60 bytes — IPv6 header + 20-byte TCP header).
#   IPv6: ver=6, plen=20, next=6 (TCP), hop=64
#         src=2001:db8:0:1::7, dst=2001:db8:0:1::91
#   TCP : sport=12345, dport=80, seq=0xdeadbeef, ack=0,
#         hlen=5, flags=SYN, win=65535, cksum=0, urp=0
_EMBEDDED__IP6_TCP: bytes = (
    b"\x60\x00\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01"
    b"\x00\x00\x00\x00\x00\x00\x00\x91\x30\x39\x00\x50\xde\xad\xbe\xef"
    b"\x00\x00\x00\x00\x50\x02\xff\xff\x00\x00\x00\x00"
)


class TestParseEmbeddedL4__Ip4Udp(TestCase):
    """
    The parse_embedded_l4 happy path for IPv4 + UDP.
    """

    def test__embedded_l4__ip4_udp__returns_embedded(self) -> None:
        """
        Ensure a valid IPv4+UDP embedded header decodes into an
        EmbeddedL4 with proto=UDP, swapped local/remote addressing,
        the wire ports and no embedded_seq.

        Reference: RFC 792 §2 (Destination Unreachable embeds inner header).
        """

        result = parse_embedded_l4(_EMBEDDED__IP4_UDP, IpVersion.IP4)

        self.assertEqual(
            result,
            EmbeddedL4(
                ip_version=IpVersion.IP4,
                proto=IpProto.UDP,
                local_ip=Ip4Address("10.0.1.7"),
                remote_ip=Ip4Address("10.0.1.91"),
                local_port=12345,
                remote_port=54321,
                embedded_seq=None,
            ),
            msg="parse_embedded_l4 must decode the IPv4+UDP 4-tuple from the embedded header.",
        )


class TestParseEmbeddedL4__Ip4Tcp(TestCase):
    """
    The parse_embedded_l4 happy path for IPv4 + TCP.
    """

    def test__embedded_l4__ip4_tcp__returns_embedded(self) -> None:
        """
        Ensure a valid IPv4+TCP embedded header decodes into an
        EmbeddedL4 with proto=TCP, the 4-tuple, and the embedded
        sequence number for the sequence-in-window guard.

        Reference: RFC 5927 §4 (TCP ICMP attack mitigations).
        """

        result = parse_embedded_l4(_EMBEDDED__IP4_TCP, IpVersion.IP4)

        self.assertEqual(
            result,
            EmbeddedL4(
                ip_version=IpVersion.IP4,
                proto=IpProto.TCP,
                local_ip=Ip4Address("10.0.1.7"),
                remote_ip=Ip4Address("10.0.1.91"),
                local_port=12345,
                remote_port=80,
                embedded_seq=0xDEADBEEF,
            ),
            msg="parse_embedded_l4 must decode the IPv4+TCP 4-tuple plus seq from the embedded header.",
        )


class TestParseEmbeddedL4__Ip6Udp(TestCase):
    """
    The parse_embedded_l4 happy path for IPv6 + UDP.
    """

    def test__embedded_l4__ip6_udp__returns_embedded(self) -> None:
        """
        Ensure a valid IPv6+UDP embedded header decodes into an
        EmbeddedL4 with proto=UDP and the IPv6 4-tuple.

        Reference: RFC 4443 §3 (ICMPv6 Destination Unreachable).
        """

        result = parse_embedded_l4(_EMBEDDED__IP6_UDP, IpVersion.IP6)

        self.assertEqual(
            result,
            EmbeddedL4(
                ip_version=IpVersion.IP6,
                proto=IpProto.UDP,
                local_ip=Ip6Address("2001:db8:0:1::7"),
                remote_ip=Ip6Address("2001:db8:0:1::91"),
                local_port=12345,
                remote_port=54321,
                embedded_seq=None,
            ),
            msg="parse_embedded_l4 must decode the IPv6+UDP 4-tuple from the embedded header.",
        )


class TestParseEmbeddedL4__Ip6Tcp(TestCase):
    """
    The parse_embedded_l4 happy path for IPv6 + TCP.
    """

    def test__embedded_l4__ip6_tcp__returns_embedded(self) -> None:
        """
        Ensure a valid IPv6+TCP embedded header decodes into an
        EmbeddedL4 with proto=TCP, the 4-tuple, and the embedded
        sequence number.

        Reference: RFC 5927 §4 (TCP ICMP attack mitigations).
        """

        result = parse_embedded_l4(_EMBEDDED__IP6_TCP, IpVersion.IP6)

        self.assertEqual(
            result,
            EmbeddedL4(
                ip_version=IpVersion.IP6,
                proto=IpProto.TCP,
                local_ip=Ip6Address("2001:db8:0:1::7"),
                remote_ip=Ip6Address("2001:db8:0:1::91"),
                local_port=12345,
                remote_port=80,
                embedded_seq=0xDEADBEEF,
            ),
            msg="parse_embedded_l4 must decode the IPv6+TCP 4-tuple plus seq from the embedded header.",
        )


class TestParseEmbeddedL4__Rejection(TestCase):
    """
    Rejection branches — every path that returns None.
    """

    def test__embedded_l4__truncated_below_ip4_header__none(self) -> None:
        """
        Ensure a frame shorter than the IPv4 header length returns
        None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            parse_embedded_l4(b"\x45\x00", IpVersion.IP4),
            msg="parse_embedded_l4 must return None on a truncated IPv4 header.",
        )

    def test__embedded_l4__bad_ip4_version__none(self) -> None:
        """
        Ensure a frame whose first nibble is not 4 returns None for
        IPv4 dispatch — guards against malformed embedded data.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bogus = b"\x00" * 28  # version nibble = 0
        self.assertIsNone(
            parse_embedded_l4(bogus, IpVersion.IP4),
            msg="parse_embedded_l4 must return None on an IPv4 version mismatch.",
        )

    def test__embedded_l4__ip4_ihl_too_small__none(self) -> None:
        """
        Ensure a frame with IHL < 5 (i.e. <20-byte IP header) returns
        None even if the full IPv4 minimum length is present.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # version=4, IHL=4 (16 bytes — invalid, RFC 791 mandates >= 5)
        bogus = bytearray(_EMBEDDED__IP4_UDP)
        bogus[0] = 0x44
        self.assertIsNone(
            parse_embedded_l4(bytes(bogus), IpVersion.IP4),
            msg="parse_embedded_l4 must return None when IHL is below the IPv4 minimum.",
        )

    def test__embedded_l4__ip4_unsupported_proto__none(self) -> None:
        """
        Ensure an embedded IPv4 packet whose protocol is not UDP/TCP
        returns None — the demux only consumes those two L4 types.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Replace proto byte (offset 9) with 1 (ICMP).
        bogus = bytearray(_EMBEDDED__IP4_UDP)
        bogus[9] = 1
        self.assertIsNone(
            parse_embedded_l4(bytes(bogus), IpVersion.IP4),
            msg="parse_embedded_l4 must return None for an unsupported embedded L4 protocol.",
        )

    def test__embedded_l4__ip4_truncated_l4__none(self) -> None:
        """
        Ensure a frame that contains the full IPv4 header but no L4
        payload bytes returns None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        truncated = _EMBEDDED__IP4_UDP[:20]  # IPv4 header only, no UDP
        self.assertIsNone(
            parse_embedded_l4(truncated, IpVersion.IP4),
            msg="parse_embedded_l4 must return None when L4 bytes are missing.",
        )

    def test__embedded_l4__truncated_below_ip6_header__none(self) -> None:
        """
        Ensure a frame shorter than the IPv6 header length returns
        None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            parse_embedded_l4(b"\x60\x00\x00\x00", IpVersion.IP6),
            msg="parse_embedded_l4 must return None on a truncated IPv6 header.",
        )

    def test__embedded_l4__bad_ip6_version__none(self) -> None:
        """
        Ensure a frame whose first nibble is not 6 returns None for
        IPv6 dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bogus = b"\x00" * 48  # version nibble = 0
        self.assertIsNone(
            parse_embedded_l4(bogus, IpVersion.IP6),
            msg="parse_embedded_l4 must return None on an IPv6 version mismatch.",
        )

    def test__embedded_l4__ip6_unsupported_proto__none(self) -> None:
        """
        Ensure an embedded IPv6 packet whose Next Header is not
        UDP/TCP returns None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Replace next-header byte (offset 6) with 0 (Hop-by-Hop options).
        bogus = bytearray(_EMBEDDED__IP6_UDP)
        bogus[6] = 0
        self.assertIsNone(
            parse_embedded_l4(bytes(bogus), IpVersion.IP6),
            msg="parse_embedded_l4 must return None for an unsupported embedded IPv6 next header.",
        )

    def test__embedded_l4__ip6_truncated_l4__none(self) -> None:
        """
        Ensure a frame that contains the full IPv6 header but no L4
        payload bytes returns None.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        truncated = _EMBEDDED__IP6_UDP[:40]  # IPv6 header only
        self.assertIsNone(
            parse_embedded_l4(truncated, IpVersion.IP6),
            msg="parse_embedded_l4 must return None when L4 bytes are missing.",
        )
