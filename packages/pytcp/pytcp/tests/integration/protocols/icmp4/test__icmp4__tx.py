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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Fluent integration tests for the IPv4/ICMPv4 TX path. Mirrors the
parametrized cases in
'pytcp/tests/integration/packet_handler/test__packet_handler__icmp4__tx.py' onto
the 'IcmpTestCase' harness.

pytcp/tests/integration/protocols/icmp4/test__icmp4__tx.py

ver 3.0.10
"""

from net_addr import MacAddress
from net_proto import (
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp4Type,
)
from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
)
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)

_ECHO_PAYLOAD: bytes = b"0123456789ABCDEF" * 20

_DST_UNREACH_PAYLOAD: bytes = b"0123456789ABCDEF" * 100

# RFC 1812 §4.3.2.3 caps ICMP error payloads to fit a 576-byte IP
# packet. Icmp4MessageDestinationUnreachable.__post_init__ truncates
# the supplied 'data' to IP4__MIN_MTU(576) - IP4__HEADER__LEN(20) -
# ICMP4__DESTINATION_UNREACHABLE__LEN(8) = 548 bytes.
_DST_UNREACH_PAYLOAD__TRUNCATED: bytes = _DST_UNREACH_PAYLOAD[:548]


class TestIcmp4Tx__EchoRequest(IcmpTestCase):
    """
    Outbound ICMPv4 Echo Request via '_phtx_icmp4'.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            icmp4__message=Icmp4MessageEchoRequest(
                id=12345,
                seq=54320,
                data=_ECHO_PAYLOAD,
            ),
        )

    def test__icmp4__tx__echo_request__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp4' returns PASSED__ETHERNET__TO_TX_RING for
        a well-formed Echo Request to a host with a known ARP entry.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a normal Echo Request emission.",
        )

    def test__icmp4__tx__echo_request__emits_one_frame(self) -> None:
        """
        Ensure the Echo Request emission produces exactly one TX
        frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"Expected one TX frame for Echo Request, got {len(self._frames_tx)}: {self._frames_tx!r}",
        )

    def test__icmp4__tx__echo_request__message_fields(self) -> None:
        """
        Ensure the emitted Echo Request carries the supplied id, seq
        and data and uses ICMPv4 type=8 / code=0.

        Reference: RFC 792 (Echo / Echo Reply messages).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            type=int(Icmp4Type.ECHO_REQUEST),
            code=0,
            id=12345,
            seq=54320,
            mtu=None,
            data=_ECHO_PAYLOAD,
        )

    def test__icmp4__tx__echo_request__ip_layer(self) -> None:
        """
        Ensure the outbound Echo Request carries the supplied IPv4
        source and destination, TTL=64, and zero DSCP/ECN/Identification
        with no fragmentation flags.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            ip_src=STACK__IP4_HOST.address,
            ip_dst=HOST_A__IP4_ADDRESS,
            ip_ttl=64,
            ip_id=0,
            ip_dscp=0,
            ip_ecn=0,
            ip_df=False,
            ip_mf=False,
            ip_offset=0,
        )

    def test__icmp4__tx__echo_request__ethernet(self) -> None:
        """
        Ensure the outbound Echo Request Ethernet src/dst reflect
        the stack's MAC and the ARP-cached host A MAC respectively.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            eth_src=MacAddress("02:00:00:00:00:07"),
            eth_dst=MacAddress("02:00:00:00:00:91"),
        )

    def test__icmp4__tx__echo_request__packet_stats_tx(self) -> None:
        """
        Ensure the Echo Request emission bumps exactly the TX
        counters the legacy byte-equality matrix used to pin.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp4__pre_assemble=1,
            icmp4__echo_request__send=1,
            ip4__pre_assemble=1,
            ip4__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip4_lookup=1,
            ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
        )


class TestIcmp4Tx__EchoReply(IcmpTestCase):
    """
    Outbound ICMPv4 Echo Reply via '_phtx_icmp4'.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            icmp4__message=Icmp4MessageEchoReply(
                id=12345,
                seq=54320,
                data=_ECHO_PAYLOAD,
            ),
        )

    def test__icmp4__tx__echo_reply__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp4' returns PASSED__ETHERNET__TO_TX_RING for
        a normal Echo Reply emission.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a normal Echo Reply emission.",
        )

    def test__icmp4__tx__echo_reply__message_fields(self) -> None:
        """
        Ensure the emitted Echo Reply carries the supplied id, seq
        and data and uses ICMPv4 type=0 / code=0.

        Reference: RFC 792 (Echo / Echo Reply messages).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            type=int(Icmp4Type.ECHO_REPLY),
            code=0,
            id=12345,
            seq=54320,
            mtu=None,
            data=_ECHO_PAYLOAD,
        )

    def test__icmp4__tx__echo_reply__ip_layer(self) -> None:
        """
        Ensure the outbound Echo Reply carries the supplied IPv4
        source and destination and zero DSCP/ECN/Identification
        with no fragmentation flags.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            ip_src=STACK__IP4_HOST.address,
            ip_dst=HOST_A__IP4_ADDRESS,
            ip_ttl=64,
            ip_id=0,
            ip_dscp=0,
            ip_ecn=0,
            ip_df=False,
            ip_mf=False,
            ip_offset=0,
        )

    def test__icmp4__tx__echo_reply__packet_stats_tx(self) -> None:
        """
        Ensure the Echo Reply emission bumps exactly the TX counters
        the legacy byte-equality matrix used to pin.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

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


class TestIcmp4Tx__DestUnreachablePort(IcmpTestCase):
    """
    Outbound ICMPv4 Destination Unreachable (Port) via '_phtx_icmp4'.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler._phtx_icmp4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.PORT,
                data=_DST_UNREACH_PAYLOAD,
            ),
        )

    def test__icmp4__tx__dst_unreach_port__tx_status(self) -> None:
        """
        Ensure '_phtx_icmp4' returns PASSED__ETHERNET__TO_TX_RING for
        a Destination Unreachable Port emission.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Expected PASSED__ETHERNET__TO_TX_RING for a Destination Unreachable emission.",
        )

    def test__icmp4__tx__dst_unreach_port__message_fields(self) -> None:
        """
        Ensure the outbound Destination Unreachable carries
        type=3 / code=3 (Port), no MTU value (Port path has none),
        and the supplied data buffer.

        Reference: RFC 792 (Destination Unreachable Message).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            type=int(Icmp4Type.DESTINATION_UNREACHABLE),
            code=int(Icmp4DestinationUnreachableCode.PORT),
            id=None,
            seq=None,
            mtu=None,
            data=_DST_UNREACH_PAYLOAD__TRUNCATED,
        )

    def test__icmp4__tx__dst_unreach_port__ip_layer(self) -> None:
        """
        Ensure the outbound Destination Unreachable carries the
        expected IPv4 source/destination and TTL=64.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()
        probe = self._parse_tx_icmp4(self._frames_tx[0])

        self._assert_icmp4_message(
            probe,
            ip_src=STACK__IP4_HOST.address,
            ip_dst=HOST_A__IP4_ADDRESS,
            ip_ttl=64,
        )

    def test__icmp4__tx__dst_unreach_port__packet_stats_tx(self) -> None:
        """
        Ensure the Destination Unreachable Port emission bumps the
        port-specific TX counter alongside the assembly path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp4__pre_assemble=1,
            icmp4__destination_unreachable__port__send=1,
            ip4__pre_assemble=1,
            ip4__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip4_lookup=1,
            ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
        )


class TestIcmp4Tx__DestUnreachableUnsupportedCode(IcmpTestCase):
    """
    Outbound ICMPv4 Destination Unreachable with a non-PORT code.
    """

    def test__icmp4__tx__dst_unreach_non_port__drops(self) -> None:
        """
        Ensure '_phtx_icmp4' drops with TxStatus.DROPPED__ICMP4__UNKNOWN
        when asked to emit a Destination Unreachable with a code other
        than PORT, PROTOCOL, or NETWORK — the TX path only supports
        those subcases today, and the fall-through is a defensive drop
        with a counter bump rather than an exception.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        before = self._packet_handler._packet_stats_tx.icmp4__unknown__drop

        status = self._packet_handler._phtx_icmp4(
            ip4__src=STACK__IP4_HOST.address,
            ip4__dst=HOST_A__IP4_ADDRESS,
            icmp4__message=Icmp4MessageDestinationUnreachable(
                code=Icmp4DestinationUnreachableCode.HOST,
            ),
        )

        self.assertIs(
            status,
            TxStatus.DROPPED__ICMP4__UNKNOWN,
            msg="Unsupported code must return DROPPED__ICMP4__UNKNOWN.",
        )
        self.assertEqual(
            self._packet_handler._packet_stats_tx.icmp4__unknown__drop,
            before + 1,
            msg="Unsupported code must bump 'icmp4__unknown__drop'.",
        )


class TestIcmp4Tx__SendIcmp4Packet(IcmpTestCase):
    """
    Public 'send_icmp4_packet' wrapper that renames its kwargs into
    the form '_phtx_icmp4' expects.
    """

    def _drive(self) -> TxStatus:
        return self._packet_handler.send_icmp4_packet(
            ip4__local_address=STACK__IP4_HOST.address,
            ip4__remote_address=HOST_A__IP4_ADDRESS,
            icmp4__message=Icmp4MessageEchoRequest(id=1, seq=1, data=b""),
        )

    def test__icmp4__tx__send_icmp4_packet__tx_status(self) -> None:
        """
        Ensure 'send_icmp4_packet' returns the same TxStatus as a
        direct '_phtx_icmp4' call would.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._drive(),
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="send_icmp4_packet must propagate the underlying _phtx_icmp4 TxStatus.",
        )

    def test__icmp4__tx__send_icmp4_packet__emits_one_frame(self) -> None:
        """
        Ensure 'send_icmp4_packet' emits exactly one frame for a
        well-formed Echo Request.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg=f"send_icmp4_packet must emit exactly one frame, got {len(self._frames_tx)}: {self._frames_tx!r}",
        )

    def test__icmp4__tx__send_icmp4_packet__packet_stats_tx(self) -> None:
        """
        Ensure 'send_icmp4_packet' produces the same per-protocol
        stats as a direct '_phtx_icmp4' call would.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._drive()

        self._assert_packet_stats_tx(
            icmp4__pre_assemble=1,
            icmp4__echo_request__send=1,
            ip4__pre_assemble=1,
            ip4__mtu_ok__send=1,
            ethernet__pre_assemble=1,
            ethernet__src_unspec__fill=1,
            ethernet__dst_unspec__ip4_lookup=1,
            ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
        )
