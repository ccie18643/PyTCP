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
This module contains integration tests for the IPv6 TX packet-handler path.

pytcp/tests/integration/protocols/ip6/test__ip6__tx.py

ver 3.0.10
"""

from typing import Any, override

from net_addr import Ip6Address
from net_proto import (
    Icmp6Assembler,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdOptions,
    IpProto,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__report import (
    Icmp6Mld2MessageReport,
)
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.ip6_testcase import Ip6TestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_B__IP6_ADDRESS,
    HOST_C__IP6_ADDRESS,
    IP6__MULTICAST__ALL_NODES,
    IP6__UNSPECIFIED,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv6 - src valid, dst unicast local network",
            "_clear_ip6_host": False,
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0000 (0 bytes)
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # Summary: Minimal IPv6 header-only datagram sent by the stack host to
                #          host A on the local LAN.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src not owned drop, dst unicast local network",
            "_clear_ip6_host": False,
            "_kwargs": {
                "ip6__src": HOST_B__IP6_ADDRESS,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP6__SRC_NOT_OWNED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_not_owned__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src multicast replace, dst unicast local network",
            "_clear_ip6_host": False,
            "_kwargs": {
                "ip6__src": IP6__MULTICAST__ALL_NODES,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (multicast source replaced)
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0000 (0 bytes)
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7 (multicast replaced)
                #   Destination IP : 2001:db8:0:1::91
                #
                # Summary: Multicast source address normalised to the stack host before
                #          emitting the minimal IPv6 datagram toward host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_multicast__replace=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src multicast drop, dst unicast local network",
            "_clear_ip6_host": True,
            "_kwargs": {
                "ip6__src": IP6__MULTICAST__ALL_NODES,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP6__SRC_MULTICAST,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_multicast__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified replace, dst unicast local network",
            "_clear_ip6_host": False,
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07 (unspecified source filled)
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0000 (0 bytes)
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7 (unspecified replaced)
                #   Destination IP : 2001:db8:0:1::91
                #
                # Summary: Unspecified source address substituted with the stack host before
                #          dispatching the header-only IPv6 frame to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_network_unspecified__replace_local=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified replace, dst unicast external network",
            "_clear_ip6_host": False,
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:01 (gateway)
                #   Source MAC      : 02:00:00:00:00:07 (unspecified source filled)
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0x0000 (0 bytes)
                #   Next Header    : 255 (Reserved)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7 (unspecified replaced)
                #   Destination IP : 2001:db8:0:2::50
                #
                # Summary: Header-only IPv6 datagram forwarded via the gateway MAC toward
                #          external host 2001:db8:0:2::50.
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x50"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_network_unspecified__replace_external=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified drop, dst unicast local network",
            "_clear_ip6_host": True,
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP6__SRC_UNSPECIFIED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_unspecified__drop=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src valid, dst unspecified drop",
            "_clear_ip6_host": False,
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPPED__IP6__DST_UNSPECIFIED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__dst_unspecified__drop=1,
            ),
        },
        {
            "_description": ("Ethernet/IPv6 - src unspecified accepted for ICMPv6 ND DAD probe (NS, no options)"),
            "_clear_ip6_host": False,
            "_kwargs": {
                # DAD probe: src=:: + ICMPv6 NS payload with no options + dst=solicited-node multicast
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": Ip6Address("ff02::1:ff00:5"),
                "ip6__hop": 255,
                "ip6__payload": Icmp6Assembler(
                    icmp6__message=Icmp6NdMessageNeighborSolicitation(
                        target_address=Ip6Address("2001:db8:0:1::5"),
                        options=Icmp6NdOptions(),
                    ),
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:05 (solicited-node multicast for ::5)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd
                # IPv6
                #   Source IP       : ::                       (DAD probe — unspecified accepted)
                #   Destination IP  : ff02::1:ff00:5
                #   Hop Limit       : 255
                # ICMPv6 ND Neighbor Solicitation
                #   Type/Code       : 135 / 0, target=2001:db8:0:1::5, no options
                b"\x33\x33\xff\x00\x00\x05\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x3a\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x05\x87\x00\x4c\xe4\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x05",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_unspecified__send=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified accepted for ICMPv6 MLDv2 Report",
            "_clear_ip6_host": False,
            "_kwargs": {
                # MLDv2 report: src=:: + ICMPv6 MLDv2 Report payload + dst=ff02::16
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": Ip6Address("ff02::16"),
                "ip6__hop": 1,
                "ip6__payload": Icmp6Assembler(
                    icmp6__message=Icmp6Mld2MessageReport(records=[]),
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:16 (MLDv2 routers)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86dd
                # IPv6
                #   Source IP       : ::          (MLDv2 — unspecified accepted)
                #   Destination IP  : ff02::16
                #   Hop Limit       : 1
                # ICMPv6 MLDv2 Report
                #   Type/Code       : 143 / 0, 0 records
                b"\x33\x33\x00\x00\x00\x16\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x08\x3a\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x16\x8f\x00\x71\xa4\x00\x00\x00\x00",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_unspecified__send=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        },
    ]
)
class TestIp6Tx(Ip6TestCase):
    """
    The IPv6 TX packet-handler path tests (success path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _clear_ip6_host: bool
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__ip6__tx(self) -> None:
        """
        Ensure the Packet Handler IPv6 TX path produces the expected
        frames, statuses, and statistics for each parametrized case.

        Reference: RFC 8200 §3 (IPv6 TX).
        """

        if self._clear_ip6_host:
            self._packet_handler._ip6_ifaddr = []

        self.assertEqual(
            self._packet_handler._phtx_ip6(**self._kwargs),
            self._expected__tx_status,
            msg=f"Unexpected TxStatus for case: {self._description}",
        )

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "_phtx_ip6 - ip6__hop == 0 fails the 0 < hop < 256 assert",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
                "ip6__hop": 0,
            },
            "_expected__error": AssertionError(),
        },
        {
            "_description": "_phtx_ip6 - ip6__hop == 256 fails the 0 < hop < 256 assert",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
                "ip6__hop": 256,
            },
            "_expected__error": AssertionError(),
        },
    ]
)
class TestIp6TxErrors(Ip6TestCase):
    """
    The IPv6 TX packet-handler path tests (error path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__error: Exception

    def test__ip6__tx__error(self) -> None:
        """
        Ensure '_phtx_ip6' raises the expected exception for invalid kwargs.

        Reference: RFC 8200 §3 (IPv6 TX).
        """

        with self.assertRaises(type(self._expected__error)) as error:
            self._packet_handler._phtx_ip6(**self._kwargs)

        # AssertionError messages depend on '__debug__' and the assert
        # expression text; only assert the exception type is correct.
        self.assertIsInstance(
            error.exception,
            type(self._expected__error),
            msg=f"Unexpected exception type for case: {self._description}",
        )


class TestIp6TxNoIp6Support(Ip6TestCase):
    """
    The IPv6 TX packet-handler path tests for when IPv6 protocol support is
    disabled — '_phtx_ip6' must short-circuit before assembly.
    """

    @override
    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable IPv6 protocol
        support on the packet handler.
        """

        super().setUp()
        self._packet_handler._ip6_support = False

    def test__ip6__tx__no_ip6_support(self) -> None:
        """
        Ensure '_phtx_ip6' returns 'DROPPED__IP6__NO_PROTOCOL_SUPPORT'
        and bumps 'ip6__no_proto_support__drop' without emitting any
        frame when IPv6 support is disabled.

        Reference: RFC 8200 §3 (IPv6 TX).
        """

        tx_status = self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP6__NO_PROTOCOL_SUPPORT,
            msg="_phtx_ip6 must return DROPPED__IP6__NO_PROTOCOL_SUPPORT when IPv6 disabled.",
        )

        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when IPv6 protocol support is disabled.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__no_proto_support__drop=1,
            ),
            msg="Only ip6__pre_assemble and ip6__no_proto_support__drop must bump.",
        )


class TestIp6TxSendIp6Packet(Ip6TestCase):
    """
    Test the public 'send_ip6_packet' wrapper, which forwards into
    '_phtx_ip6' wrapping the user payload as a 'RawAssembler' and
    renaming the addressing kwargs.
    """

    def test__ip6__tx__send_ip6_packet(self) -> None:
        """
        Ensure 'send_ip6_packet' wraps the call to '_phtx_ip6' with
        a 'RawAssembler' payload using the supplied 'ip6__next' and
        the renamed addressing kwargs, producing a successful frame
        and matching stats.

        Reference: RFC 8200 §3 (IPv6 TX).
        """

        self._packet_handler.send_ip6_packet(
            ip6__local_address=STACK__IP6_HOST.address,
            ip6__remote_address=HOST_A__IP6_ADDRESS,
            ip6__next=IpProto.from_int(99),
            ip6__payload=b"\x00\x00\x00\x00",
        )

        # 'send_ip6_packet' is fire-and-forget (Phase 4b) — no
        # TxStatus return; assert on the emitted frame and stats.
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="send_ip6_packet must emit exactly one frame for a small RAW payload.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
            msg="send_ip6_packet stats must match a direct _phtx_ip6 RAW-payload call.",
        )


class TestIp6TxRfc4291LinkLocalScopeGate(Ip6TestCase):
    """
    The RFC 4007 §6 / RFC 4291 §2.5.6 link-local-scope-gate
    tests for explicit caller-supplied source addresses.

    A caller passing an owned link-local source with a
    non-link-local destination would otherwise emit a packet
    that violates the scope rule (no peer can route a reply
    back to fe80::ours). The TX path rejects such combinations
    with DROPPED__IP6__SRC_SCOPE_MISMATCH.
    """

    _LINK_LOCAL_SRC = Ip6Address("fe80::7")

    @override
    def setUp(self) -> None:
        """
        Add a link-local host to '_ip6_ifaddr' / '_ip6_unicast' so
        the caller-supplied fe80::7 source passes the ownership
        check and reaches the scope gate.
        """

        super().setUp()
        from net_addr import Ip6IfAddr

        link_local_host = Ip6IfAddr("fe80::7/64")
        self._packet_handler._ip6_ifaddr.append(link_local_host)

    def test__ip6__tx__link_local_src_global_dst__drops_scope_mismatch(self) -> None:
        """
        Ensure an explicit link-local source paired with a
        global-scope destination is rejected with
        DROPPED__IP6__SRC_SCOPE_MISMATCH — the resulting packet
        cannot be routed back to the link-local source so the
        kernel-equivalent action is to fail the send.

        Reference: RFC 4007 §6 (source scope must be >= destination scope).
        Reference: RFC 4291 §2.5.6 (link-local addresses MUST NOT
        leak off-link).
        """

        tx_status = self._packet_handler._phtx_ip6(
            ip6__src=self._LINK_LOCAL_SRC,
            ip6__dst=HOST_A__IP6_ADDRESS,
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP6__SRC_SCOPE_MISMATCH,
            msg="Link-local src + global dst must drop with SRC_SCOPE_MISMATCH.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted on a scope-mismatch drop.",
        )

    def test__ip6__tx__link_local_src_link_local_dst__sends(self) -> None:
        """
        Ensure an explicit link-local source paired with a
        link-local destination passes through unchanged — the
        canonical ND-traffic case where both endpoints share
        link-local scope.

        Reference: RFC 4007 §6 (same-scope traffic permitted).
        """

        # Use the fixture link-local gateway (in the ND cache
        # mock) so the test exercises the scope gate without
        # tripping a downstream ND cache miss.
        from pytcp.tests.lib.network_testcase import STACK__IP6_GATEWAY

        tx_status = self._packet_handler._phtx_ip6(
            ip6__src=self._LINK_LOCAL_SRC,
            ip6__dst=STACK__IP6_GATEWAY,
        )

        self.assertNotEqual(
            tx_status,
            TxStatus.DROPPED__IP6__SRC_SCOPE_MISMATCH,
            msg="Link-local src + link-local dst must NOT drop on scope mismatch.",
        )

    def test__ip6__tx__link_local_src_link_local_multicast_dst__sends(self) -> None:
        """
        Ensure an explicit link-local source paired with a
        link-local-scope multicast destination (ff02::/16)
        passes through — the canonical ND case (all-nodes
        ff02::1, solicited-node ff02::1:ff00::/104, all-routers
        ff02::2).

        Reference: RFC 4007 §6 (same-scope multicast permitted).
        Reference: RFC 4291 §2.7 (multicast scop nibble; ff02::
        is scope = link-local).
        """

        tx_status = self._packet_handler._phtx_ip6(
            ip6__src=self._LINK_LOCAL_SRC,
            ip6__dst=Ip6Address("ff02::1"),
        )

        self.assertNotEqual(
            tx_status,
            TxStatus.DROPPED__IP6__SRC_SCOPE_MISMATCH,
            msg="Link-local src + link-local multicast dst must NOT drop on scope mismatch.",
        )

    def test__ip6__tx__link_local_src_global_multicast_dst__drops(self) -> None:
        """
        Ensure an explicit link-local source paired with a
        global-scope multicast destination (ff0e::/16) is
        rejected — global multicast must use a global source.

        Reference: RFC 4007 §6 (source scope must be >= multicast scope).
        Reference: RFC 4291 §2.7 (multicast scop nibble; ff0e::
        is scope = global).
        """

        tx_status = self._packet_handler._phtx_ip6(
            ip6__src=self._LINK_LOCAL_SRC,
            ip6__dst=Ip6Address("ff0e::1"),
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__IP6__SRC_SCOPE_MISMATCH,
            msg="Link-local src + global multicast dst must drop with SRC_SCOPE_MISMATCH.",
        )

    def test__ip6__tx__global_src_global_dst__sends(self) -> None:
        """
        Ensure a global-scope source paired with a global-scope
        destination passes through unchanged — regression net
        for the common case.

        Reference: PyTCP test infrastructure (regression net).
        """

        tx_status = self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
        )

        self.assertNotEqual(
            tx_status,
            TxStatus.DROPPED__IP6__SRC_SCOPE_MISMATCH,
            msg="Global src + global dst must NOT drop on scope mismatch.",
        )


# IPv6 header lives at Ethernet offset 14; byte 7 within the IPv6
# header is the Hop Limit.
_IP6__HOP_LIMIT_OFFSET = 14 + 7


class TestIp6TxMulticastHopLimit(Ip6TestCase):
    """
    The IPv6 outbound multicast Hop-Limit default tests.

    Outbound IPv6 datagrams with a multicast destination default
    to Hop-Limit=1 (Linux 'IPV6_DEFAULT_MCASTHOPS') so multicast
    traffic does not leak past the local link unless the caller
    explicitly raises it — mirroring the IPv4 TTL=1 default.
    """

    def test__ip6__tx__multicast_dst_no_caller_hop__defaults_to_1(self) -> None:
        """
        Ensure outbound IPv6 datagrams with a multicast
        destination ship with Hop-Limit=1 when the caller does
        not specify 'ip6__hop' — multicast is local-link by
        default and only escapes when the sender explicitly opts
        in.

        Reference: Linux net/ipv6/af_inet6.c inet6_create
        (np->mcast_hops = IPV6_DEFAULT_MCASTHOPS = 1).
        """

        self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=IP6__MULTICAST__ALL_NODES,
        )

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Multicast outbound must emit exactly one frame.",
        )
        self.assertEqual(
            self._frames_tx[0][_IP6__HOP_LIMIT_OFFSET],
            1,
            msg="Multicast outbound datagrams must default to Hop-Limit=1.",
        )

    def test__ip6__tx__multicast_dst_caller_overrides_hop__preserved(self) -> None:
        """
        Ensure a caller-supplied 'ip6__hop' overrides the
        multicast-default of 1 — the sender can choose to
        multicast beyond the local link by raising the
        Hop-Limit.

        Reference: Linux net/ipv6/ip6_output.c ip6_sk_dst_hoplimit
        (explicit IPV6_MULTICAST_HOPS overrides the default).
        """

        self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=IP6__MULTICAST__ALL_NODES,
            ip6__hop=64,
        )

        self.assertEqual(
            self._frames_tx[0][_IP6__HOP_LIMIT_OFFSET],
            64,
            msg="Caller-supplied multicast Hop-Limit must be preserved verbatim.",
        )

    def test__ip6__tx__unicast_dst_no_caller_hop__defaults_to_64(self) -> None:
        """
        Ensure outbound IPv6 datagrams with a unicast
        destination retain the IP6__DEFAULT_HOP_LIMIT=64 default
        — regression net for the multicast carve-out so the
        unicast common path keeps working.

        Reference: PyTCP test infrastructure (regression net for
        the multicast Hop-Limit carve-out).
        """

        self._packet_handler._phtx_ip6(
            ip6__src=STACK__IP6_HOST.address,
            ip6__dst=HOST_A__IP6_ADDRESS,
        )

        self.assertEqual(
            self._frames_tx[0][_IP6__HOP_LIMIT_OFFSET],
            64,
            msg="Unicast outbound datagrams must keep the IP6__DEFAULT_HOP_LIMIT=64 default.",
        )
