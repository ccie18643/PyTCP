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
Integration tests for the Packet Handler ARP RX operations,
migrated to 'ArpTestCase'. The legacy fixture-style copy is
preserved at 'pytcp/tests/integration/packet_handler/test__packet_handler__arp__rx.py'
for reference; this file is the canonical migration target.

pytcp/tests/integration/protocols/arp/test__arp__rx.py

ver 3.0.8
"""

from net_addr import Ip4Address, MacAddress
from net_proto import ArpOperation
from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.arp_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    IP4__UNSPECIFIED,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)
from pytcp.tests.lib.parameterized import parameterized_class

# Shorter aliases used inside the parametrized fixtures.
_STACK_MAC = STACK__MAC_ADDRESS
_STACK_IP = STACK__IP4_HOST.address
_CANDIDATE_IP = STACK__IP4_HOST__CANDIDATE.address
_PEER_MAC = HOST_A__MAC_ADDRESS
_PEER_IP = HOST_A__IP4_ADDRESS
_PEER_B_IP = HOST_B__IP4_ADDRESS
_BCAST_MAC = MAC__BROADCAST
_UNSPEC_MAC = MAC__UNSPECIFIED
_UNSPEC_IP = IP4__UNSPECIFIED

# Cases involving a foreign-subnet SPA / unusual MACs.
_FOREIGN_MAC = MacAddress("52:54:00:df:85:37")
_FOREIGN_IP = Ip4Address("192.168.9.102")
_FOREIGN_TPA = Ip4Address("192.168.9.55")
_MCAST_MAC = MacAddress("01:00:5e:00:00:01")
_GRATUITOUS_PEER_IP = Ip4Address("10.0.1.145")


@parameterized_class(
    [
        # ---------------------------------------------------------
        # ARP Request — TPA matching, not matching, opcode handling
        # ---------------------------------------------------------
        {
            "_description": "Request, unknown TPA on local network — drop reply, learn ARP",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tpa=_PEER_B_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_unknown=1,
                arp__op_request__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Request, unknown TPA on foreign subnet — drop, no cache update",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_FOREIGN_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_FOREIGN_MAC,
                    arp_spa=_FOREIGN_IP,
                    arp_tpa=_FOREIGN_TPA,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_unknown=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Request for stack MAC, broadcasted — reply + learn",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_PEER_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_STACK_MAC,
                    arp_spa=_STACK_IP,
                    arp_tha=_PEER_MAC,
                    arp_tpa=_PEER_IP,
                ),
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_stack=1,
                arp__op_request__respond=1,
                arp__op_request__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Request for stack MAC, unicasted — reply + learn",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_STACK_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_PEER_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_STACK_MAC,
                    arp_spa=_STACK_IP,
                    arp_tha=_PEER_MAC,
                    arp_tpa=_PEER_IP,
                ),
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_stack=1,
                arp__op_request__respond=1,
                arp__op_request__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Request from foreign SPA for our IP — respond, no cache update",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_FOREIGN_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_FOREIGN_MAC,
                    arp_spa=_FOREIGN_IP,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_FOREIGN_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_STACK_MAC,
                    arp_spa=_STACK_IP,
                    arp_tha=_FOREIGN_MAC,
                    arp_tpa=_FOREIGN_IP,
                ),
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_stack=1,
                arp__op_request__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        # ---------------------------------------------------------
        # ARP probe paths
        # ---------------------------------------------------------
        {
            "_description": "Probe (SPA=0.0.0.0) for stack IP, broadcast — reply, no learn",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_PEER_MAC,
                    arp_spa=_UNSPEC_IP,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_PEER_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_STACK_MAC,
                    arp_spa=_STACK_IP,
                    arp_tha=_PEER_MAC,
                    arp_tpa=_UNSPEC_IP,
                ),
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__probe=1,
                arp__op_request__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        # ---------------------------------------------------------
        # Loopback drops (frame sourced from our own MAC)
        # ---------------------------------------------------------
        {
            "_description": "Request looped back from our own MAC — drop",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_STACK_MAC,
                    arp_spa=_STACK_IP,
                    arp_tpa=_PEER_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__looped__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Probe looped back from our own MAC — drop",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_STACK_MAC,
                    arp_spa=_UNSPEC_IP,
                    arp_tpa=_PEER_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__looped__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Reply looped back from our own MAC — drop",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_STACK_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_STACK_MAC,
                    arp_spa=_STACK_IP,
                    arp_tha=_UNSPEC_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__looped__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        # ---------------------------------------------------------
        # Sanity / integrity drops at the parser layer
        # ---------------------------------------------------------
        {
            "_description": "Request with SHA = unspecified — drop at parser",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_UNSPEC_MAC,
                    arp_spa=_UNSPEC_IP,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Unsupported ArpOperation = 3 — drop at parser",
            # Wire frame carries a raw uint16 oper = 3; the sanity
            # check at 'arp__parser.py' rejects via
            # 'ArpOperation.from_int(3).is_unknown'. The TX-strict
            # 'ArpAssembler' refuses to construct such a frame on
            # principle, so the test bypasses via the raw-oper
            # builder.
            "_frames_rx": [
                ArpTestCase._build_arp_frame_with_raw_oper(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper_raw=3,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Reply with unspecified SHA — drop at parser",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_STACK_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_UNSPEC_MAC,
                    arp_spa=_PEER_IP,
                    arp_tha=_STACK_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Reply with multicast SHA — drop at parser",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_STACK_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_MCAST_MAC,
                    arp_spa=_PEER_IP,
                    arp_tha=_STACK_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Reply with broadcast SHA — drop at parser",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_STACK_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_BCAST_MAC,
                    arp_spa=_PEER_IP,
                    arp_tha=_STACK_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        # ---------------------------------------------------------
        # Gratuitous Request / Reply — learn or conflict
        # ---------------------------------------------------------
        {
            "_description": "Gratuitous Request: SPA == TPA, broadcast — no reply, learn",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tpa=_PEER_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__gratuitous=1,
                arp__op_request__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        # ---------------------------------------------------------
        # ARP Reply — direct / gratuitous / cache-update branches
        # ---------------------------------------------------------
        {
            "_description": "Reply, direct unicast to us — learn ARP cache",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_STACK_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tha=_STACK_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__direct=1,
                arp__op_reply__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Reply, direct to our MAC, foreign-subnet SPA — direct, no cache update",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_STACK_MAC,
                    ethernet_src=_FOREIGN_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_FOREIGN_MAC,
                    arp_spa=_FOREIGN_IP,
                    arp_tha=_STACK_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__direct=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Gratuitous Reply, broadcast, SPA == TPA on local subnet — learn",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_PEER_MAC,
                    arp_spa=_GRATUITOUS_PEER_IP,
                    arp_tpa=_GRATUITOUS_PEER_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__gratuitous=1,
                arp__op_reply__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Gratuitous Reply, broadcast, SPA == TPA on foreign subnet — no cache update",
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_FOREIGN_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_FOREIGN_MAC,
                    arp_spa=_FOREIGN_IP,
                    arp_tpa=_FOREIGN_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__gratuitous=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Reply, broadcast non-gratuitous (SPA != TPA, THA set) — cache update only",
            # Pins the current cache-injection-permissive behaviour
            # for non-RFC-defined broadcast Replies on the local
            # subnet. Future hardening here would require deliberate
            # test changes.
            "_frames_rx": [
                ArpTestCase._build_arp_frame(
                    ethernet_dst=_BCAST_MAC,
                    ethernet_src=_PEER_MAC,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=_PEER_MAC,
                    arp_spa=_PEER_IP,
                    arp_tha=_STACK_MAC,
                    arp_tpa=_STACK_IP,
                ),
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestArpRx(ArpTestCase):
    """
    The Packet Handler ARP RX tests — RFC 826 Packet Reception
    algorithm plus RFC 5227 §2.1.1 / §2.4 / §2.5 host-side ARP
    behaviours (probe handling, conflict detection and defence,
    continuing operation).
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    def test__arp__rx(self) -> None:
        """
        Ensure the Packet Handler RX path produces the expected
        wire frames, RX stats, and TX stats for each parametrized
        case.

        Reference: RFC 826 (foundational ARP wire format and Packet Reception algorithm).
        Reference: RFC 5227 §2.1.1 (ARP probe wire format and probe-conflict detection).
        Reference: RFC 5227 §2.4 (ongoing conflict detection and defense).
        Reference: RFC 5227 §2.5 (continuing operation: respond to ARP Requests for our IPs).
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
            msg=f"Unexpected RX packet stats for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )
