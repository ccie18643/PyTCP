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
This module contains integration tests for the RFC 5227 'Ip4Acd'
engine driving probe / announce over a real AF_PACKET socket: probes
egress the interface's TxRing, and a conflict captured off the socket
ends the probe.

pytcp/tests/integration/protocols/ip4/test__ip4__acd_engine.py

ver 3.0.8
"""

from typing import Any, cast, override
from unittest.mock import patch

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler
from pytcp.protocols.arp import arp__constants
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd
from pytcp.runtime.socket import ETH_P_ARP, SOCK_RAW, AddressFamily, socket
from pytcp.runtime.socket.packet__metadata import PacketMetadata
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl
from pytcp.tests.lib.network_testcase import STACK__MAC_ADDRESS, NetworkTestCase

_CANDIDATE = Ip4Address("10.0.1.50")
_PEER_MAC = MacAddress("02:00:00:00:00:99")


def _conflict_frame() -> bytes:
    """
    Build an ARP reply from a peer already using the candidate address.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_PEER_MAC,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REPLY,
                arp__sha=_PEER_MAC,
                arp__spa=_CANDIDATE,
                arp__tha=MacAddress(),
                arp__tpa=_CANDIDATE,
            ),
        )
    )


class TestIp4AcdEngine(NetworkTestCase):
    """
    The RFC 5227 'Ip4Acd' probe / announce integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the mock network, collapse the RFC 5227 timers to zero so
        the probe / announce windows elapse instantly, and suppress
        packet-socket log output.
        """

        super().setUp()
        self.enterContext(patch("pytcp.runtime.socket.packet__socket.log"))
        self.enterContext(patch("pytcp.protocols.ip4.acd.ip4_acd.random.uniform", return_value=0.0))
        self.enterContext(patch.object(arp__constants, "ARP__ANNOUNCE_WAIT", 0))
        self.enterContext(patch.object(arp__constants, "ARP__ANNOUNCE_INTERVAL", 0))

        self._ifindex = self._packet_handler._ifindex
        self._acd = Ip4Acd(mac_address=STACK__MAC_ADDRESS, ifindex=self._ifindex)
        self._tx_ring = cast(Any, self._packet_handler._tx_ring)

    def _arp_socket(self) -> PacketSocket:
        """
        Open a non-blocking AF_PACKET (ARP) socket bound to the boot
        interface, with cleanup registered.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW, protocol=ETH_P_ARP)
        assert isinstance(sock, PacketSocket)
        sock.bind(SockAddrLl(ifindex=self._ifindex, ethertype=ETH_P_ARP))
        sock.setblocking(False)
        self.addCleanup(sock.close)
        return sock

    def test__ip4_acd__probe_clean_succeeds_and_emits_probes(self) -> None:
        """
        Ensure a clean probe (no conflicting ARP) succeeds and emits
        PROBE_NUM ARP Probes onto the interface's TxRing.

        Reference: RFC 5227 §2.1.1 (PROBE_NUM Probes, no conflict).
        """

        result = self._acd.probe(address=_CANDIDATE)

        self.assertTrue(result.success, msg="A clean probe must succeed.")
        self.assertEqual(
            self._tx_ring.enqueue_raw_frame.call_count,
            arp__constants.ARP__PROBE_NUM,
            msg="A clean probe must emit exactly PROBE_NUM ARP Probes.",
        )

    def test__ip4_acd__probe_detects_conflict(self) -> None:
        """
        Ensure a probe that observes an ARP for the candidate from a
        peer fails and reports the conflicting peer MAC.

        Reference: RFC 5227 §2.1.1 (probe aborts on observed conflict).
        """

        sock = self._arp_socket()
        sock.process_packet(PacketMetadata(frame=_conflict_frame(), sockaddr_ll=SockAddrLl(ifindex=self._ifindex)))

        result = self._acd._run_probe(sock, _CANDIDATE)

        self.assertFalse(result.success, msg="A probe observing a conflict must fail.")
        self.assertEqual(
            result.conflict_mac,
            _PEER_MAC,
            msg="The probe result must report the conflicting peer MAC.",
        )

    def test__ip4_acd__announce_emits_announce_num_frames(self) -> None:
        """
        Ensure 'announce' emits ANNOUNCE_NUM gratuitous ARPs onto the
        interface's TxRing.

        Reference: RFC 5227 §2.3 (ANNOUNCE_NUM Announcements).
        """

        self._acd.announce(address=_CANDIDATE)

        self.assertEqual(
            self._tx_ring.enqueue_raw_frame.call_count,
            arp__constants.ARP__ANNOUNCE_NUM,
            msg="announce must emit exactly ANNOUNCE_NUM ARP Announcements.",
        )

    def test__ip4_acd__claim_clean_holds_defense_socket(self) -> None:
        """
        Ensure a clean 'claim' probes, announces, and leaves the defense
        socket open so the address can be guarded afterward.

        Reference: RFC 5227 §2.1.1 / §2.3 (claim = probe + announce).
        """

        result = self._acd.claim(address=_CANDIDATE)
        self.addCleanup(self._acd.release)

        self.assertTrue(result.success, msg="A clean claim must succeed.")
        self.assertIsNotNone(
            self._acd._sock,
            msg="A clean claim must hold the defense socket open.",
        )
        self.assertEqual(
            self._tx_ring.enqueue_raw_frame.call_count,
            arp__constants.ARP__PROBE_NUM + arp__constants.ARP__ANNOUNCE_NUM,
            msg="A clean claim must emit PROBE_NUM Probes plus ANNOUNCE_NUM Announcements.",
        )

    def test__ip4_acd__start_defense_announces_and_holds_socket(self) -> None:
        """
        Ensure 'start_defense' announces an already-probed address
        (ANNOUNCE_NUM gratuitous ARPs) and holds the defense socket
        open for ongoing conflict polling, WITHOUT re-running the
        probe — the entry point a client whose probe and commit are
        separated by a wire exchange (DHCPv4) uses to begin §2.4
        defense after the lease ACK.

        Reference: RFC 5227 §2.3 (Announcements after claim).
        Reference: RFC 5227 §2.4 (ongoing defense over the held socket).
        """

        self._acd.start_defense(address=_CANDIDATE)
        self.addCleanup(self._acd.release)

        self.assertIsNotNone(
            self._acd._sock,
            msg="start_defense must hold the defense socket open.",
        )
        self.assertEqual(
            self._acd._claimed,
            _CANDIDATE,
            msg="start_defense must record the claimed address for poll_conflict / defend.",
        )
        self.assertEqual(
            self._tx_ring.enqueue_raw_frame.call_count,
            arp__constants.ARP__ANNOUNCE_NUM,
            msg="start_defense must emit exactly ANNOUNCE_NUM Announcements and no Probes.",
        )

    def test__ip4_acd__poll_conflict_detects_then_drains(self) -> None:
        """
        Ensure 'poll_conflict' reports the peer MAC of an ARP using the
        claimed address, then returns None once the socket is drained.

        Reference: RFC 5227 §2.4 (ongoing conflict detection).
        """

        self._acd.claim(address=_CANDIDATE)
        self.addCleanup(self._acd.release)
        assert self._acd._sock is not None
        cast(PacketSocket, self._acd._sock).process_packet(
            PacketMetadata(frame=_conflict_frame(), sockaddr_ll=SockAddrLl(ifindex=self._ifindex))
        )

        self.assertEqual(
            self._acd.poll_conflict(),
            _PEER_MAC,
            msg="poll_conflict must report the conflicting peer MAC.",
        )
        self.assertIsNone(
            self._acd.poll_conflict(),
            msg="poll_conflict must return None once the socket is drained.",
        )

    def test__ip4_acd__defend_emits_gratuitous_arp(self) -> None:
        """
        Ensure 'defend' broadcasts one defensive gratuitous ARP for the
        claimed address onto the interface's TxRing.

        Reference: RFC 5227 §2.4(b) (single defensive ARP).
        """

        self._acd.claim(address=_CANDIDATE)
        self.addCleanup(self._acd.release)
        self._tx_ring.enqueue_raw_frame.reset_mock()

        self._acd.defend()

        self._tx_ring.enqueue_raw_frame.assert_called_once()

    def test__ip4_acd__release_closes_defense_socket(self) -> None:
        """
        Ensure 'release' drops the claim and closes the defense socket,
        and is idempotent on a second call.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._acd.claim(address=_CANDIDATE)

        self._acd.release()
        self._acd.release()

        self.assertIsNone(self._acd._sock, msg="release must close and clear the defense socket.")
