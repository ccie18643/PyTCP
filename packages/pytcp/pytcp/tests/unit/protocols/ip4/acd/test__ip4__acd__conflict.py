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
This module contains tests for the RFC 5227 ACD conflict-detection
predicate and ARP frame parsing of the 'Ip4Acd' engine — the pure
logic that decides whether an inbound ARP frame conflicts with a
candidate address.

pytcp/tests/unit/protocols/ip4/acd/test__ip4__acd__conflict.py

ver 3.0.10
"""

from typing import override
from unittest import TestCase

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler, EtherType, Ip4Assembler
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd

_OUR_MAC = MacAddress("02:00:00:00:00:07")
_PEER_MAC = MacAddress("02:00:00:00:00:99")
_CANDIDATE = Ip4Address("10.0.1.50")
_OTHER_IP = Ip4Address("10.0.1.60")
_UNSPEC = Ip4Address()


def _arp_frame(*, oper: ArpOperation, sha: MacAddress, spa: Ip4Address, tpa: Ip4Address) -> bytes:
    """
    Build an Ethernet/ARP wire frame from semantic ARP fields.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=sha,
            ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
            ethernet__payload=ArpAssembler(
                arp__oper=oper,
                arp__sha=sha,
                arp__spa=spa,
                arp__tha=MacAddress(),
                arp__tpa=tpa,
            ),
        )
    )


class TestIp4AcdConflict(TestCase):
    """
    The 'Ip4Acd' conflict-detection predicate + ARP-parse tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build an ACD engine bound to our MAC on a stub ifindex.
        """

        self._acd = Ip4Acd(mac_address=_OUR_MAC, ifindex=1)

    def _is_conflict(self, *, oper: ArpOperation, sha: MacAddress, spa: Ip4Address, tpa: Ip4Address) -> bool:
        """
        Parse a built ARP frame and run it through the probe-time
        conflict predicate against the candidate address.
        """

        arp = self._acd._parse_arp(_arp_frame(oper=oper, sha=sha, spa=spa, tpa=tpa))
        assert arp is not None
        return self._acd._is_conflict(arp, _CANDIDATE)

    def _is_ongoing(self, *, oper: ArpOperation, sha: MacAddress, spa: Ip4Address, tpa: Ip4Address) -> bool:
        """
        Parse a built ARP frame and run it through the ongoing-defense
        conflict predicate against the claimed address.
        """

        arp = self._acd._parse_arp(_arp_frame(oper=oper, sha=sha, spa=spa, tpa=tpa))
        assert arp is not None
        return self._acd._is_ongoing_conflict(arp, _CANDIDATE)

    def test__ip4_acd__parse_arp_extracts_fields(self) -> None:
        """
        Ensure '_parse_arp' decodes an Ethernet/ARP frame into the ARP
        header with its sender-protocol-address and sender-hardware-
        address intact.

        Reference: RFC 826 (ARP packet format).
        """

        arp = self._acd._parse_arp(_arp_frame(oper=ArpOperation.REPLY, sha=_PEER_MAC, spa=_CANDIDATE, tpa=_CANDIDATE))

        assert arp is not None
        self.assertEqual(arp.spa, _CANDIDATE, msg="_parse_arp must decode the ARP sender protocol address.")
        self.assertEqual(arp.sha, _PEER_MAC, msg="_parse_arp must decode the ARP sender hardware address.")

    def test__ip4_acd__parse_arp_rejects_non_arp(self) -> None:
        """
        Ensure '_parse_arp' returns None for a non-ARP frame (e.g. an
        IPv4 frame) so the watcher skips it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = bytes(
            EthernetAssembler(
                ethernet__src=_PEER_MAC,
                ethernet__dst=MacAddress(0xFFFFFFFFFFFF),
                ethernet__payload=Ip4Assembler(
                    ip4__src=_OTHER_IP,
                    ip4__dst=_CANDIDATE,
                ),
            )
        )

        self.assertIsNone(
            self._acd._parse_arp(frame),
            msg="_parse_arp must return None for a non-ARP frame.",
        )
        self.assertIs(
            EtherType.from_proto(Ip4Assembler()),
            EtherType.IP4,
            msg="Sanity: the built frame carries the IPv4 ethertype, not ARP.",
        )

    def test__ip4_acd__conflict_peer_uses_address(self) -> None:
        """
        Ensure an ARP whose sender protocol address equals the candidate
        (a peer already using it) is a conflict.

        Reference: RFC 5227 §2.1.1 (a peer using the address conflicts).
        """

        self.assertTrue(
            self._is_conflict(oper=ArpOperation.REPLY, sha=_PEER_MAC, spa=_CANDIDATE, tpa=_CANDIDATE),
            msg="An ARP with sender-IP == candidate from a peer must conflict.",
        )

    def test__ip4_acd__conflict_simultaneous_probe(self) -> None:
        """
        Ensure a peer probing the same candidate (sender-IP 0.0.0.0,
        target-IP == candidate) is a conflict.

        Reference: RFC 5227 §2.1.1 (simultaneous-probe conflict).
        """

        self.assertTrue(
            self._is_conflict(oper=ArpOperation.REQUEST, sha=_PEER_MAC, spa=_UNSPEC, tpa=_CANDIDATE),
            msg="A peer probe (sender 0.0.0.0, target == candidate) must conflict.",
        )

    def test__ip4_acd__own_frame_is_not_conflict(self) -> None:
        """
        Ensure a frame sent from our own MAC is never a conflict, even
        when it carries the candidate address (our own Probe / Announce).

        Reference: RFC 5227 §2.1.1 (a host ignores its own ARP).
        """

        self.assertFalse(
            self._is_conflict(oper=ArpOperation.REQUEST, sha=_OUR_MAC, spa=_UNSPEC, tpa=_CANDIDATE),
            msg="A frame from our own MAC must not be a conflict.",
        )

    def test__ip4_acd__unrelated_address_is_not_conflict(self) -> None:
        """
        Ensure an ARP for an unrelated address (neither sender nor a
        probe target matching the candidate) is not a conflict.

        Reference: RFC 5227 §2.1.1 (only the candidate address matters).
        """

        self.assertFalse(
            self._is_conflict(oper=ArpOperation.REQUEST, sha=_PEER_MAC, spa=_OTHER_IP, tpa=_OTHER_IP),
            msg="An ARP for an unrelated address must not conflict.",
        )

    def test__ip4_acd__probe_for_other_address_is_not_conflict(self) -> None:
        """
        Ensure a peer probe (sender 0.0.0.0) targeting an address other
        than the candidate is not a conflict.

        Reference: RFC 5227 §2.1.1 (only the candidate target matters).
        """

        self.assertFalse(
            self._is_conflict(oper=ArpOperation.REQUEST, sha=_PEER_MAC, spa=_UNSPEC, tpa=_OTHER_IP),
            msg="A peer probe for a different address must not conflict.",
        )

    def test__ip4_acd__ongoing_conflict_peer_uses_address(self) -> None:
        """
        Ensure ongoing-defense conflict detection flags a peer actively
        using the claimed address (sender protocol address == ours).

        Reference: RFC 5227 §2.4 (ongoing defense — peer using address).
        """

        self.assertTrue(
            self._is_ongoing(oper=ArpOperation.REQUEST, sha=_PEER_MAC, spa=_CANDIDATE, tpa=_OTHER_IP),
            msg="A peer whose sender-IP == claimed address must be an ongoing conflict.",
        )

    def test__ip4_acd__ongoing_conflict_ignores_bare_probe(self) -> None:
        """
        Ensure ongoing-defense detection does NOT flag a bare Probe
        (sender 0.0.0.0) for the claimed address — the stack's ARP RX
        path answers such Probes for an owned address.

        Reference: RFC 5227 §2.4 (ongoing defense ignores bare Probes).
        """

        self.assertFalse(
            self._is_ongoing(oper=ArpOperation.REQUEST, sha=_PEER_MAC, spa=_UNSPEC, tpa=_CANDIDATE),
            msg="A bare Probe for the claimed address must not be an ongoing conflict.",
        )

    def test__ip4_acd__ongoing_conflict_ignores_own_frame(self) -> None:
        """
        Ensure ongoing-defense detection never flags a frame from our
        own MAC carrying the claimed address (our own Announcement /
        defensive ARP).

        Reference: RFC 5227 §2.4 (a host ignores its own ARP).
        """

        self.assertFalse(
            self._is_ongoing(oper=ArpOperation.REPLY, sha=_OUR_MAC, spa=_CANDIDATE, tpa=_CANDIDATE),
            msg="A frame from our own MAC must not be an ongoing conflict.",
        )
