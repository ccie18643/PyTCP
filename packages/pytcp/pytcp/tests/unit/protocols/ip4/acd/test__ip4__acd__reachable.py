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
This module contains tests for the 'Ip4Acd' RFC 4436 DNAv4 reachability
probe ('probe_reachable' + the '_is_gateway_reply' predicate).

pytcp/tests/unit/protocols/ip4/acd/test__ip4__acd__reachable.py

ver 3.0.8
"""

from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, MacAddress
from net_proto import ArpAssembler, ArpOperation, EthernetAssembler
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd

_OUR_MAC = MacAddress("02:00:00:00:00:07")
_GW_IP = Ip4Address("192.168.1.1")
_GW_MAC = MacAddress("aa:bb:cc:dd:ee:ff")
_OTHER_MAC = MacAddress("02:00:00:00:00:99")
_OTHER_IP = Ip4Address("192.168.1.2")
_CANDIDATE = Ip4Address("192.168.1.145")


def _arp_reply(*, sha: MacAddress, spa: Ip4Address) -> bytes:
    """
    Build an Ethernet/ARP Reply frame from 'sha' / 'spa' targeting our
    candidate address — the shape of the cached gateway's DNAv4 answer.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=sha,
            ethernet__dst=_OUR_MAC,
            ethernet__payload=ArpAssembler(
                arp__oper=ArpOperation.REPLY,
                arp__sha=sha,
                arp__spa=spa,
                arp__tha=_OUR_MAC,
                arp__tpa=_CANDIDATE,
            ),
        )
    )


class TestIp4AcdGatewayReplyPredicate(TestCase):
    """
    The 'Ip4Acd._is_gateway_reply' DNAv4 reply-match predicate tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build an ACD engine bound to our MAC on a stub ifindex.
        """

        self._acd = Ip4Acd(mac_address=_OUR_MAC, ifindex=1)

    def _is_gateway_reply(self, *, sha: MacAddress, spa: Ip4Address) -> bool:
        """
        Parse a built ARP Reply frame and run it through the
        gateway-reply predicate against the cached gateway.
        """

        arp = self._acd._parse_arp(_arp_reply(sha=sha, spa=spa))
        assert arp is not None
        return self._acd._is_gateway_reply(arp, _GW_IP, _GW_MAC)

    def test__ip4_acd__gateway_reply_matches_same_ip_and_mac(self) -> None:
        """
        Ensure a Reply whose sender is the cached gateway on both IPv4 and
        MAC is recognised as the gateway's answer.

        Reference: RFC 4436 §4 (cached gateway reply confirms attachment).
        """

        self.assertTrue(
            self._is_gateway_reply(sha=_GW_MAC, spa=_GW_IP),
            msg="A Reply from the cached gateway IP + MAC must match.",
        )

    def test__ip4_acd__gateway_reply_rejects_wrong_ip(self) -> None:
        """
        Ensure a Reply from the gateway MAC but a different IPv4 is not
        treated as the gateway's answer.

        Reference: RFC 4436 §4.3 (the answer must be from the cached gateway).
        """

        self.assertFalse(
            self._is_gateway_reply(sha=_GW_MAC, spa=_OTHER_IP),
            msg="A Reply from a different IPv4 must not match.",
        )

    def test__ip4_acd__gateway_reply_rejects_wrong_mac(self) -> None:
        """
        Ensure a Reply for the gateway IPv4 but from a different MAC is
        not treated as the gateway's answer (a different physical device).

        Reference: RFC 4436 §4 (same physical gateway confirms the segment).
        """

        self.assertFalse(
            self._is_gateway_reply(sha=_OTHER_MAC, spa=_GW_IP),
            msg="A Reply from a different MAC must not match.",
        )


class TestIp4AcdProbeReachable(TestCase):
    """
    The 'Ip4Acd.probe_reachable' DNAv4 socket-driven probe tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build an ACD engine and replace its AF_PACKET socket factory with
        a mock so the probe runs without a real link socket.
        """

        self.enterContext(patch("pytcp.protocols.ip4.acd.ip4_acd.log"))
        self._sock = MagicMock(name="raw_link_socket")
        socket_factory = self.enterContext(patch("pytcp.protocols.ip4.acd.ip4_acd.socket"))
        socket_factory.return_value = self._sock
        self._acd = Ip4Acd(mac_address=_OUR_MAC, ifindex=1)

    def _run(self, *, timeout: float = 1.0) -> bool:
        """
        Run a DNAv4 reachability probe to the cached gateway.
        """

        return self._acd.probe_reachable(target=_GW_IP, target_mac=_GW_MAC, sender=_CANDIDATE, timeout=timeout)

    def test__ip4_acd__probe_reachable_true_when_gateway_answers(self) -> None:
        """
        Ensure 'probe_reachable' returns True when the cached gateway's
        Reply is read off the socket, and that the probe unicasts to the
        gateway MAC with the candidate as the sender protocol address.

        Reference: RFC 4436 §4 (cached gateway reply confirms attachment).
        Reference: RFC 4436 §4.3 (unicast ARP Request, ar$spa = candidate).
        """

        self._sock.recvfrom.return_value = (_arp_reply(sha=_GW_MAC, spa=_GW_IP), ("", 0))

        self.assertTrue(self._run(), msg="probe_reachable must return True when the gateway answers.")

        self._sock.sendto.assert_called_once()
        sent_frame = self._sock.sendto.call_args.args[0]
        self.assertEqual(sent_frame[0:6], bytes(_GW_MAC), msg="The probe must unicast to the gateway MAC.")
        arp = self._acd._parse_arp(sent_frame)
        assert arp is not None
        self.assertEqual(arp.spa, _CANDIDATE, msg="The probe ar$spa must be the candidate address.")
        self.assertEqual(arp.tpa, _GW_IP, msg="The probe must target the gateway IPv4.")

    def test__ip4_acd__probe_reachable_false_on_silent_gateway(self) -> None:
        """
        Ensure 'probe_reachable' returns False when no Reply arrives
        before the timeout elapses.

        Reference: RFC 4436 §4 (timeout → standard DHCP fallback).
        """

        self._sock.recvfrom.side_effect = BlockingIOError

        self.assertFalse(self._run(timeout=0.0), msg="A silent gateway must yield False.")

    def test__ip4_acd__probe_reachable_ignores_non_gateway_frame(self) -> None:
        """
        Ensure 'probe_reachable' skips an unrelated ARP frame and still
        returns True on the gateway's subsequent Reply.

        Reference: RFC 4436 §4 (only the cached gateway's reply counts).
        """

        self._sock.recvfrom.side_effect = [
            (_arp_reply(sha=_OTHER_MAC, spa=_OTHER_IP), ("", 0)),
            (_arp_reply(sha=_GW_MAC, spa=_GW_IP), ("", 0)),
        ]

        self.assertTrue(self._run(), msg="An unrelated ARP must be ignored; the gateway Reply must win.")
