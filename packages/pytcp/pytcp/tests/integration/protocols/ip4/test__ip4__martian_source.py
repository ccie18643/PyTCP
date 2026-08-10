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
Integration tests for the IPv4 martian-source directed-broadcast
filter. The IPv4 parser sanity check already drops sources that
are the limited broadcast (255.255.255.255), any multicast
address, or any reserved (240.0.0.0/4) address. The remaining
martian class is directed broadcast — the broadcast address of a
locally configured subnet (e.g. 10.0.1.255 for a host on
10.0.1.0/24). Recognising it requires per-interface subnet state,
so the check lives in the IPv4 RX packet handler where the
configured '_ip4_ifaddr' list is in scope.

pytcp/tests/integration/protocols/ip4/test__ip4__martian_source.py

ver 3.0.10
"""

from net_addr import Ip4Address, MacAddress
from net_proto import (
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4MessageEchoRequest,
    Ip4Assembler,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp.tests.lib.ip4_testcase import Ip4TestCase

_STACK_MAC = MacAddress("02:00:00:00:00:07")
_STACK_IP4 = Ip4Address("10.0.1.7")
_OUR_SUBNET_DIRECTED_BROADCAST = Ip4Address("10.0.1.255")
_REMOTE_SUBNET_DIRECTED_BROADCAST = Ip4Address("192.168.1.255")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_HOST_A_IP4 = Ip4Address("10.0.1.91")


def _build_echo_request(*, ip4__src: Ip4Address, ethernet__src: MacAddress) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Echo Request frame targeting
    the stack address from the supplied source address.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=ethernet__src,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=ip4__src,
                ip4__dst=_STACK_IP4,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoRequest(
                        id=0x1234,
                        seq=0x0001,
                        data=b"hello",
                    ),
                ),
            ),
        )
    )


class TestIp4MartianSourceDirectedBroadcast(Ip4TestCase):
    """
    The IPv4 martian-source directed-broadcast filter tests.
    """

    def test__ip4__src_directed_broadcast_local_subnet__dropped(self) -> None:
        """
        Ensure an inbound IPv4 datagram whose source address
        equals the directed-broadcast address of a locally
        configured subnet is silently dropped. The drop bumps
        'ip4__src_directed_broadcast__drop' and emits zero TX
        frames — the ICMPv4 Echo Reply path never runs.

        Reference: RFC 1122 §3.2.1.3 (a source address MUST NOT
        be a broadcast address).
        """

        frame = _build_echo_request(
            ip4__src=_OUR_SUBNET_DIRECTED_BROADCAST,
            ethernet__src=_HOST_A_MAC,
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            self._frames_tx,
            [],
            msg=(
                "Directed-broadcast source must produce zero TX " "frames — the ICMPv4 Echo Reply path must never run."
            ),
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__src_directed_broadcast__drop,
            1,
            msg=("Directed-broadcast source must bump " "'ip4__src_directed_broadcast__drop' exactly once."),
        )

    def test__ip4__src_directed_broadcast_remote_subnet__accepted(self) -> None:
        """
        Ensure an inbound IPv4 datagram whose source address
        equals the directed-broadcast address of a subnet the
        stack does NOT host is accepted as a normal unicast
        source. The host has no way to know it is a broadcast
        elsewhere; the filter only catches OUR own directed
        broadcasts.

        Reference: RFC 1122 §3.2.1.3 (filter scope limited to
        locally configured broadcast addresses).
        """

        frame = _build_echo_request(
            ip4__src=_REMOTE_SUBNET_DIRECTED_BROADCAST,
            ethernet__src=_HOST_A_MAC,
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__src_directed_broadcast__drop,
            0,
            msg=("Remote-subnet directed broadcast must NOT bump " "the local-directed-broadcast drop counter."),
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Remote-subnet directed broadcast must be accepted; Echo Reply emitted.",
        )

    def test__ip4__src_unicast__not_affected(self) -> None:
        """
        Ensure an inbound IPv4 datagram with a normal unicast
        source is unaffected by the directed-broadcast filter —
        the gate is specifically about broadcast sources, not
        all inbound traffic.

        Reference: RFC 1122 §3.2.1.3 (filter scope limited to
        broadcast source addresses).
        """

        frame = _build_echo_request(
            ip4__src=_HOST_A_IP4,
            ethernet__src=_HOST_A_MAC,
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame))

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip4__src_directed_broadcast__drop,
            0,
            msg="Unicast source must NOT bump the drop counter.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Unicast Echo Request must be processed; Echo Reply emitted.",
        )
