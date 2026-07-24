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
Integration tests for the IPv4 ICMP Echo ('ping') datagram socket.

Pins the Linux 'SOCK_DGRAM' / 'IPPROTO_ICMP' behaviour at the stack level:
'sendto' rewrites the Echo Request id to the socket's owned id and emits
it on the wire; an inbound Echo Reply is demuxed back to the owning socket
by id and surfaced through 'recvmsg' as the ICMP message bytes (no IP
header) with the reply's TTL as an 'IP_TTL' cmsg.

pytcp/tests/integration/protocols/icmp4/test__icmp4__ping_socket.py

ver 3.0.9
"""

from typing import override
from unittest.mock import patch

from net_proto import (
    EthernetAssembler,
    Icmp4Assembler,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp4Type,
    Ip4Assembler,
    IpProto,
)
from pytcp.runtime.socket import IP_RECVTTL, IP_TTL, IPPROTO_IP, AddressFamily, SocketType
from pytcp.runtime.socket.ping__socket import PingSocket
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)

_SEQ: int = 0x0007
_REPLY_TTL: int = 57


def _echo_reply_frame(*, echo_id: int) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Echo Reply frame carrying 'echo_id'
    from HOST_A to the stack, with a known IP TTL.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=HOST_A__MAC_ADDRESS,
            ethernet__dst=STACK__MAC_ADDRESS,
            ethernet__payload=Ip4Assembler(
                ip4__src=HOST_A__IP4_ADDRESS,
                ip4__dst=STACK__IP4_HOST.address,
                ip4__ttl=_REPLY_TTL,
                ip4__payload=Icmp4Assembler(
                    icmp4__message=Icmp4MessageEchoReply(id=echo_id, seq=_SEQ, data=b"ping-data"),
                ),
            ),
        )
    )


class TestIcmp4PingSocket(IcmpTestCase):
    """
    The IPv4 ICMP Echo ('ping') datagram-socket tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the mocked ICMP runtime and silence the ping socket's
        'socket'-channel lifecycle logging.
        """

        super().setUp()
        self.enterContext(patch("pytcp.runtime.socket.ping__socket.log"))

    def _ping_socket(self) -> PingSocket:
        """
        Open an IPv4 ICMP Echo datagram socket and register its cleanup.
        """

        sock = PingSocket(AddressFamily.INET4, SocketType.DGRAM, IpProto.ICMP4)
        self.addCleanup(sock.close)
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__ping_socket__sendto_emits_echo_request_with_owned_id(self) -> None:
        """
        Ensure 'sendto' rewrites the application's Echo Request id to the
        socket's owned id and emits the request on the wire (the
        application's id field is ignored, as Linux ping sockets do).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._ping_socket()
        # The application's id (0x9999) must be overwritten by the socket.
        request = bytes(Icmp4MessageEchoRequest(id=0x9999, seq=_SEQ, data=b"ping-data"))

        sock.sendto(request, (str(HOST_A__IP4_ADDRESS), 0))
        tx_frames = list(self._frames_tx)

        self.assertEqual(len(tx_frames), 1, msg="sendto must emit exactly one Echo Request on the wire.")
        probe = self._parse_tx_icmp4(tx_frames[0])
        self._assert_icmp4_message(
            probe,
            type=int(Icmp4Type.ECHO_REQUEST),
            id=sock.echo_id,
            seq=_SEQ,
            ip_dst=HOST_A__IP4_ADDRESS,
        )

    def test__ping_socket__demux_delivers_reply_with_ttl_cmsg(self) -> None:
        """
        Ensure an inbound Echo Reply is demuxed to the owning ping socket
        by id and 'recvmsg' returns the ICMP message bytes (no IP header)
        plus the reply's TTL as an 'IP_TTL' cmsg when 'IP_RECVTTL' is set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._ping_socket()
        sock.setsockopt(IPPROTO_IP, IP_RECVTTL, 1)
        expected = bytes(Icmp4MessageEchoReply(id=sock.echo_id, seq=_SEQ, data=b"ping-data"))

        self._drive_rx(frame=_echo_reply_frame(echo_id=sock.echo_id))

        data, ancdata, _flags, address = sock.recvmsg(timeout=0.0)

        self.assertEqual(data, expected, msg="recvmsg must return the ICMP message bytes only (no IP header).")
        self.assertEqual(
            address,
            (str(HOST_A__IP4_ADDRESS), 0),
            msg="recvmsg must pair the reply with the sender's address.",
        )
        self.assertEqual(
            ancdata,
            [(int(IPPROTO_IP), int(IP_TTL), _REPLY_TTL.to_bytes(4, "little"))],
            msg="recvmsg must surface the reply's TTL as an IP_TTL cmsg when IP_RECVTTL is enabled.",
        )
