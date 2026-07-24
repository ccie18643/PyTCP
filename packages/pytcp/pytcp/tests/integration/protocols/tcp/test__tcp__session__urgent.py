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
This module contains integration tests for the RFC 6093 §5/§6
urgent-mechanism passthrough behaviour: PyTCP does not expose a
TX-side urgent API to applications (consistent with §5's "new
applications SHOULD NOT employ the TCP urgent mechanism") but does
satisfy the §5 implementation MUST by correctly accepting peer
URG-bearing segments and delivering their data inline to the recv
buffer — which is the behaviour §6 SO_OOBINLINE prescribes for
applications that DO interact with peers using urgent.

pytcp/tests/integration/protocols/tcp/test__tcp__session__urgent.py

ver 3.0.8
"""

from net_addr import Ip4Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpSessionRfc6093Urgent(TcpTestCase):
    """
    RFC 6093 §5 implementation-side MUST: "TCP implementations
    MUST still include support for the urgent mechanism such
    that existing applications can still use it." PyTCP's
    interpretation: support the wire-level URG flag and
    Urgent Pointer at parser/assembler, and deliver inbound
    URG-bearing data inline to the recv buffer (the §6
    SO_OOBINLINE-recommended posture). The TX-side urgent API
    is intentionally absent because §5's "new applications
    SHOULD NOT employ" makes a TX path inappropriate for new
    code in an educational stack.
    """

    def test__rfc6093__urg_segment_data_delivered_inline(self) -> None:
        """
        Ensure that an inbound segment carrying the URG flag
        and a data payload has its bytes delivered inline to
        the recv buffer, satisfying the §6 SO_OOBINLINE
        behaviour PyTCP applies by default. This is the §5
        implementation-MUST: a peer using the urgent mechanism
        can still send urgent-marked data and the receiving
        application reads it inline (the §1.4 / §6 IETF-
        intended path).

        Reference: RFC 6093 §5 (implementations MUST support urgent mechanism).
        Reference: RFC 6093 §6 (SO_OOBINLINE inline-delivery posture).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        urg_payload = b"urgent-bytes"
        urg_segment = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("URG", "ACK"),
            win=PEER__WIN,
            payload=urg_payload,
        )
        self._drive_rx(frame=urg_segment)

        self.assertEqual(
            bytes(session._rx_buffer),
            urg_payload,
            msg=(
                "RFC 6093 §6: an inbound URG-bearing segment's "
                "data MUST be delivered inline to the recv buffer "
                "(PyTCP's SO_OOBINLINE-by-default posture). Got "
                f"_rx_buffer={bytes(session._rx_buffer)!r}."
            ),
        )

    def test__rfc6093__urg_segment_does_not_terminate_connection(self) -> None:
        """
        Ensure that an inbound URG-bearing segment leaves the
        connection in ESTABLISHED — PyTCP does not abort or
        misbehave on URG flag receipt. The §5 MUST is
        compromised if the stack rejects URG-marked traffic.

        Reference: RFC 6093 §5 (implementations MUST support urgent mechanism).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        urg_segment = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("URG", "ACK"),
            win=PEER__WIN,
            payload=b"u",
        )
        self._drive_rx(frame=urg_segment)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "RFC 6093 §5: an inbound URG-bearing segment MUST "
                "NOT terminate or destabilise the connection. Got "
                f"state={session.state!r}."
            ),
        )
