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
End-to-end integration tests for the RFC 6935 per-port
zero-checksum UDP-over-IPv6 alternative mode socket-API
surface ('UDP_NO_CHECK6_TX' / 'UDP_NO_CHECK6_RX' at level
'SOL_UDP'). Exercises:

  * setsockopt / getsockopt round-trip on both optnames.
  * TX: opt-in emits cksum=0x0000 literal on the wire
    (NOT the default-mode 0xFFFF "computed zero" sentinel
    that RFC 768 mandates).
  * TX: without opt-in, cksum is computed and non-zero
    on UDPv6 (default-mode RFC 8200 §8.1 requirement).
  * RX: with opt-in, an inbound UDPv6 frame with cksum=0
    reaches the socket's recv() path instead of the
    default-mode silent discard.
  * RX: without opt-in, the inbound cksum=0 UDPv6 frame
    is dropped and the 'udp__ip6_zero_cksum__drop'
    counter bumps (the existing default-mode behaviour).

pytcp/tests/integration/protocols/udp/test__udp__no_check6.py

ver 3.0.8
"""

from net_addr import MacAddress
from net_proto import (
    EthernetAssembler,
    Ip6Assembler,
    UdpAssembler,
)
from pytcp.socket import (
    SOL_UDP,
    UDP_NO_CHECK6_RX,
    UDP_NO_CHECK6_TX,
    AddressFamily,
)
from pytcp.tests.lib.udp_testcase import (
    HOST_A__IP6_ADDRESS,
    STACK__IP6_HOST,
    UdpTestCase,
)

_STACK_MAC = MacAddress("02:00:00:00:00:07")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555


def _udpv6_zero_cksum_frame(*, payload: bytes = b"probe") -> bytes:
    """
    Build an Ethernet/IPv6/UDP datagram from HOST_A → STACK on
    the canonical fixture 4-tuple with the UDP checksum field
    forced to 0x0000 on the wire. The UDP assembler's standard
    RFC 768 substitution (computed-cksum=0 → 0xFFFF) would
    otherwise prevent the wire value from being zero, so this
    helper builds the assembler then overwrites the checksum
    slice in the assembled bytes directly.
    """

    udp = UdpAssembler(
        udp__sport=_REMOTE_PORT,
        udp__dport=_LOCAL_PORT,
        udp__payload=payload,
    )
    frame = bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip6Assembler(
                ip6__src=HOST_A__IP6_ADDRESS,
                ip6__dst=STACK__IP6_HOST.address,
                ip6__payload=udp,
            ),
        )
    )
    # Locate the UDP checksum byte offset: Ethernet (14) + IPv6
    # header (40) + UDP cksum offset (6) = 60.
    frame_b = bytearray(frame)
    frame_b[60:62] = b"\x00\x00"
    return bytes(frame_b)


class TestUdpNoCheck6Roundtrip(UdpTestCase):
    """
    The UDP_NO_CHECK6 setsockopt / getsockopt round-trip
    tests on UdpSocket.
    """

    def test__udp_no_check6__tx__round_trip(self) -> None:
        """
        Ensure setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1) flips
        the per-socket flag and getsockopt reads it back, with
        the default value of 0 on a fresh socket. The setsockopt
        level uses 'SOL_UDP' = 17 (Linux numbering), matching the
        stdlib socket module's level for UDP-level options.

        Reference: Linux udp(7) (UDP_NO_CHECK6_TX socket option).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET6)

        self.assertEqual(
            sock.getsockopt(SOL_UDP, UDP_NO_CHECK6_TX),
            0,
            msg="Default UDP_NO_CHECK6_TX must be 0 on a fresh socket.",
        )

        sock.setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1)

        self.assertEqual(
            sock.getsockopt(SOL_UDP, UDP_NO_CHECK6_TX),
            1,
            msg="After setsockopt(UDP_NO_CHECK6_TX=1) getsockopt must return 1.",
        )

        sock.setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 0)

        self.assertEqual(
            sock.getsockopt(SOL_UDP, UDP_NO_CHECK6_TX),
            0,
            msg="After setsockopt(UDP_NO_CHECK6_TX=0) getsockopt must return 0.",
        )

    def test__udp_no_check6__rx__round_trip(self) -> None:
        """
        Ensure setsockopt(SOL_UDP, UDP_NO_CHECK6_RX, 1) flips
        the per-socket flag and getsockopt reads it back, with
        default 0 on a fresh socket. RX flag is independent of
        TX flag — exercising one MUST NOT alter the other.

        Reference: Linux udp(7) (UDP_NO_CHECK6_RX socket option).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET6)

        self.assertEqual(
            sock.getsockopt(SOL_UDP, UDP_NO_CHECK6_RX),
            0,
            msg="Default UDP_NO_CHECK6_RX must be 0 on a fresh socket.",
        )

        sock.setsockopt(SOL_UDP, UDP_NO_CHECK6_RX, 1)

        self.assertEqual(
            sock.getsockopt(SOL_UDP, UDP_NO_CHECK6_RX),
            1,
            msg="After setsockopt(UDP_NO_CHECK6_RX=1) getsockopt must return 1.",
        )

        # TX flag must still be 0 (independent).
        self.assertEqual(
            sock.getsockopt(SOL_UDP, UDP_NO_CHECK6_TX),
            0,
            msg="UDP_NO_CHECK6_RX must NOT affect UDP_NO_CHECK6_TX.",
        )


class TestUdpNoCheck6Tx(UdpTestCase):
    """
    The UDP_NO_CHECK6_TX cksum-skip-on-send tests.
    """

    def test__udp_no_check6_tx__opted_in__cksum_zero_on_wire(self) -> None:
        """
        Ensure an outbound UDPv6 datagram from a socket with
        UDP_NO_CHECK6_TX=1 carries the literal value 0x0000 in
        the UDP checksum slot — NOT the default-mode 0xFFFF
        sentinel. Default-mode senders substitute a computed
        zero with all-ones so the wire value 0x0000 remains
        unambiguously "no checksum"; alternative-mode senders
        emit the literal zero directly.

        Reference: RFC 768 (default-mode 0 → 0xFFFF substitution).
        Reference: RFC 6935 §5 (alternative-mode zero-cksum opt-in).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET6)
        sock.setsockopt(SOL_UDP, UDP_NO_CHECK6_TX, 1)

        sock.sendto(b"probe", (str(HOST_A__IP6_ADDRESS), _REMOTE_PORT))

        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="Exactly one outbound frame must be produced by sendto().",
        )
        outbound = self._frames_tx[-1]
        # Ethernet (14) + IPv6 (40) + UDP cksum offset (6).
        cksum = int.from_bytes(outbound[60:62])

        self.assertEqual(
            cksum,
            0,
            msg="UDP_NO_CHECK6_TX=1 must emit cksum=0x0000 on the wire.",
        )

    def test__udp_no_check6_tx__default__cksum_computed(self) -> None:
        """
        Ensure an outbound UDPv6 datagram from a socket WITHOUT
        UDP_NO_CHECK6_TX set carries a computed non-zero
        checksum, matching the default-mode requirement that
        UDPv6 packets MUST carry a valid checksum.

        Reference: RFC 8200 §8.1 (UDPv6 checksum mandatory).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET6)

        sock.sendto(b"probe", (str(HOST_A__IP6_ADDRESS), _REMOTE_PORT))

        outbound = self._frames_tx[-1]
        cksum = int.from_bytes(outbound[60:62])

        self.assertNotEqual(
            cksum,
            0,
            msg="Default-mode UDPv6 send must emit a computed non-zero cksum.",
        )


class TestUdpNoCheck6Rx(UdpTestCase):
    """
    The UDP_NO_CHECK6_RX cksum-skip-on-receive tests.
    """

    def test__udp_no_check6_rx__opted_in__delivers_to_socket(self) -> None:
        """
        Ensure an inbound UDPv6 datagram with checksum=0 is
        delivered to the matching socket when UDP_NO_CHECK6_RX=1,
        instead of being silently dropped by the default-mode
        receiver gate.

        Reference: RFC 8200 §8.1 (default-mode IPv6 zero-cksum drop).
        Reference: RFC 6935 §5 (alternative-mode receivers MAY
        accept zero-cksum on opted-in ports).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET6)
        sock.setsockopt(SOL_UDP, UDP_NO_CHECK6_RX, 1)

        self._drive_udp_rx(frame=_udpv6_zero_cksum_frame(payload=b"hello"))

        data, addr = self._recvfrom(sock, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="UDP_NO_CHECK6_RX=1 must deliver the cksum=0 payload to recvfrom.",
        )
        self.assertEqual(
            addr,
            (str(HOST_A__IP6_ADDRESS), _REMOTE_PORT),
            msg="recvfrom address tuple must reflect the sender's IPv6 / port.",
        )

    def test__udp_no_check6_rx__default__drops_with_counter(self) -> None:
        """
        Ensure an inbound UDPv6 datagram with checksum=0 is
        silently dropped when no matching socket has
        UDP_NO_CHECK6_RX set, and the
        'udp__ip6_zero_cksum__drop' counter bumps exactly once.

        Reference: RFC 8200 §8.1 (UDPv6 checksum mandatory).
        """

        sock = self._bind_udp_socket(family=AddressFamily.INET6)
        # UDP_NO_CHECK6_RX intentionally not set.

        before = self._packet_handler.packet_stats_rx.udp__ip6_zero_cksum__drop

        self._drive_udp_rx(frame=_udpv6_zero_cksum_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.udp__ip6_zero_cksum__drop,
            before + 1,
            msg="Default-mode UDPv6 cksum=0 drop must bump the dedicated counter.",
        )

        # The socket's RX queue must be empty.
        self.assertEqual(
            len(sock._packet_rx_md),
            0,
            msg="Default-mode cksum=0 IPv6 must NOT deliver to the socket.",
        )
