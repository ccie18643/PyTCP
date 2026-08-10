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
This module contains integration tests for the AF_PACKET TX path —
'PacketSocket.send' / 'sendto' enqueuing a verbatim pre-built Ethernet
frame onto the egress interface's TxRing.

pytcp/tests/integration/packet_handler/test__packet_socket__tx.py

ver 3.0.10
"""

import errno
from typing import Any, cast, override
from unittest.mock import patch

from pytcp.runtime.socket import SOCK_RAW, AddressFamily, socket
from pytcp.runtime.socket.packet__socket import PacketSocket
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl
from pytcp.tests.lib.network_testcase import NetworkTestCase

# A complete, pre-built Ethernet frame (the AF_PACKET socket supplies
# the whole link-layer header): broadcast dst, stack src, ARP ethertype,
# arbitrary trailing payload.
_FRAME = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06verbatim-frame"


class TestPacketSocketTx(NetworkTestCase):
    """
    The AF_PACKET egress (send / sendto) integration tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the mock network, suppress packet-socket log output, and
        expose the boot interface's mocked TxRing for assertions.
        """

        super().setUp()
        self.enterContext(patch("pytcp.runtime.socket.packet__socket.log"))
        self._tx_ring = cast(Any, self._packet_handler._tx_ring)

    def _packet_socket(self) -> PacketSocket:
        """
        Open an AF_PACKET socket and register cleanup.
        """

        sock = socket(family=AddressFamily.PACKET, type=SOCK_RAW)
        assert isinstance(sock, PacketSocket)
        self.addCleanup(sock.close)
        return sock

    def test__packet_socket__sendto_enqueues_verbatim_frame(self) -> None:
        """
        Ensure 'sendto' enqueues the frame bytes verbatim onto the
        TxRing of the interface named by the address ifindex, and
        reports the full byte count as sent.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()
        ifindex = self._packet_handler._ifindex

        sent = sock.sendto(_FRAME, SockAddrLl(ifindex=ifindex))

        self.assertEqual(sent, len(_FRAME), msg="sendto must return the number of bytes accepted.")
        self._tx_ring.enqueue_raw_frame.assert_called_once_with(_FRAME)

    def test__packet_socket__send_uses_sole_interface_when_unbound(self) -> None:
        """
        Ensure 'send' on an unbound socket egresses the sole registered
        interface (the N=1 fallback), enqueuing the frame verbatim.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()

        sent = sock.send(_FRAME)

        self.assertEqual(sent, len(_FRAME), msg="send must return the number of bytes accepted.")
        self._tx_ring.enqueue_raw_frame.assert_called_once_with(_FRAME)

    def test__packet_socket__sendto_unknown_ifindex_raises_enodev(self) -> None:
        """
        Ensure 'sendto' to an ifindex with no registered interface
        raises 'OSError(ENODEV)' and enqueues nothing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._packet_socket()

        with self.assertRaises(OSError) as context:
            sock.sendto(_FRAME, SockAddrLl(ifindex=99))

        self.assertEqual(
            context.exception.errno,
            errno.ENODEV,
            msg="sendto to an unregistered ifindex must raise OSError(ENODEV).",
        )
        self._tx_ring.enqueue_raw_frame.assert_not_called()
