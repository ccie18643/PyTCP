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
Integration tests for IP_OPTIONS honored on the RAW (SOCK_RAW)
TX path: a raw IPv4 socket that sets 'setsockopt(IPPROTO_IP,
IP_OPTIONS, bytes)' emits the options block on its outbound
datagrams, exactly as the UDP path does (RFC 1122 §4.1.3.2 — the
application must be able to specify IP options to be sent).

pytcp/tests/integration/socket/test__socket__raw_ip_options.py

ver 3.0.8
"""

from net_addr import IpVersion
from net_proto import Ip4Parser, IpProto
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.runtime.socket import (
    IP_OPTIONS,
    IPPROTO_IP,
    AddressFamily,
    SocketType,
)
from pytcp.runtime.socket.raw__socket import RawSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    NetworkTestCase,
)

# A Router Alert IPv4 option (RFC 2113): type 0x94, length 4, value 0.
_ROUTER_ALERT_BYTES = b"\x94\x04\x00\x00"

# Silence the SOCKET log channel: RAW sockets log 'Closed socket'
# from addCleanup(close) after the harness restores LOG__CHANNEL.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence stack log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the production log-channel configuration.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class TestSocketRawIpOptions(NetworkTestCase):
    """
    IP_OPTIONS set on a RAW IPv4 socket must be emitted on its
    outbound datagrams, mirroring the UDP TX path.
    """

    def _raw_socket(self) -> RawSocket:
        """
        Open an IPv4 RAW socket on an experimental IANA protocol
        number (253, RFC 3692) and register its cleanup.
        """

        sock = RawSocket(family=AddressFamily.INET4, type=SocketType.RAW, protocol=IpProto.from_int(253))
        self.addCleanup(sock.close)
        return sock  # pyright: ignore[reportReturnType]  # factory __new__ divergence; mypy-clean

    def test__raw__ip_options__sendto_emits_options_block_on_wire(self) -> None:
        """
        Ensure a RAW socket with 'setsockopt(IP_OPTIONS, bytes)'
        emits the options block on its outbound datagram — 'hlen'
        is bumped to cover the options and the parsed block
        round-trips to the configured bytes.

        Reference: RFC 1122 §4.1.3.2 (application MUST be able to
        specify IP options to be sent).
        """

        sock = self._raw_socket()
        sock.setsockopt(IPPROTO_IP, IP_OPTIONS, _ROUTER_ALERT_BYTES)

        sock.sendto(b"payload", (str(HOST_A__IP4_ADDRESS), 0))

        self.assertEqual(len(self._frames_tx), 1, msg="One outbound RAW datagram must be emitted.")
        ip4_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        self.assertEqual(ip4_parser.ver, IpVersion.IP4, msg="Outbound frame must be IPv4.")
        self.assertEqual(
            ip4_parser.hlen,
            24,
            msg="hlen must be 24 (20-byte header + 4-byte Router Alert option).",
        )
        self.assertEqual(
            bytes(ip4_parser.options),
            _ROUTER_ALERT_BYTES,
            msg="Outbound RAW IPv4 options block must equal the configured IP_OPTIONS bytes.",
        )

    def test__raw__ip_options__sendto_no_options_emits_plain_header(self) -> None:
        """
        Ensure a RAW socket without 'setsockopt(IP_OPTIONS, ...)'
        emits a plain 20-byte IPv4 header — regression pin so the
        options carve-out does not disturb the default path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._raw_socket()

        sock.sendto(b"payload", (str(HOST_A__IP4_ADDRESS), 0))

        ip4_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        self.assertEqual(
            ip4_parser.hlen,
            20,
            msg="hlen must be 20 (no options) when IP_OPTIONS is unset.",
        )
        self.assertEqual(
            bytes(ip4_parser.options),
            b"",
            msg="A RAW datagram without IP_OPTIONS must carry no options block.",
        )
