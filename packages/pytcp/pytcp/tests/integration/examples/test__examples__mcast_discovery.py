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
Tests for the multicast service-discovery examples. The tiny announcement
wire format is exercised as pure logic; the discoverer's join + receive path
is exercised end-to-end over the daemon — a drop-in socket joins a group
(IP_ADD_MEMBERSHIP) and a multicast datagram driven on the wire is delivered
to it — mirroring the IGMP group-delivery tests.

pytcp/tests/integration/examples/test__examples__mcast_discovery.py

ver 3.0.9
"""

import os
import socket
import tempfile
import time
from typing import cast, override
from unittest import TestCase

import pytcp.socket as pytcp_socket
from examples.mcast_announce import announce_once
from examples.mcast_discover import join_group
from examples.mcast_proto import Announcement, format_announcement, parse_announcement
from net_addr import Ip4Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.udp.udp__assembler import UdpAssembler
from pytcp import stack
from pytcp.ipc.ipc__server import IpcServer
from pytcp.socket.socket__dropin import _reset_default_stack
from pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, HOST_A__MAC_ADDRESS
from pytcp.tests.lib.udp_testcase import UdpTestCase

_GROUP: str = "239.1.2.3"
_GROUP_MAC: MacAddress = MacAddress("01:00:5e:01:02:03")
_PORT: int = 1900
_REMOTE_PORT: int = 5555
_DEADLINE__SEC: float = 5.0

_ANNOUNCEMENT: Announcement = Announcement(service="echo", host="10.0.1.7", port=7)


class TestMcastAnnouncementWireFormat(TestCase):
    """
    The announcement encode / decode round-trip and rejection tests.
    """

    def test__mcast__announcement_round_trips(self) -> None:
        """
        Ensure an announcement rendered to its wire form parses back into an
        equal 'Announcement'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            parse_announcement(format_announcement(_ANNOUNCEMENT)),
            _ANNOUNCEMENT,
            msg="format_announcement then parse_announcement must round-trip.",
        )

    def test__mcast__malformed_announcements_are_rejected(self) -> None:
        """
        Ensure a datagram that is not a well-formed 'PyTCP-DISCOVER v1'
        announcement (wrong magic / version, missing field, non-integer
        port, or non-UTF-8) parses to None rather than a bogus service.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for label, blob in (
            ("garbage", b"just some bytes"),
            ("wrong-magic", b"OTHER v1 service=x host=y port=1"),
            ("wrong-version", b"PyTCP-DISCOVER v2 service=x host=y port=1"),
            ("missing-field", b"PyTCP-DISCOVER v1 service=x host=y"),
            ("bad-port", b"PyTCP-DISCOVER v1 service=x host=y port=nope"),
            ("non-utf8", b"PyTCP-DISCOVER v1 service=\xff host=y port=1"),
        ):
            with self.subTest(case=label):
                self.assertIsNone(
                    parse_announcement(blob),
                    msg=f"A {label} datagram must not parse to an announcement.",
                )


class TestMcastDiscoveryOverDaemon(UdpTestCase):
    """
    The discoverer's join + receive path exercised over the daemon.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging.
        """

        super().setUpClass()
        cls._log_channel_prior = stack.LOG__CHANNEL
        stack.LOG__CHANNEL = set()

    @classmethod
    @override
    def tearDownClass(cls) -> None:
        """
        Restore the original logger channel set.
        """

        stack.LOG__CHANNEL = cls._log_channel_prior
        super().tearDownClass()

    @override
    def setUp(self) -> None:
        """
        Build the mocked UDP runtime, stand up an 'IpcServer', and point the
        drop-in's daemon singleton at it via '$PYTCP_DAEMON_SOCKET'.
        """

        super().setUp()

        self._tmp_dir = tempfile.mkdtemp(prefix="pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self._socket_path = os.path.join(self._tmp_dir, "pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        self._server.start()
        self.addCleanup(self._server.stop)

        self._env_prior = os.environ.get("PYTCP_DAEMON_SOCKET")
        os.environ["PYTCP_DAEMON_SOCKET"] = self._socket_path
        _reset_default_stack()
        self.addCleanup(self._restore_env)
        self.addCleanup(_reset_default_stack)

    def _restore_env(self) -> None:
        """
        Restore the PYTCP_DAEMON_SOCKET environment variable.
        """

        if self._env_prior is None:
            os.environ.pop("PYTCP_DAEMON_SOCKET", None)
        else:
            os.environ["PYTCP_DAEMON_SOCKET"] = self._env_prior

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    def _mcast_announcement_frame(self, announcement: Announcement, /) -> bytes:
        """
        Build an Ethernet/IPv4/UDP frame carrying 'announcement' from the
        peer to the discovery group.
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=_GROUP_MAC,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=Ip4Address(_GROUP),
                    ip4__payload=UdpAssembler(
                        udp__sport=_REMOTE_PORT,
                        udp__dport=_PORT,
                        udp__payload=format_announcement(announcement),
                    ),
                ),
            )
        )

    def test__mcast__joined_socket_receives_group_announcement(self) -> None:
        """
        Ensure a drop-in socket that joined the discovery group receives an
        announcement multicast to that group and parses it back into the
        advertised service.

        Reference: RFC 1112 (Host Extensions for IP Multicasting — group
        membership + delivery).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)
        sock.settimeout(_DEADLINE__SEC)
        sock.bind(("0.0.0.0", _PORT))
        join_group(cast(socket.socket, sock), group=_GROUP)

        self._drive_udp_rx(frame=self._mcast_announcement_frame(_ANNOUNCEMENT))

        data, address = sock.recvfrom(65535)

        self.assertEqual(
            (parse_announcement(data), address),
            (_ANNOUNCEMENT, (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)),
            msg="A joined socket must receive + parse the group announcement with its sender address.",
        )

    def test__mcast__announcer_reaches_the_wire(self) -> None:
        """
        Ensure an announcement the announcer multicasts is carried onto the
        wire as a UDP datagram addressed to the discovery group.

        Reference: RFC 1112 (Host Extensions for IP Multicasting —
        multicast transmission).
        """

        sock = pytcp_socket.socket(pytcp_socket.AF_INET, pytcp_socket.SOCK_DGRAM)
        self.addCleanup(sock.close)

        announce_once(cast(socket.socket, sock), group=_GROUP, port=_PORT, announcement=_ANNOUNCEMENT)

        deadline = time.monotonic() + _DEADLINE__SEC
        probe = None
        while time.monotonic() < deadline:
            for frame in list(self._frames_tx):
                candidate = self._parse_tx(frame)
                if str(candidate.ip_dst) == _GROUP and candidate.dport == _PORT:
                    probe = candidate
                    break
            if probe is not None:
                break
            time.sleep(0.01)

        assert probe is not None, "The announcer datagram never reached the wire addressed to the group."
        self.assertEqual(
            parse_announcement(probe.payload),
            _ANNOUNCEMENT,
            msg="The multicast datagram on the wire must carry the announcement.",
        )
