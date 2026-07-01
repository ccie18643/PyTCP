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
Tests for the async UDP Echo server example (RFC 862 + the malpi easter
egg). The pure 'echo_reply' logic is exercised directly; the async server
wiring is exercised end-to-end over real loopback datagram sockets via the
example's injectable socket factory (no daemon required).

pytcp/tests/integration/examples/test__examples__udp_echo.py

ver 3.0.8
"""

import asyncio
import socket
from unittest import IsolatedAsyncioTestCase, TestCase

from examples.malpi import malpa, malpi, malpka
from examples.udp_echo_client import echo_once
from examples.udp_echo_server__async import echo_reply, serve


def _udp_socket() -> socket.socket:
    """
    Build a fresh unbound loopback-capable AF_INET datagram socket.
    """

    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


class TestUdpEchoReply(TestCase):
    """
    The 'echo_reply' payload-selection tests.
    """

    def test__udp_echo__reply_echoes_plain_message(self) -> None:
        """
        Ensure a plain datagram is echoed back verbatim.

        Reference: RFC 862 (Echo Protocol — return the data received).
        """

        self.assertEqual(
            echo_reply(b"hello world"),
            b"hello world",
            msg="A non-monkey message must be echoed back unchanged.",
        )

    def test__udp_echo__reply_serves_the_monkeys(self) -> None:
        """
        Ensure a request naming a monkey is answered with the matching
        ASCII-art payload, case-insensitively and ignoring surrounding
        whitespace, with 'malpka' taking precedence over 'malpa'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for request, expected, label in (
            (b"malpka\n", malpka, "malpka"),
            (b"  MALPA  ", malpa, "malpa"),
            (b"malpi!", malpi, "malpi"),
        ):
            with self.subTest(request=label):
                self.assertEqual(
                    echo_reply(request),
                    expected,
                    msg=f"A {label!r} request must be answered with the {label} monkey.",
                )


class TestUdpEchoServer(IsolatedAsyncioTestCase):
    """
    The async UDP Echo server end-to-end tests over real loopback sockets.
    """

    async def _start_server(self) -> tuple[str, int]:
        """
        Start the example's async 'serve' on a free loopback UDP port and
        return the '(host, port)' the client should target. 'serve' binds
        its OWN fresh socket (from make_socket) to it, so the factory must
        yield an UNBOUND socket — pre-binding would make serve's bind fail.
        """

        probe = _udp_socket()
        probe.bind(("127.0.0.1", 0))
        host, port = probe.getsockname()
        probe.close()

        server_task = asyncio.ensure_future(serve(host=host, port=port, make_socket=_udp_socket))
        self.addCleanup(server_task.cancel)
        # Give the datagram endpoint a moment to arm before the first send.
        await asyncio.sleep(0.05)
        return host, port

    async def _roundtrip(self, message: bytes, /) -> bytes:
        """
        Start the async server and send 'message' from a client, returning
        the reply.
        """

        loop = asyncio.get_running_loop()
        host, port = await self._start_server()

        client = _udp_socket()
        client.setblocking(False)
        self.addCleanup(client.close)
        await loop.sock_sendto(client, message, (host, port))
        data, _ = await asyncio.wait_for(loop.sock_recvfrom(client, 65535), timeout=5.0)
        return data

    async def test__udp_echo__server_echoes_datagram(self) -> None:
        """
        Ensure a datagram a client sends to the async server is echoed
        back over the loopback datagram endpoint.

        Reference: RFC 862 (Echo Protocol — return the data received).
        """

        self.assertEqual(
            await self._roundtrip(b"ping over the endpoint"),
            b"ping over the endpoint",
            msg="The async server must echo a plain datagram back to the sender.",
        )

    async def test__udp_echo__server_serves_a_monkey(self) -> None:
        """
        Ensure a 'malpi' request to the async server is answered with the
        ASCII-art monkey over the loopback datagram endpoint.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            await self._roundtrip(b"malpi"),
            malpi,
            msg="A 'malpi' request must be answered with the monkey over the endpoint.",
        )

    async def test__udp_echo__client_and_server_interoperate(self) -> None:
        """
        Ensure the example client ('echo_once') and the async server
        interoperate over loopback: the client's 'malpi' request comes back
        as the ASCII-art monkey. The blocking client runs in a worker
        thread so it does not stall the server's event loop.

        Reference: RFC 862 (Echo Protocol — client/server round trip).
        """

        host, port = await self._start_server()

        reply = await asyncio.to_thread(
            echo_once,
            host=host,
            port=port,
            message=b"malpi",
            timeout=5.0,
            make_socket=_udp_socket,
        )

        self.assertEqual(
            reply,
            malpi,
            msg="The example client and server must interoperate: 'malpi' returns the monkey.",
        )
