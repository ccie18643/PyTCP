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
This module contains behavioural unit tests for the daemon-backed
'pytcp.socket' drop-in 'Socket' wrapper and its 'socket()' factory.

Every test constructs the wrapper over a 'create_autospec' client
shim (or patches the lazy default-stack accessor for the factory
tests), so the daemon-independent logic — blocking-mode state,
stream-only operation guards, the stdlib 'makefile' mode parsing
and shared-fd refcount, and the factory's family / type / proto
dispatch — is exercised without a live daemon. The end-to-end data
path is covered separately by the daemon integration suite under
'tests/integration/ipc/test__ipc__socket_dropin*.py'.

pytcp/tests/unit/socket/test__socket__dropin__behaviour.py

ver 3.0.8
"""

import errno
import io
from unittest import TestCase
from unittest.mock import create_autospec, patch

import pytcp.socket as pytcp_socket
import pytcp.socket.socket__dropin as dropin
from net_proto.lib.enums import IpProto
from pytcp.client import ClientStack, ClientTcpSocket, ClientUdpSocket
from pytcp.runtime.socket import IPPROTO_ICMP, AddressFamily, SocketType
from pytcp.socket.socket__dropin import Socket


def _stream_socket() -> Socket:
    """
    Build a 'Socket' over an autospec'd stream client shim.
    """

    return Socket(
        create_autospec(ClientTcpSocket, spec_set=True),
        family=AddressFamily.INET4,
        type=SocketType.STREAM,
        proto=0,
    )


def _dgram_socket() -> Socket:
    """
    Build a 'Socket' over an autospec'd datagram client shim.
    """

    return Socket(
        create_autospec(ClientUdpSocket, spec_set=True),
        family=AddressFamily.INET4,
        type=SocketType.DGRAM,
        proto=0,
    )


class TestSocketDropinBlockingMode(TestCase):
    """
    The drop-in blocking-mode state tests.
    """

    def test__socket__dropin__default_socket_is_blocking(self) -> None:
        """
        Ensure a freshly constructed drop-in socket reports blocking
        mode (timeout None), matching the stdlib default.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        self.assertIs(
            _stream_socket().getblocking(),
            True,
            msg="A freshly constructed drop-in socket must report blocking mode.",
        )

    def test__socket__dropin__setblocking_false_makes_getblocking_false(self) -> None:
        """
        Ensure setblocking(False) flips getblocking() to False — pinning
        the 'self._timeout != 0.0' blocking predicate against a '=='
        edit and the 'None if flag else 0.0' state assignment.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        sock = _stream_socket()
        sock.setblocking(False)

        self.assertIs(
            sock.getblocking(),
            False,
            msg="setblocking(False) must make getblocking() report False (timeout 0.0).",
        )

    def test__socket__dropin__setblocking_true_makes_getblocking_true(self) -> None:
        """
        Ensure setblocking(True) restores getblocking() to True after a
        prior non-blocking switch.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        sock = _stream_socket()
        sock.setblocking(False)
        sock.setblocking(True)

        self.assertIs(
            sock.getblocking(),
            True,
            msg="setblocking(True) must restore blocking mode (timeout None).",
        )


class TestSocketDropinStreamOnlyGuards(TestCase):
    """
    The drop-in stream-only operation-guard tests.
    """

    def test__socket__dropin__listen_on_datagram_raises_eopnotsupp(self) -> None:
        """
        Ensure listen() on a non-stream socket raises OSError(EOPNOTSUPP)
        — pinning the 'self._type is not SocketType.STREAM' guard against
        an 'is' edit that would let a datagram socket fall through to the
        control shim.

        Reference: RFC 9293 §3.9 (User/TCP interface — passive OPEN is stream-only).
        """

        with self.assertRaises(OSError) as ctx:
            _dgram_socket().listen()

        self.assertEqual(
            ctx.exception.errno,
            errno.EOPNOTSUPP,
            msg="listen() on a datagram socket must raise OSError(EOPNOTSUPP).",
        )

    def test__socket__dropin__accept_on_datagram_raises_eopnotsupp(self) -> None:
        """
        Ensure accept() on a non-stream socket raises OSError(EOPNOTSUPP).

        Reference: RFC 9293 §3.9 (User/TCP interface — accept is stream-only).
        """

        with self.assertRaises(OSError) as ctx:
            _dgram_socket().accept()

        self.assertEqual(
            ctx.exception.errno,
            errno.EOPNOTSUPP,
            msg="accept() on a datagram socket must raise OSError(EOPNOTSUPP).",
        )

    def test__socket__dropin__shutdown_on_datagram_raises_eopnotsupp(self) -> None:
        """
        Ensure shutdown() on a non-stream socket raises OSError(EOPNOTSUPP).

        Reference: RFC 9293 §3.9 (User/TCP interface — shutdown is stream-only).
        """

        with self.assertRaises(OSError) as ctx:
            _dgram_socket().shutdown(0)

        self.assertEqual(
            ctx.exception.errno,
            errno.EOPNOTSUPP,
            msg="shutdown() on a datagram socket must raise OSError(EOPNOTSUPP).",
        )

    def test__socket__dropin__dup_on_datagram_raises_eopnotsupp(self) -> None:
        """
        Ensure dup() on a non-stream socket raises OSError(EOPNOTSUPP).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(OSError) as ctx:
            _dgram_socket().dup()

        self.assertEqual(
            ctx.exception.errno,
            errno.EOPNOTSUPP,
            msg="dup() on a datagram socket must raise OSError(EOPNOTSUPP).",
        )


class TestSocketDropinMakefile(TestCase):
    """
    The drop-in 'makefile' mode-parsing and refcount tests.
    """

    def test__socket__dropin__makefile_rejects_invalid_mode(self) -> None:
        """
        Ensure makefile() with a mode containing characters outside
        {r, w, b} raises ValueError — pinning the 'set(mode) <= {r, w, b}'
        subset guard against a '!=' edit that would admit arbitrary
        modes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as ctx:
            _stream_socket().makefile("xyz")

        self.assertIn(
            "invalid mode",
            str(ctx.exception),
            msg="makefile() must reject a mode with characters outside {r, w, b}.",
        )

    def test__socket__dropin__makefile_read_mode_returns_buffered_reader(self) -> None:
        """
        Ensure makefile('rb') returns a read-only buffered reader.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            _stream_socket().makefile("rb"),
            io.BufferedReader,
            msg="makefile('rb') must return an io.BufferedReader.",
        )

    def test__socket__dropin__makefile_write_mode_returns_buffered_writer(self) -> None:
        """
        Ensure makefile('wb') returns a write-only buffered writer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            _stream_socket().makefile("wb"),
            io.BufferedWriter,
            msg="makefile('wb') must return an io.BufferedWriter.",
        )

    def test__socket__dropin__makefile_read_write_mode_returns_rw_pair(self) -> None:
        """
        Ensure makefile('rwb') returns a read-write buffered pair —
        pinning the 'reading = "r" in mode or not writing' parse against
        an 'and' edit that would collapse the read+write mode to
        write-only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            _stream_socket().makefile("rwb"),
            io.BufferedRWPair,
            msg="makefile('rwb') must return an io.BufferedRWPair (both directions).",
        )

    def test__socket__dropin__makefile_unbuffered_text_mode_rejected(self) -> None:
        """
        Ensure an unbuffered (buffering=0) non-binary makefile raises
        ValueError, mirroring the stdlib 'unbuffered streams must be
        binary' rule.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError) as ctx:
            _stream_socket().makefile("r", buffering=0)

        self.assertIn(
            "unbuffered",
            str(ctx.exception),
            msg="An unbuffered non-binary makefile must raise ValueError.",
        )

    def test__socket__dropin__makefile_stream_holds_close_until_decref(self) -> None:
        """
        Ensure a socket with an outstanding makefile stream defers the
        real daemon-handle close until the stream drops its reference —
        pinning the 'self._io_refs <= 0' close gate and the decref
        ordering of the stdlib shared-fd ownership contract.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        underlying = create_autospec(ClientTcpSocket, spec_set=True)
        sock = Socket(
            underlying,
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            proto=0,
        )
        stream = sock.makefile("rb")

        sock.close()
        underlying.close.assert_not_called()

        stream.close()
        underlying.close.assert_called_once_with()


class TestSocketDropinFactoryDispatch(TestCase):
    """
    The 'pytcp.socket.socket()' factory family/type/proto dispatch tests.
    """

    def test__socket__dropin__factory_raw_forwards_proto(self) -> None:
        """
        Ensure socket(AF_INET, SOCK_RAW, proto) forwards the IANA
        next-header proto to the daemon-stack socket factory — pinning
        the 'socket_type is SocketType.RAW' arm of the proto dispatch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client_stack = create_autospec(ClientStack, spec_set=True)
        with patch.object(dropin, "_get_default_stack", return_value=client_stack):
            dropin.socket(AddressFamily.INET4, SocketType.RAW, IPPROTO_ICMP)

        client_stack.socket.assert_called_once_with(
            AddressFamily.INET4,
            SocketType.RAW,
            IpProto.ICMP4,
        )

    def test__socket__dropin__factory_plain_dgram_drops_proto(self) -> None:
        """
        Ensure socket(AF_INET, SOCK_DGRAM, 0) passes protocol=None to the
        daemon-stack factory — a plain datagram socket ignores proto.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client_stack = create_autospec(ClientStack, spec_set=True)
        with patch.object(dropin, "_get_default_stack", return_value=client_stack):
            dropin.socket(AddressFamily.INET4, SocketType.DGRAM, 0)

        client_stack.socket.assert_called_once_with(
            AddressFamily.INET4,
            SocketType.DGRAM,
            None,
        )

    def test__socket__dropin__factory_icmp_dgram_forwards_proto(self) -> None:
        """
        Ensure socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) forwards the
        proto (an unprivileged ICMP-Echo 'ping' socket keys on it) —
        pinning the 'SocketType.DGRAM and proto in (ICMP4, ICMP6)' arm.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client_stack = create_autospec(ClientStack, spec_set=True)
        with patch.object(dropin, "_get_default_stack", return_value=client_stack):
            dropin.socket(AddressFamily.INET4, SocketType.DGRAM, IPPROTO_ICMP)

        client_stack.socket.assert_called_once_with(
            AddressFamily.INET4,
            SocketType.DGRAM,
            IpProto.ICMP4,
        )

    def test__socket__dropin__factory_rejects_fileno_wrapping(self) -> None:
        """
        Ensure socket(fileno=...) raises NotImplementedError — the
        daemon-backed drop-in cannot adopt an arbitrary descriptor.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            dropin.socket(AddressFamily.INET4, SocketType.STREAM, 0, fileno=3)


class TestSocketDropinModuleSurface(TestCase):
    """
    The 'pytcp.socket' module-surface constant tests.
    """

    def test__socket__dropin__has_ipv6_is_true(self) -> None:
        """
        Ensure the drop-in advertises IPv6 support via 'has_ipv6',
        mirroring a dual-stack stdlib socket module.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            pytcp_socket.has_ipv6,
            True,
            msg="pytcp.socket.has_ipv6 must be True (the daemon stack is dual-stack).",
        )
