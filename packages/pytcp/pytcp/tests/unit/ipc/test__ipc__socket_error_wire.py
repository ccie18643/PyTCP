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
This module contains tests for the faithful socket-error wire round trip.

pytcp/tests/unit/ipc/test__ipc__socket_error_wire.py

ver 3.0.9
"""

import errno
import socket
from unittest import TestCase

from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.ipc.ipc__socket_rpc import (
    encode_exception,
    encode_socket_error,
    raise_socket_error,
)


class TestSocketErrorWire(TestCase):
    """
    The faithful socket-error wire-format round-trip tests.
    """

    def test__ipc__socket_error_wire__connection_refused_round_trips(self) -> None:
        """
        Ensure an OSError carrying ECONNREFUSED reconstructs as a
        'ConnectionRefusedError' with the original errno on the client.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_exception(ConnectionRefusedError(errno.ECONNREFUSED, "Connection refused"))

        with self.assertRaises(ConnectionRefusedError) as raised:
            raise_socket_error(body)

        self.assertEqual(
            raised.exception.errno,
            errno.ECONNREFUSED,
            msg="The reconstructed OSError must carry the original errno.",
        )

    def test__ipc__socket_error_wire__timeout_round_trips(self) -> None:
        """
        Ensure an OSError carrying ETIMEDOUT reconstructs as a
        'TimeoutError' via the errno-to-subclass mapping.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_exception(OSError(errno.ETIMEDOUT, "Connection timed out"))

        with self.assertRaises(TimeoutError) as raised:
            raise_socket_error(body)

        self.assertEqual(
            raised.exception.errno,
            errno.ETIMEDOUT,
            msg="An ETIMEDOUT error must reconstruct as TimeoutError with the errno.",
        )

    def test__ipc__socket_error_wire__blocking_io_round_trips(self) -> None:
        """
        Ensure an OSError carrying EAGAIN reconstructs as a
        'BlockingIOError' with the original errno.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_exception(BlockingIOError(errno.EAGAIN, "Resource temporarily unavailable"))

        with self.assertRaises(BlockingIOError) as raised:
            raise_socket_error(body)

        self.assertEqual(
            raised.exception.errno,
            errno.EAGAIN,
            msg="An EAGAIN error must reconstruct as BlockingIOError with the errno.",
        )

    def test__ipc__socket_error_wire__gaierror_round_trips(self) -> None:
        """
        Ensure a 'socket.gaierror' reconstructs as 'socket.gaierror' by
        name rather than collapsing into a plain OSError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_exception(socket.gaierror(socket.EAI_NONAME, "Name or service not known"))

        with self.assertRaises(socket.gaierror) as raised:
            raise_socket_error(body)

        self.assertEqual(
            raised.exception.args[0],
            socket.EAI_NONAME,
            msg="The reconstructed gaierror must carry the original EAI code.",
        )

    def test__ipc__socket_error_wire__overflow_round_trips(self) -> None:
        """
        Ensure a non-OSError builtin exception reconstructs as that same
        builtin type from its args.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_exception(OverflowError("value out of range"))

        with self.assertRaises(OverflowError) as raised:
            raise_socket_error(body)

        self.assertEqual(
            str(raised.exception),
            "value out of range",
            msg="The reconstructed builtin must preserve its message.",
        )

    def test__ipc__socket_error_wire__unknown_falls_back_to_remote_error(self) -> None:
        """
        Ensure a minimal error body with no errno and an unrecognised
        module falls back to the generic 'IpcRemoteError' boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_socket_error(error_type="WeirdDaemonError", message="something odd happened")

        with self.assertRaises(IpcRemoteError) as raised:
            raise_socket_error(body)

        self.assertEqual(
            (raised.exception.error_type, raised.exception.remote_message),
            ("WeirdDaemonError", "something odd happened"),
            msg="An unreconstructable error must surface as IpcRemoteError with the remote type and message.",
        )

    def test__ipc__socket_error_wire__key_error_reconstructs_as_builtin(self) -> None:
        """
        Ensure a daemon-raised builtin KeyError reconstructs as KeyError
        rather than the generic remote-error boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        body = encode_exception(KeyError("missing registry key"))

        with self.assertRaises(KeyError):
            raise_socket_error(body)
