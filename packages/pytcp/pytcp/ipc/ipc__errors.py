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
This module contains the IPC-layer error classes.

pytcp/ipc/ipc__errors.py

ver 3.0.10
"""

from typing import override

from net_proto.lib.errors import PyTcpError


class IpcError(PyTcpError):
    """
    The base class for all IPC-layer exceptions.
    """

    @override
    def __init__(self, message: str, /) -> None:
        super().__init__("[IPC] " + message)


class IpcFrameError(IpcError):
    """
    Exception raised when stream frame encoding or decoding fails.
    """


class IpcMessageError(IpcError):
    """
    Exception raised when control-channel message encoding or decoding
    fails (truncated header, unknown message kind or op code).
    """


class IpcConnectionError(IpcError):
    """
    Exception raised when an IPC client operation fails because the
    daemon connection is closed or unusable.
    """


class IpcValueError(IpcError):
    """
    Exception raised when a control-plane value cannot be encoded to or
    decoded from its tagged wire form (unsupported type, missing type
    tag, or unknown type tag).
    """


class IpcRemoteError(IpcError):
    """
    Exception raised client-side when a control-plane RPC call fails on
    the daemon. Carries the remote exception's class name ('error_type')
    and message ('remote_message') so the caller can see what went wrong
    across the boundary. A Phase-1 simplification: the original exception
    type is reported, not reconstructed — every remote failure surfaces
    as this single type.
    """

    error_type: str
    remote_message: str

    def __init__(self, *, error_type: str, message: str) -> None:
        super().__init__(f"{error_type}: {message}")
        self.error_type = error_type
        self.remote_message = message
