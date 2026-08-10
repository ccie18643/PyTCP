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
This module contains the client-side remote-exception reconstruction.

'raise_remote_error' turns a decoded RESPONSE_ERROR document — carrying
the remote exception's type name, module, errno, args, message, and
strerror — back into a faithful local exception: an 'OSError' whose
concrete subclass Python auto-selects from the errno (a refused connect
becomes 'ConnectionRefusedError', a timeout 'TimeoutError', ...), a
'stdlib_socket.gaierror' / 'stdlib_socket.herror' rebuilt by name, a non-OSError
builtin exception rebuilt from its args, or — when nothing matches — the
generic 'IpcRemoteError' boundary. It is the socket-plane analogue of
the control plane's deliberately coarse 'IpcRemoteError' translation and
is what lets the daemon-backed socket drop-in raise the same exceptions a
real stdlib socket would. It lives in the IPC layer (not the client
layer) because the socket-plane RPC helpers that call it live here, and
'pytcp.client' already depends on 'pytcp.ipc' — the reverse dependency
would be a cycle.

pytcp/ipc/ipc__remote_error.py

ver 3.0.10
"""

import builtins
from typing import Any, NoReturn

from pytcp.ipc.ipc__errors import IpcRemoteError
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket
from pytcp.ipc.ipc__values import decode_value

# stdlib_socket.gaierror / stdlib_socket.herror are OSError subclasses keyed by EAI /
# h_errno codes that the errno->subclass map does not cover, so they are
# rebuilt by name rather than through the errno branch.
_SOCKET_ERROR_TYPES: dict[str, type[OSError]] = {
    "gaierror": stdlib_socket.gaierror,
    "herror": stdlib_socket.herror,
}


def raise_remote_error(document: dict[str, Any], /) -> NoReturn:
    """
    Reconstruct and raise the remote exception described by 'document'.
    """

    error_type = str(document["error"])
    message = str(document.get("message", ""))
    module = document.get("module")
    errno_value = document.get("errno")
    strerror = document.get("strerror")
    args = tuple(decode_value(item) for item in document.get("args", []))

    if module == "socket" and error_type in _SOCKET_ERROR_TYPES:
        socket_error_type = _SOCKET_ERROR_TYPES[error_type]
        raise (socket_error_type(*args) if args else socket_error_type(message))

    if errno_value is not None:
        # OSError.__new__ auto-selects the concrete subclass (e.g.
        # ConnectionRefusedError, TimeoutError, BlockingIOError) from the
        # errno, so a single OSError construction reconstructs the family.
        raise OSError(int(errno_value), strerror if strerror is not None else message)

    if module == "builtins":
        builtin = getattr(builtins, error_type, None)
        if isinstance(builtin, type) and issubclass(builtin, Exception):
            # 'builtin' is a class (verified callable by the guard above);
            # pylint does not narrow through 'isinstance'/'issubclass'.
            raise (builtin(*args) if args else builtin(message))  # pylint: disable=not-callable

    raise IpcRemoteError(error_type=error_type, message=message)
