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
This module captures a reference to the real standard-library 'socket'
module.

The daemon-backed drop-in installs 'pytcp.socket' as the process-wide
'socket' module ('sys.modules["socket"] = pytcp.socket', the one-line
import swap). After that swap, any internal module whose own 'import
socket' is first executed resolves to the drop-in — which has no
'AF_UNIX' / 'SCM_RIGHTS' / 'socketpair'. The client and IPC modules that
need those real primitives import 'stdlib_socket' from here instead.

This module is imported by 'socket__dropin' (and therefore loaded while
'import pytcp' is still in progress, before a consumer can perform the
swap), so the reference captured below is always the genuine stdlib
module, regardless of when a consuming module is first imported.

pytcp/ipc/ipc__stdlib_socket.py

ver 3.0.9
"""

import socket

# The genuine stdlib 'socket' module, captured at first import (before
# any consumer 'sys.modules["socket"]' swap). Internal modules import
# THIS in place of their own 'import socket'.
stdlib_socket = socket
