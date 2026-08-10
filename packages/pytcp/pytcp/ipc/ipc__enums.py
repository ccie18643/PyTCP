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
This module contains the IPC control-channel message enumerations.

The op space is a PyTCP-internal protocol with no stdlib-socket
counterpart, so the members carry no bare module-level aliases (see
.claude/rules/enums.md §2.1). New ops are appended as later phases marshal
the socket syscalls and the control APIs over the channel.

pytcp/ipc/ipc__enums.py

ver 3.0.9
"""

from enum import IntEnum


class IpcMessageKind(IntEnum):
    """
    The control-channel message kind — whether a message is a request
    or one of the two response flavours (success / error).
    """

    REQUEST = 0
    RESPONSE_OK = 1
    RESPONSE_ERROR = 2


class IpcOp(IntEnum):
    """
    The control-channel operation code identifying which request /
    response pair a message belongs to. The same 'op' value appears on a
    request and on its matching response.
    """

    PING = 0
    CONTROL_CALL = 1
    SOCKET_CALL = 2
