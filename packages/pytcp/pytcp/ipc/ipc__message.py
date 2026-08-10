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
This module contains the IPC control-channel message envelope.

A message is a fixed 7-byte header (kind:u8, op:u16, req_id:u32) followed
by an opaque op-specific body. It is the unit a single frame
(ipc__frame.py) carries: the framing restores the message boundary, this
envelope routes the bytes to a handler and correlates a response to its
request. Like ipc__frame, this module is part of the extraction-ready
codec core — net_proto + stdlib only, no pytcp stack reach-in (see
docs/refactor/kernel_userspace_separation.md §2).

The 'op' field is decoded as a raw 16-bit opcode, not resolved to an
'IpcOp' member, so an unknown op survives decode and is answered with a
RESPONSE_ERROR at dispatch (ENOSYS-style) rather than dropping the
connection — a newer client's op against an older daemon degrades
gracefully. The 'kind' field is the fixed three-value framing concept
the IPC layer owns and IS validated on decode (an unknown kind is a
structural protocol error).

pytcp/ipc/ipc__message.py

ver 3.0.9
"""

import struct
from dataclasses import dataclass
from typing import Self

from net_addr import Buffer
from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__errors import IpcMessageError

IPC__MESSAGE__HEADER_STRUCT: str = "! B H I"
IPC__MESSAGE__HEADER_LEN: int = 7


@dataclass(frozen=True, kw_only=True, slots=True)
class IpcMessage:
    """
    A single IPC control-channel message: a typed envelope around an
    opaque op-specific body.
    """

    kind: IpcMessageKind
    op: int  # Raw 16-bit opcode; IpcOp is the known-value vocabulary.
    req_id: int
    body: bytes = b""

    def to_bytes(self) -> bytes:
        """
        Encode the message as its 7-byte header followed by the body.
        """

        return struct.pack(IPC__MESSAGE__HEADER_STRUCT, self.kind, self.op, self.req_id) + self.body

    @classmethod
    def from_bytes(cls, buffer: Buffer, /) -> Self:
        """
        Decode a message from a frame payload.
        """

        if len(buffer) < IPC__MESSAGE__HEADER_LEN:
            raise IpcMessageError(
                f"Message buffer of {len(buffer)} bytes is shorter than the "
                f"{IPC__MESSAGE__HEADER_LEN}-byte header.",
            )

        view = memoryview(buffer)
        kind_raw, op_raw, req_id = struct.unpack(IPC__MESSAGE__HEADER_STRUCT, view[:IPC__MESSAGE__HEADER_LEN])

        try:
            kind = IpcMessageKind(kind_raw)
        except ValueError as error:
            raise IpcMessageError(f"Unknown message kind {kind_raw}.") from error

        return cls(
            kind=kind,
            op=int(op_raw),
            req_id=int(req_id),
            body=bytes(view[IPC__MESSAGE__HEADER_LEN:]),
        )
