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
This module contains the IPC datagram data-channel frame codec.

A datagram socket's data channel is a SOCK_DGRAM socketpair, which
preserves message boundaries — one PyTCP datagram is carried as one
AF_UNIX datagram. Each frame prefixes the payload with the peer address
and any ancillary control messages so 'recvfrom' / 'recvmsg' (daemon ->
client: who sent it, with which cmsgs) and 'sendto' (client -> daemon:
where to send it) survive the boundary:

    tag(1) [ port(2) ip(4|16) ] ncmsg(1) [ level(2) type(2) len(2) data ]* payload

The tag is the address family: 0 = no address (a connected-socket send),
4 = IPv4 (4-byte address), 6 = IPv6 (16-byte address). The IP is packed
with 'inet_pton' and read back with 'inet_ntop', so the address survives
as its canonical string form. 'ncmsg' counts the ancillary control
messages (IP_TOS / IP_OPTIONS / IPV6_TCLASS); each is a Linux
'(cmsg_level, cmsg_type, cmsg_data)' triple. This codec is net_proto +
stdlib only — no pytcp stack reach-in (extraction-ready, see
docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__dgram_frame.py

ver 3.0.8
"""

from net_addr import Buffer
from pytcp.ipc.ipc__errors import IpcFrameError
from pytcp.ipc.ipc__stdlib_socket import stdlib_socket

IPC__DGRAM__TAG_NONE: int = 0
IPC__DGRAM__TAG_IP4: int = 4
IPC__DGRAM__TAG_IP6: int = 6
IPC__DGRAM__PORT_LEN: int = 2
IPC__DGRAM__IP4_LEN: int = 4
IPC__DGRAM__IP6_LEN: int = 16
IPC__DGRAM__NCMSG_LEN: int = 1
IPC__DGRAM__CMSG_LEVEL_LEN: int = 2
IPC__DGRAM__CMSG_TYPE_LEN: int = 2
IPC__DGRAM__CMSG_DATALEN_LEN: int = 2

# An ancillary control message — a Linux '(cmsg_level, cmsg_type,
# cmsg_data)' triple as produced by 'recvmsg'.
type Cmsg = tuple[int, int, bytes]


def encode_dgram(
    address: tuple[str, int] | None,
    payload: Buffer,
    cmsg: list[Cmsg] | tuple[Cmsg, ...] = (),
    /,
) -> bytes:
    """
    Encode a datagram into a framed blob carrying its optional peer
    address and any ancillary control messages ahead of the payload.
    """

    if address is None:
        prefix = bytes([IPC__DGRAM__TAG_NONE])
    else:
        host, port = address
        try:
            packed = stdlib_socket.inet_pton(stdlib_socket.AF_INET, host)
            tag = IPC__DGRAM__TAG_IP4
        except OSError:
            packed = stdlib_socket.inet_pton(stdlib_socket.AF_INET6, host)
            tag = IPC__DGRAM__TAG_IP6
        prefix = bytes([tag]) + port.to_bytes(IPC__DGRAM__PORT_LEN, "big") + packed

    parts = [prefix, bytes([len(cmsg)])]
    for level, ctype, data in cmsg:
        parts.append(
            level.to_bytes(IPC__DGRAM__CMSG_LEVEL_LEN, "big")
            + ctype.to_bytes(IPC__DGRAM__CMSG_TYPE_LEN, "big")
            + len(data).to_bytes(IPC__DGRAM__CMSG_DATALEN_LEN, "big")
            + bytes(data)
        )
    parts.append(bytes(payload))

    return b"".join(parts)


def decode_dgram(blob: Buffer, /) -> tuple[tuple[str, int] | None, list[Cmsg], bytes]:
    """
    Decode a framed datagram blob into its optional peer address, its
    ancillary control messages, and its payload.
    """

    data = bytes(blob)

    if not data:
        raise IpcFrameError("Datagram frame is empty (no address-family tag).")

    tag = data[0]
    address: tuple[str, int] | None

    if tag == IPC__DGRAM__TAG_NONE:
        address = None
        offset = 1
    else:
        if tag == IPC__DGRAM__TAG_IP4:
            family, ip_len = stdlib_socket.AF_INET, IPC__DGRAM__IP4_LEN
        elif tag == IPC__DGRAM__TAG_IP6:
            family, ip_len = stdlib_socket.AF_INET6, IPC__DGRAM__IP6_LEN
        else:
            raise IpcFrameError(f"Datagram frame has an unknown address-family tag {tag}.")

        ip_start = 1 + IPC__DGRAM__PORT_LEN
        offset = ip_start + ip_len

        if len(data) < offset:
            raise IpcFrameError("Datagram frame is truncated before the end of its address.")

        address = (stdlib_socket.inet_ntop(family, data[ip_start:offset]), int.from_bytes(data[1:ip_start], "big"))

    if len(data) < offset + IPC__DGRAM__NCMSG_LEN:
        raise IpcFrameError("Datagram frame is truncated before its cmsg count.")

    ncmsg = data[offset]
    offset += IPC__DGRAM__NCMSG_LEN

    cmsg: list[Cmsg] = []
    cmsg_meta_len = IPC__DGRAM__CMSG_LEVEL_LEN + IPC__DGRAM__CMSG_TYPE_LEN + IPC__DGRAM__CMSG_DATALEN_LEN
    for _ in range(ncmsg):
        if len(data) < offset + cmsg_meta_len:
            raise IpcFrameError("Datagram frame is truncated inside a cmsg header.")
        level = int.from_bytes(data[offset : offset + IPC__DGRAM__CMSG_LEVEL_LEN], "big")
        ctype = int.from_bytes(
            data[offset + IPC__DGRAM__CMSG_LEVEL_LEN : offset + IPC__DGRAM__CMSG_LEVEL_LEN + IPC__DGRAM__CMSG_TYPE_LEN],
            "big",
        )
        datalen = int.from_bytes(
            data[offset + cmsg_meta_len - IPC__DGRAM__CMSG_DATALEN_LEN : offset + cmsg_meta_len], "big"
        )
        offset += cmsg_meta_len
        if len(data) < offset + datalen:
            raise IpcFrameError("Datagram frame is truncated inside a cmsg payload.")
        cmsg.append((level, ctype, data[offset : offset + datalen]))
        offset += datalen

    return address, cmsg, data[offset:]
