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
This module contains the socket-list introspection API.

'SocketIntrospectApi' is the stack's socket-observation surface — the
Linux 'ss' analogue. 'list_sockets' walks the open-socket table and
returns a tuple of immutable 'SocketSnapshot' values (copy-by-value, so
the caller cannot mutate socket state through them — the Phase-3
"introspection is read-only" north-star constraint). 'build_socket_
snapshots' is the pure mapping/filtering core, so it is testable without
a running stack.

net_proto/protocols are unaffected — this is a pytcp-side observation API
over the live socket table.

pytcp/stack/socket_introspect.py

ver 3.0.10
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from net_addr import Ip4Address, Ip6Address
from pytcp.protocols.tcp.tcp__enums import FsmState
from pytcp.runtime.socket import AddressFamily, SocketType


@dataclass(frozen=True, kw_only=True, slots=True)
class SocketSnapshot:
    """
    Immutable point-in-time view of one open socket — the unit the
    introspection side of the socket API returns ('ss'). Copy-by-value:
    the caller cannot mutate socket state through it.
    """

    address_family: AddressFamily
    socket_type: SocketType
    local_address: Ip4Address | Ip6Address
    local_port: int
    remote_address: Ip4Address | Ip6Address
    remote_port: int
    state: FsmState | None
    rx_queue: int
    tx_queue: int


class IntrospectableSocket(Protocol):
    """
    The read-only socket surface 'build_socket_snapshots' depends on.
    """

    @property
    def address_family(self) -> AddressFamily:
        """
        Get the socket's address family.
        """

        ...

    @property
    def socket_type(self) -> SocketType:
        """
        Get the socket's type.
        """

        ...

    @property
    def local_ip_address(self) -> Ip4Address | Ip6Address:
        """
        Get the socket's local IP address.
        """

        ...

    @property
    def remote_ip_address(self) -> Ip4Address | Ip6Address:
        """
        Get the socket's remote IP address.
        """

        ...

    @property
    def local_port(self) -> int:
        """
        Get the socket's local port.
        """

        ...

    @property
    def remote_port(self) -> int:
        """
        Get the socket's remote port.
        """

        ...


def _socket_state(sock: IntrospectableSocket, /) -> FsmState | None:
    """
    Return the TCP FSM state of a socket, or None for a non-TCP socket.
    """

    state = getattr(sock, "state", None)
    return state if isinstance(state, FsmState) else None


def _socket_queues(sock: IntrospectableSocket, /) -> tuple[int, int]:
    """
    Return the (rx, tx) queued byte counts of a socket (0, 0 when the
    socket has no buffer accounting — a non-TCP socket).
    """

    status_getter = getattr(sock, "status", None)
    if not callable(status_getter):
        return 0, 0
    status = status_getter()
    return int(getattr(status, "rx_buffer_len", 0)), int(getattr(status, "tx_buffer_len", 0))


def _is_listening(sock: IntrospectableSocket, state: FsmState | None, /) -> bool:
    """
    Return whether a socket counts as listening for the 'ss -l' filter —
    a TCP socket in LISTEN, or a non-TCP socket with no connected peer.
    """

    if state is not None:
        return state is FsmState.LISTEN
    return sock.remote_port == 0


def _sort_key(snapshot: SocketSnapshot, /) -> tuple[int, int, int, str, int, str]:
    """
    Build the deterministic sort key for a socket snapshot.
    """

    return (
        int(snapshot.address_family),
        int(snapshot.socket_type),
        snapshot.local_port,
        str(snapshot.local_address),
        snapshot.remote_port,
        str(snapshot.remote_address),
    )


def build_socket_snapshots(
    sockets: Iterable[IntrospectableSocket],
    *,
    family: AddressFamily | None = None,
    socket_type: SocketType | None = None,
    listening_only: bool = False,
) -> tuple[SocketSnapshot, ...]:
    """
    Map the live sockets to a deterministically-sorted tuple of snapshots,
    filtered by family / type / listening state.
    """

    snapshots: list[SocketSnapshot] = []

    for sock in sockets:
        if family is not None and sock.address_family is not family:
            continue
        if socket_type is not None and sock.socket_type is not socket_type:
            continue

        state = _socket_state(sock)
        if listening_only and not _is_listening(sock, state):
            continue

        rx_queue, tx_queue = _socket_queues(sock)
        snapshots.append(
            SocketSnapshot(
                address_family=sock.address_family,
                socket_type=sock.socket_type,
                local_address=sock.local_ip_address,
                local_port=sock.local_port,
                remote_address=sock.remote_ip_address,
                remote_port=sock.remote_port,
                state=state,
                rx_queue=rx_queue,
                tx_queue=tx_queue,
            )
        )

    return tuple(sorted(snapshots, key=_sort_key))


class SocketIntrospectApi:
    """
    The socket-list introspection API (the Linux 'ss' analogue).
    """

    def list_sockets(
        self,
        *,
        family: AddressFamily | None = None,
        socket_type: SocketType | None = None,
        listening_only: bool = False,
    ) -> tuple[SocketSnapshot, ...]:
        """
        Return a read-only copy-by-value snapshot of the open sockets,
        filtered by family / type / listening state — Linux 'ss'.
        """

        import pytcp.stack as _stack

        sockets = [sock for _socket_id, sock in _stack.sockets.items()]
        return build_socket_snapshots(
            sockets,
            family=family,
            socket_type=socket_type,
            listening_only=listening_only,
        )
