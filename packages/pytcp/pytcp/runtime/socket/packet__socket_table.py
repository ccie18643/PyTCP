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
This module contains the lock-guarded registry of open AF_PACKET
sockets — the fan-out lookup the Ethernet RX tap uses to deliver a
copy of each matching frame to every bound packet socket.

pytcp/runtime/socket/packet__socket_table.py

ver 3.0.10
"""

import threading

from net_proto.lib.enums import EtherType
from pytcp.runtime.socket import ETH_P_ALL
from pytcp.runtime.socket.packet__socket import PacketSocket


class PacketSocketTable:
    """
    The stack-wide registry of open AF_PACKET sockets.

    Unlike the IP-keyed 'SocketTable' (which maps one 'SocketId' to one
    socket for unicast delivery), packet-socket delivery is a TAP:
    every socket whose '(ifindex, ethertype)' filter matches an inbound
    frame gets its own copy. The registry is therefore a flat list of
    sockets with a 'matching()' fan-out query, not a unique-key map.

    Every operation is guarded by a single lock — the RX-side packet
    handler iterates the set (delivery fan-out) while app threads
    register / unregister sockets at construct / close time, and
    free-threaded builds need the explicit guard. 'matching()' /
    'snapshot()' return detached lists taken under the lock so an RX
    thread can iterate while another thread mutates the registry.
    """

    def __init__(self) -> None:
        """
        Initialize an empty registry and its guarding lock.
        """

        self._lock = threading.Lock()
        self._sockets: list[PacketSocket] = []

    def register(self, sock: PacketSocket, /) -> None:
        """
        Add 'sock' to the registry (its capture filter becomes live).
        """

        with self._lock:
            self._sockets.append(sock)

    def unregister(self, sock: PacketSocket, /) -> None:
        """
        Remove 'sock' from the registry; a no-op when it is absent.
        """

        with self._lock:
            if sock in self._sockets:
                self._sockets.remove(sock)

    def matching(self, *, ifindex: int, ethertype: EtherType | int) -> list[PacketSocket]:
        """
        Return every registered socket whose filter matches a frame of
        'ethertype' arriving on interface 'ifindex'. A socket matches
        when its ifindex is 0 (unbound = any interface) or equals
        'ifindex', AND its ethertype filter is ETH_P_ALL (capture-all)
        or equals the frame's ethertype. Comparison is on the integer
        value so an 'EtherType' member and a bare-int filter unify.
        """

        target = int(ethertype)
        with self._lock:
            return [
                sock
                for sock in self._sockets
                if sock.ifindex in (0, ifindex) and int(sock.ethertype) in (ETH_P_ALL, target)
            ]

    def snapshot(self) -> list[PacketSocket]:
        """
        Return a detached snapshot list of the registered sockets.
        """

        with self._lock:
            return list(self._sockets)

    def clear(self) -> None:
        """
        Remove every registered socket.
        """

        with self._lock:
            self._sockets.clear()

    def __len__(self) -> int:
        """
        Return the number of registered sockets.
        """

        with self._lock:
            return len(self._sockets)

    def __bool__(self) -> bool:
        """
        Return whether any packet socket is registered — the RX tap's
        cheap "is anything bound?" short-circuit guard.
        """

        with self._lock:
            return bool(self._sockets)
