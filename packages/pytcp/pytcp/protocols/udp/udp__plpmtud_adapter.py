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
The UDP-side PLPMTUD adapter. 'UdpPlpmtudAdapter' wraps a
'PmtuSearch' engine and exposes a manual-driven API the
application calls to drive RFC 8899 §6 probe / ack / loss
events. Vanilla UDP has no native ACK channel, so PLPMTUD
on UDP is application-driven: protocols built on UDP
(QUIC's PATH_CHALLENGE / PATH_RESPONSE, SCTP's HEARTBEAT,
or any echo/heartbeat the application defines) call
'probe_pmtu(size)' to send a probe, 'ack_probe()' when
their app-layer ACK confirms the probe arrived, and
'timeout_probe()' when their app-layer timer expires
without an ACK.

Unlike TcpPlpmtudAdapter, the UDP adapter tracks at most
one outstanding probe at a time — concurrent multi-size
probing on UDP is rejected so the application's ACK
unambiguously maps to the single in-flight probe.

Design rationale and per-phase migration plan:
docs/refactor/plpmtud_unified_engine.md

pytcp/protocols/udp/udp__plpmtud_adapter.py

ver 3.0.8
"""

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.plpmtud import PmtuSearch, PmtuState


class UdpPlpmtudAdapter:
    """
    Per-socket PLPMTUD adapter for UDP. Owns the
    'PmtuSearch' engine for the socket's connected peer
    and a single 'in_flight_size' slot for the outstanding
    probe.
    """

    __slots__ = ("_engine", "_in_flight_size")

    _engine: PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]
    _in_flight_size: int | None

    def __init__(
        self,
        *,
        remote_ip_address: Ip4Address | Ip6Address,
        interface_mtu: int,
    ) -> None:
        """
        Initialize the adapter for one connected UDP socket.
        """

        if isinstance(remote_ip_address, Ip6Address):
            engine_ip6: PmtuSearch[Ip6Address] = PmtuSearch(
                address=remote_ip_address,
                interface_mtu=interface_mtu,
            )
            self._engine = engine_ip6
        else:
            engine_ip4: PmtuSearch[Ip4Address] = PmtuSearch(
                address=remote_ip_address,
                interface_mtu=interface_mtu,
            )
            self._engine = engine_ip4
        self._in_flight_size = None

    @property
    def engine(self) -> PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]:
        """
        Get the underlying PLPMTUD engine.
        """

        return self._engine

    @property
    def current_mtu(self) -> int:
        """
        Get the engine's current PLPMTU.
        """

        return self._engine.current_mtu

    @property
    def state(self) -> PmtuState:
        """
        Get the engine's current state.
        """

        return self._engine.state

    @property
    def in_flight_size(self) -> int | None:
        """
        Get the size of the in-flight probe, or None when
        no probe is outstanding.
        """

        return self._in_flight_size

    def probe_pmtu(self, *, size: int | None = None, now: float) -> int | None:
        """
        Reserve a probe slot. Returns the size to probe, or
        None when a probe is already in flight (the
        single-outstanding invariant) or the engine has no
        probe to recommend right now.

        If 'size' is provided, that exact size is used (the
        application chose its own probe size). If 'size' is
        None, the engine's 'next_probe_size(now)' is used.

        The caller is responsible for actually emitting a
        UDP datagram of the returned size on the wire; the
        adapter only tracks state.
        """

        if self._in_flight_size is not None:
            return None
        if size is None:
            size = self._engine.next_probe_size(now=now)
            if size is None:
                return None
        self._in_flight_size = size
        return size

    def ack_probe(self, *, now: float) -> None:
        """
        Notify the adapter that the application's app-layer
        ACK confirmed the in-flight probe. Dispatches
        'engine.on_probe_ack(size)' and clears the in-flight
        slot. No-op when no probe is in flight.
        """

        if self._in_flight_size is None:
            return
        self._engine.on_probe_ack(self._in_flight_size, now=now)
        self._in_flight_size = None

    def timeout_probe(self, *, now: float) -> None:
        """
        Notify the adapter that the application's app-layer
        timer expired without an ACK. Dispatches
        'engine.on_probe_loss(now)' and clears the in-flight
        slot. No-op when no probe is in flight.
        """

        if self._in_flight_size is None:
            return
        self._engine.on_probe_loss(now=now)
        self._in_flight_size = None

    def on_classical_pmtu(self, mtu: int, *, now: float) -> None:
        """
        Pass-through to the engine's classical-PMTUD handler.
        Called by UdpSocket.notify_pmtu so the engine absorbs
        RFC 1191 / RFC 8201 PTB signals.
        """

        self._engine.on_classical_pmtu(mtu, now=now)
