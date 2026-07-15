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
This module contains the daemon capture writer ('DaemonCapture'): a
boot-time background drain that reads every frame off an in-daemon
AF_PACKET socket, decodes it with the shared 'pytcp tcpdump' engine, and
writes a rebased, direction-tagged tcpdump-style line to a text sink.

Bound before 'stack.start()', the writer sees the stack's own
autoconfiguration from the first frame — IPv6 DAD / RS / RA, the RFC 5227
ARP Probe / Announcement, DHCPv4 DISCOVER..ACK — which a client-attached
'pytcp tcpdump' (which must connect over IPC to an already-running
daemon) structurally cannot. The drain is one-directional and mirrors the
'PacketBridge' RX pump: a poll-timeout read loop guarded by a stop event,
joined with a timeout on teardown.

pytcp/daemon/daemon__capture.py

ver 3.0.8
"""

import threading
import time
from collections.abc import Callable
from typing import Protocol, TextIO

from pytcp.cli.cli__tcpdump import format_capture_line
from pytcp.runtime.socket.sockaddr_ll import SockAddrLl

DAEMON__CAPTURE__POLL_TIMEOUT__SEC: float = 0.2
DAEMON__CAPTURE__JOIN_TIMEOUT__SEC: float = 2.0


class CaptureSocket(Protocol):
    """
    The minimal capture-socket surface the drain consumes: a 'recvfrom'
    that returns a '(frame, sockaddr_ll)' pair, blocking up to 'timeout'
    seconds and raising 'TimeoutError' when it elapses.
    """

    def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]: ...


class DaemonCapture:
    """
    A background writer that drains an in-daemon AF_PACKET socket and
    renders each captured frame as a decoded, direction-tagged line.
    """

    def __init__(
        self,
        *,
        capture_socket: CaptureSocket,
        sink: TextIO,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """
        Bind the writer to a capture socket and a text sink (left
        unstarted until 'start'). 'clock' supplies the monotonic reading
        rebased so the first captured frame reads 0.0 s.
        """

        self._capture_socket = capture_socket
        self._sink = sink
        self._clock = clock
        self._epoch: float | None = None
        self._event__stop = threading.Event()
        self._thread__capture: threading.Thread | None = None

    def start(self) -> None:
        """
        Spawn the drain thread.
        """

        self._thread__capture = threading.Thread(target=self._pump, name="Daemon-Capture", daemon=True)
        self._thread__capture.start()

    def _pump(self) -> None:
        """
        Drain captured frames until stopped, writing one decoded,
        direction-tagged, rebased-timestamp line per frame to the sink.
        """

        while not self._event__stop.is_set():
            try:
                frame, sockaddr_ll = self._capture_socket.recvfrom(None, DAEMON__CAPTURE__POLL_TIMEOUT__SEC)
            except BlockingIOError, TimeoutError:
                continue
            except OSError:
                break

            now = self._clock()
            if self._epoch is None:
                self._epoch = now
            line = format_capture_line(pkttype=sockaddr_ll.pkttype, frame=frame, timestamp=now - self._epoch)

            try:
                self._sink.write(line + "\n")
                self._sink.flush()
            except OSError, ValueError:
                # Sink closed underneath us (ValueError on a closed
                # StringIO / file) — stop draining rather than spin.
                break

    def is_alive(self) -> bool:
        """
        Report whether the drain thread is still running.
        """

        return self._thread__capture is not None and self._thread__capture.is_alive()

    def stop(self) -> None:
        """
        Signal the drain thread to stop and join it (idempotent). The
        poll-timeout read means the loop rechecks the stop event within
        'DAEMON__CAPTURE__POLL_TIMEOUT__SEC', so the join returns promptly.
        """

        self._event__stop.set()
        if self._thread__capture is not None:
            self._thread__capture.join(timeout=DAEMON__CAPTURE__JOIN_TIMEOUT__SEC)
            self._thread__capture = None
