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
This module contains class supporting stack TX Ring operations.

pytcp/runtime/tx_ring.py

ver 3.0.8
"""

import collections
import os
import select
import threading
from collections.abc import Callable
from typing import override

from net_addr import Buffer
from net_proto import (
    Ethernet8023Assembler,
    EthernetAssembler,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
)
from net_proto.protocols.ethernet.ethernet__header import ETHERNET__HEADER__LEN
from net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
)
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem

# A fully-built outbound frame ready for 'os.writev'. The TX
# deque carries these alongside '_TxRequest' marshaled-call
# descriptors (see the ring-handoff design): the worker writes
# a 'TxFrame' directly and runs a '_TxRequest' callable.
type TxFrame = EthernetAssembler | Ethernet8023Assembler | Ip6Assembler | Ip4Assembler | Ip4FragAssembler

# Per-protocol-class dispatch table mapping the TX-side Assembler
# concrete class to its (Ethernet-type prefix, MTU overhead) tuple.
# Used by '_send_one' to look up the wire-framing without an
# 'isinstance' chain — single 'type()' dict lookup on the production
# fast path, with an 'isinstance' fallback for test fixtures using
# 'unittest.mock.MagicMock(spec=...)' (where 'type(mock)' is
# 'MagicMock', not the spec class).
_TX_PROTO_DISPATCH: dict[type, tuple[bytes, int]] = {
    EthernetAssembler: (b"", ETHERNET__HEADER__LEN),
    Ethernet8023Assembler: (b"", ETHERNET_802_3__HEADER__LEN),
    Ip6Assembler: (b"\x00\x00\x86\xdd", 0),
    Ip4Assembler: (b"\x00\x00\x08\x00", 0),
    Ip4FragAssembler: (b"\x00\x00\x08\x00", 0),
}


class _TxRequest:
    """
    A marshaled '_phtx_*' pipeline call handed off to the TX
    worker thread. The producing thread (an app 'send_*_packet'
    caller, an RX-thread reply, a timer-thread retransmit) builds
    the descriptor and blocks on its event; the single TX worker
    thread runs the callable so every per-interface TX-state write
    happens on one thread (single-writer). The callable's
    'TxStatus' (or any exception) is handed back to the waiter.
    """

    __slots__ = ("_run", "_event", "_result", "_exc", "_on_complete")

    def __init__(
        self,
        run: Callable[[], TxStatus],
        /,
        *,
        blocking: bool = True,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """
        Initialize the marshaled request from its callable. A
        'blocking' request carries a 'threading.Event' the producer
        waits on; a fire-and-forget request ('blocking=False', the
        Phase 4b async-send path) has no event — the worker runs it
        and discards the result.

        'on_complete' (if given) is invoked exactly once after the
        callable finishes — success, raise, or inline fallback —
        from the request's 'execute()' 'finally'. The UDP SO_SNDBUF
        accounting uses it to decrement a socket's outstanding-bytes
        counter when its datagram leaves the send queue.
        """

        self._run = run
        self._event = threading.Event() if blocking else None
        self._result: TxStatus | None = None
        self._exc: BaseException | None = None
        self._on_complete = on_complete

    def execute(self) -> None:
        """
        Run the callable on the worker thread, capturing its result
        or exception, and signal the waiting producer. For a blocking
        request the event is set in a 'finally' so a raising callable
        never strands the waiter; for a fire-and-forget request a
        raise is logged (no caller to receive it) and swallowed so it
        cannot kill the TX loop. The 'on_complete' hook fires in the
        same 'finally' so send-buffer accounting is released on every
        exit path.
        """

        try:
            self._result = self._run()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            self._exc = exc
            if self._event is None:
                __debug__ and log(
                    "tx-ring",
                    f"<CRIT>Fire-and-forget TX call raised, dropping: {exc!r}</>",
                )
        finally:
            if self._event is not None:
                self._event.set()
            if self._on_complete is not None:
                self._on_complete()

    def wait(self) -> None:
        """
        Block the producer until the worker has executed the call.
        Only valid on a blocking request (one carrying an event).
        """

        assert self._event is not None, "wait() called on a fire-and-forget TX request."
        self._event.wait()

    def result(self) -> TxStatus:
        """
        Return the worker-side 'TxStatus', re-raising any exception
        the callable raised on the worker thread.
        """

        if self._exc is not None:
            raise self._exc
        assert self._result is not None
        return self._result


class TxRing(Subsystem):
    """
    Support for sending packets to the network.
    """

    _subsystem_name = "TX Ring"

    _fd: int
    _mtu: int
    _queue_max_size: int

    _tx_deque: collections.deque[TxFrame | _TxRequest | Buffer]
    _tx_event_fd: int
    _queue_full_drop_count: int
    _os_error_drop_count: int
    _packet_stats: PacketStatsTx | None
    _link_stats: LinkStatsCounters | None

    @override
    def __init__(
        self,
        *,
        fd: int,
        mtu: int,
        queue_max_size: int = 1000,
        packet_stats: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Initialize access to TX file descriptor and the outbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        super().__init__(info=f"fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}")

        # 'collections.deque' append/popleft are atomic under the
        # GIL, no kernel mutex calls per op. The producer
        # (packet-handler thread) and consumer (TX worker thread)
        # synchronise via 'os.eventfd': producer signals on append,
        # consumer waits via 'select.select' on the eventfd. Net per
        # packet: ~5-8 µs saved over the prior 'queue.Queue' that
        # used 'Lock + Condition' on every put/get.
        self._tx_deque = collections.deque()
        self._tx_event_fd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        self._queue_full_drop_count = 0
        self._os_error_drop_count = 0
        # Optional shared 'PacketStatsTx' object — see RxRing for
        # the same pattern; ring drop counters live as fields on
        # the shared stats when wired so unified-stats consumers
        # see them alongside per-protocol drops.
        self._packet_stats = packet_stats
        # Optional shared 'LinkStatsCounters' object — when set,
        # 'tx_bytes' is bumped here per successful 'enqueue'. The
        # PacketHandler owns the canonical instance; sharing it
        # gives the Link API a single source of truth for
        # 'stats.tx_bytes'.
        self._link_stats = link_stats

    def set_mtu(self, mtu: int, /) -> None:
        """
        Set the writev-size MTU bound for this TX ring — the Link API's
        'set_mtu' mutator resizes the bound interface's own ring through
        this. Validation (RFC 791 floor, uint16 ceiling) is the Link
        API's responsibility.
        """

        self._mtu = mtu

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of outbound packets dropped because
        the TX ring was at capacity at 'enqueue' time. A non-zero
        rate signals the producer (the packet handler) is generating
        packets faster than 'os.writev' can drain them. Sources from
        the shared 'PacketStatsTx' field when wired, falls back to
        the internal counter otherwise.
        """

        if self._packet_stats is not None:
            return self._packet_stats.tx_ring__queue_full__drop
        return self._queue_full_drop_count

    @property
    def os_error_drop_count(self) -> int:
        """
        Get the cumulative count of outbound packets dropped because
        'os.writev' raised 'OSError' (typically ENOBUFS, ENETDOWN,
        EIO on link failure). A non-zero rate signals interface
        trouble the application would otherwise have no visibility
        into.
        """

        if self._packet_stats is not None:
            return self._packet_stats.tx_ring__os_error__drop
        return self._os_error_drop_count

    @property
    def qsize(self) -> int:
        """
        Get the current depth of the TX deque (analogous to
        'queue.Queue.qsize'). Useful for live observability —
        steady-state qsize > 0 indicates the consumer is falling
        behind the producer.
        """

        return len(self._tx_deque)

    @override
    def _stop(self) -> None:
        """
        Close the eventfd backing the producer/consumer wakeup
        channel so 'stack.stop()' returns the descriptor to the
        kernel.
        """

        try:
            os.close(self._tx_event_fd)
        except OSError:
            pass

    @override
    def _subsystem_loop(self) -> None:
        """
        Wait for a producer signal on the TX eventfd, then drain
        every queued packet in one inner pass. The eventfd ack
        ('os.eventfd_read') is called once per wake-up regardless
        of how many packets the inner drain processes; if the
        drain breaks early on 'os.writev' OSError, the eventfd is
        re-armed so the next outer-loop iteration wakes immediately
        rather than blocking on a stale empty signal.
        """

        ready, _, _ = select.select([self._tx_event_fd], [], [], SUBSYSTEM_SLEEP_TIME__SEC)
        if not ready:
            return

        # Drain the eventfd counter — it accumulates one signal per
        # producer enqueue; we only need 'queue is non-empty', so
        # one read clears the kernel-side ready bit.
        try:
            os.eventfd_read(self._tx_event_fd)
        except OSError:
            pass

        while self._tx_deque:
            item = self._tx_deque.popleft()
            if isinstance(item, _TxRequest):
                # A marshaled '_phtx_*' call: run it here on the
                # worker thread (single-writer). The callable itself
                # enqueues the built frame back onto this deque, which
                # the inner drain then writes in the same pass.
                item.execute()
                continue
            if isinstance(item, (bytes, bytearray, memoryview)):
                # A verbatim pre-built frame from an AF_PACKET socket:
                # write it as-is, no assembler / ethertype framing.
                if not self._send_raw_frame(item):
                    if self._tx_deque:
                        try:
                            os.eventfd_write(self._tx_event_fd, 1)
                        except OSError:
                            pass
                    return
                continue
            if not self._send_one(item):
                # 'os.writev' errored — stop draining. Re-arm the
                # eventfd so the next outer pass picks up where we
                # left off; otherwise pending packets would wait
                # for a fresh producer signal.
                if self._tx_deque:
                    try:
                        os.eventfd_write(self._tx_event_fd, 1)
                    except OSError:
                        pass
                return

    def dispatch(self, run: Callable[[], TxStatus], /) -> TxStatus:
        """
        Run a '_phtx_*' pipeline call on the TX worker thread and
        return its 'TxStatus' (ring-handoff single-writer). Marshals
        the callable to the worker and blocks for the result, EXCEPT:

        - No live worker (not started, or stopped) — run inline; the
          unit-test path and the pre-'start()' boot path both hit
          this, and there is no worker to hand off to.
        - Called from the worker thread itself (a re-entrant
          solicitation emitted mid-pipeline) — run inline; enqueuing
          onto our own deque and waiting would deadlock.
        """

        worker = self._thread
        if worker is None or not worker.is_alive() or threading.current_thread() is worker:
            return run()

        request = _TxRequest(run)
        self._tx_deque.append(request)
        try:
            os.eventfd_write(self._tx_event_fd, 1)
        except OSError:
            # Eventfd closed (stop in progress); the request will not
            # be serviced. Surfacing a drop is better than hanging.
            return run()
        request.wait()
        return request.result()

    def dispatch_async(
        self,
        run: Callable[[], TxStatus],
        /,
        *,
        on_complete: Callable[[], None] | None = None,
    ) -> None:
        """
        Fire-and-forget variant of 'dispatch' (Phase 4b async send):
        hand the '_phtx_*' call to the TX worker and return
        immediately without waiting for the result. Used by the
        UDP / raw socket send paths so the application thread is not
        blocked on the worker; transmission failures are not surfaced
        to the caller (the datagram is "accepted into the stack",
        matching Linux's queued-on-send semantics). Same inline
        fallback as 'dispatch' when there is no live worker or the
        caller already IS the worker.

        'on_complete' fires once after the marshaled call finishes on
        whichever thread runs it (worker or inline fallback) — the
        SO_SNDBUF release hook.
        """

        request = _TxRequest(run, blocking=False, on_complete=on_complete)
        worker = self._thread
        if worker is None or not worker.is_alive() or threading.current_thread() is worker:
            request.execute()
            return

        self._tx_deque.append(request)
        try:
            os.eventfd_write(self._tx_event_fd, 1)
        except OSError:
            # Eventfd closed (stop in progress); run inline so the
            # call is not silently lost on the dead deque.
            request.execute()

    def _send_one(
        self,
        packet_tx: TxFrame,
    ) -> bool:
        """
        Build the wire-buffer list for a single packet and call
        'os.writev'. Returns True on a successful send (including
        the silent oversized-frame and unknown-type drops which
        are non-fatal log-only branches), and False on 'os.writev'
        OSError so the inner drain can break early.
        """

        # Production fast path: 'type(x)' dict lookup is O(1). For
        # 'MagicMock(spec=X)' fixtures whose 'type(mock)' is
        # 'MagicMock', fall back to an 'isinstance' walk so test
        # mocks resolve via '__class__' / '__instancecheck__'.
        proto_info = _TX_PROTO_DISPATCH.get(type(packet_tx))
        if proto_info is None:
            for cls, info in _TX_PROTO_DISPATCH.items():
                if isinstance(packet_tx, cls):
                    proto_info = info
                    break
        if proto_info is None:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - <CRIT>Unknown packet type: " f"{type(packet_tx)!r}</>",
            )
            return True

        prefix, mtu_extra = proto_info
        buffers: list[Buffer] = [prefix] if prefix else []
        mtu = self._mtu + mtu_extra

        if (packet_tx_len := len(packet_tx)) > mtu:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - Unable to send frame, frame" f"len ({packet_tx_len}) > mtu ({mtu})",
            )
            return True

        packet_tx.assemble(buffers)

        try:
            os.writev(self._fd, buffers)
        except OSError as error:
            if self._packet_stats is not None:
                self._packet_stats.tx_ring__os_error__drop += 1
            else:
                self._os_error_drop_count += 1
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - <CRIT>Unable to send frame, " f"OSError: {error}</>",
            )
            return False

        __debug__ and log(
            "tx-ring",
            f"<B><lr>[TX]</> {packet_tx.tracker}<y>"
            f"{packet_tx.tracker.latency}</> - sent frame, "
            f"{len(packet_tx)} bytes",
        )
        return True

    def _send_raw_frame(self, frame: Buffer, /) -> bool:
        """
        Write a verbatim pre-built link-layer frame (from an AF_PACKET
        socket) to the TX fd via 'os.writev', adding no framing prefix.
        Returns True on success (the contract '_subsystem_loop' expects)
        and False on 'os.writev' OSError so the drain can break early.
        """

        try:
            os.writev(self._fd, [frame])
        except OSError as error:
            if self._packet_stats is not None:
                self._packet_stats.tx_ring__os_error__drop += 1
            else:
                self._os_error_drop_count += 1
            __debug__ and log(
                "tx-ring",
                f"<CRIT>Unable to send raw frame, OSError: {error}</>",
            )
            return False

        __debug__ and log("tx-ring", f"<B><lr>[TX]</> - sent raw frame, {len(frame)} bytes")
        return True

    def enqueue_raw_frame(self, frame: Buffer, /) -> None:
        """
        Enqueue a verbatim pre-built link-layer frame for transmission —
        the AF_PACKET (SOCK_RAW) egress primitive. Unlike 'enqueue',
        which takes an Assembler the worker serializes, this puts the
        finished frame bytes straight on the ring; the worker writes
        them as-is, skipping the IP / assembler layers. Same full-queue
        drop and 'tx_bytes' accounting as 'enqueue'.
        """

        if len(self._tx_deque) >= self._queue_max_size:
            if self._packet_stats is not None:
                self._packet_stats.tx_ring__queue_full__drop += 1
            else:
                self._queue_full_drop_count += 1
            __debug__ and log("tx-ring", "TX Queue is full, dropping raw frame")
            return

        self._tx_deque.append(frame)
        try:
            os.eventfd_write(self._tx_event_fd, 1)
        except OSError:
            pass

        if self._link_stats is not None:
            self._link_stats.tx_bytes += len(frame)

        __debug__ and log("tx-ring", f"TX Queue len: {len(self._tx_deque)}")

    def enqueue(
        self,
        packet_tx: TxFrame,
    ) -> None:
        """
        Enqueue a fully-built outbound frame into the TX Ring. The
        'len() >= cap' check tolerates concurrent producers (the
        worker re-enqueues built frames while app / RX / timer
        threads also enqueue) — 'deque.append' is atomic, and an
        occasional off-by-one against the cap only over/under-fills
        by one slot. On a full deque the frame is dropped; the drop
        counter increments so monitors can spot saturation.
        """

        if len(self._tx_deque) >= self._queue_max_size:
            if self._packet_stats is not None:
                self._packet_stats.tx_ring__queue_full__drop += 1
            else:
                self._queue_full_drop_count += 1
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - TX Queue is full, dropping packet",
            )
            return

        self._tx_deque.append(packet_tx)
        try:
            os.eventfd_write(self._tx_event_fd, 1)
        except OSError:
            # Eventfd closed (stop in progress) — packet sits on
            # the deque, will not be drained. Acceptable during
            # shutdown.
            pass

        # Link API tx_bytes: count wire-level frame bytes enqueued
        # for transmission regardless of whether the kernel write
        # ultimately succeeds. Matches Linux 'ifOutOctets' / 'ip
        # -s link show' TX semantics (frames counted at the qdisc
        # boundary, not at the device-write boundary).
        if self._link_stats is not None:
            self._link_stats.tx_bytes += len(packet_tx)

        __debug__ and log(
            "tx-ring",
            f"{packet_tx.tracker} - TX Queue len: {len(self._tx_deque)}",
        )
