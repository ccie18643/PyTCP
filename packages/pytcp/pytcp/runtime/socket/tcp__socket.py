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
This module contains the BSD-like TCP socket interface for the stack.

pytcp/runtime/socket/tcp__socket.py

ver 3.0.9
"""

import errno
import os
import threading
import time
from collections import deque
from collections.abc import Iterable
from threading import Semaphore
from typing import cast, override

from net_addr import (
    Buffer,
    Ip4Address,
    Ip4AddressFormatError,
    Ip6Address,
    Ip6AddressFormatError,
)
from net_proto.lib.enums import IpProto
from net_proto.lib.proto_enum import ProtoEnum
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.session import TcpSession
from pytcp.protocols.tcp.tcp__enums import CcMode, FsmState
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.runtime.socket import (
    IP_RECVERR,
    IPPROTO_IP,
    IPPROTO_IPV6,
    IPPROTO_TCP,
    IPV6_RECVERR,
    MSG_ERRQUEUE,
    SO_KEEPALIVE,
    SO_LINGER,
    SO_RCVBUF,
    SOL_SOCKET,
    TCP_CONGESTION,
    TCP_FASTOPEN,
    TCP_INFO,
    TCP_KEEPCNT,
    TCP_KEEPIDLE,
    TCP_KEEPINTVL,
    TCP_MAXSEG,
    TCP_NODELAY,
    TCP_USER_TIMEOUT,
    AddressFamily,
    SocketType,
    gaierror,
    socket,
    tcp__info,
)
from pytcp.runtime.socket.error_queue import (
    ERROR_QUEUE__MAX_LEN,
    ErrorQueueEntry,
    SoEeOrigin,
    build_icmp_error_entry,
    pack_sock_extended_err,
)
from pytcp.runtime.socket.socket__bind_helpers import (
    is_address_in_use,
    pick_local_ip_address,
    pick_local_port,
    pick_local_port_for,
)
from pytcp.runtime.socket.tcp__metadata import TcpMetadata
from pytcp.runtime.socket.tcp__status import TcpStatus

# Linux 'include/net/tcp.h' TCP_MIN_MSS = 88. The acceptance floor
# for 'setsockopt(IPPROTO_TCP, TCP_MAXSEG, ...)' — Linux rejects
# any value below this. PyTCP mirrors the Linux floor exactly so
# applications that probe the boundary see the same behaviour.
_LINUX__TCP_MIN_MSS: int = 88


# Default cap on the listening socket's '_tcp_accept' queue when
# the application calls 'listen()' without an explicit 'backlog'.
# POSIX requires the implementation to accept at least 5; BSD and
# Linux have historically defaulted to higher values (Linux's
# tcp_max_syn_backlog is 4096 on modern kernels). PyTCP picks a
# conservative middle ground that still accommodates the existing
# 5-peer multi-child regression test, leaves headroom for typical
# small-stack workloads, and keeps the per-listener memory ceiling
# bounded for network-exposed deployments.
TCP__DEFAULT_BACKLOG: int = 16


class TcpSocket(socket):
    """
    The IPv6/IPv4 TCP socket.
    """

    _socket_type = SocketType.STREAM
    _ip_proto = IpProto.TCP

    def __init__(  # pyright: ignore[reportInconsistentConstructor]
        self,
        family: AddressFamily,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | int | None = IpProto.TCP,
        *,
        tcp_session: TcpSession | None = None,
    ) -> None:
        """
        Initialize the IPv6/IPv4 TCP socket.
        """

        assert type is SocketType.STREAM
        # Accept the BSD 'IPPROTO_IP' (= 0) default-protocol sentinel
        # as equivalent to 'IpProto.TCP' for STREAM sockets.
        if protocol is None or (protocol.__class__ is int and protocol == 0):
            protocol = IpProto.TCP
        assert protocol is IpProto.TCP

        super().__init__()

        self._address_family = family
        self._event__tcp_session_established: Semaphore = threading.Semaphore(0)
        self._tcp_accept: list[socket] = []
        # Per-socket ICMP error queue (RFC 1122 §4.2.3.9 surface
        # via Linux IP_RECVERR / IPV6_RECVERR). FIFO-drop on
        # overflow at 'ERROR_QUEUE__MAX_LEN'. The UDP-side surface
        # ('UdpSocket._error_queue') uses the same shape; both
        # consume 'build_icmp_error_entry' from
        # 'pytcp.runtime.socket.error_queue'.
        self._error_queue: deque[ErrorQueueEntry] = deque(maxlen=ERROR_QUEUE__MAX_LEN)
        self._error_queue_ready = threading.Semaphore(0)
        # Cap on '_tcp_accept' length, set by 'listen(backlog=...)'.
        # Initialised to the default so listening sockets created
        # outside the 'listen()' call path (e.g. the integration-
        # test helpers, or future paths that bypass the BSD API)
        # still have a finite cap. Re-set by 'listen()' when the
        # caller passes an explicit value.
        self._backlog: int = TCP__DEFAULT_BACKLOG
        self._tcp_session: TcpSession | None = tcp_session
        self._parent_socket: TcpSocket | None = None

        # RFC 1122 §4.2.3.6 SO_KEEPALIVE flag, settable via
        # 'setsockopt(SOL_SOCKET, SO_KEEPALIVE, ...)'. Defaults
        # False per the RFC's MUST. The socket holds the flag
        # pre-handshake; 'connect()' / 'listen()' propagate it
        # into the freshly-constructed 'TcpSession' before the
        # FSM starts firing.
        self._so_keepalive: bool = False

        # Linux-style per-connection keep-alive overrides
        # (TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT). 'None'
        # means "no override - use the system default constant
        # at runtime". Units are milliseconds for the two timer
        # values, count for max-probes; this matches the units
        # of the corresponding 'tcp__constants.KEEPALIVE_*'
        # values internally. (Linux's API is in seconds; PyTCP
        # uses ms for ergonomics with the small test windows.)
        self._tcp_keepidle: int | None = None
        self._tcp_keepintvl: int | None = None
        self._tcp_keepcnt: int | None = None

        # RFC 7413 §3.1 server-side TFO accept-queue depth.
        # 0 means "TFO disabled"; the application opts the
        # listening socket in via 'setsockopt(IPPROTO_TCP,
        # TCP_FASTOPEN, qlen)' with a positive depth before
        # 'listen()'. Today this is observable via
        # 'getsockopt'; the protocol-level gating (server only
        # issues cookies and accepts SYN-data when this is
        # > 0) is a subsequent phase.
        self._tcp_fastopen_qlen: int = 0

        # Linux 'TCP_USER_TIMEOUT' per-connection abort budget
        # (RFC 9293 §3.10.7.4 R2 abort, RFC 1122 §4.2.3.5
        # alternative budget). Integer milliseconds; 0 means
        # "no override — use the system-default
        # 'tcp.retransmit.max_count'-driven budget". The value
        # bounds the total wall-time the stack will retransmit
        # data without an ACK before tearing down the
        # connection. 'connect()' / 'listen()' propagate this
        # onto the freshly-constructed 'TcpSession' so the
        # R2-abort site can consult it. M6 of
        # 'socket_linux_parity_audit.md'.
        self._tcp_user_timeout: int = 0

        # Linux 'TCP_MAXSEG' per-connection MSS-option clamp
        # (RFC 9293 §3.7.1 / RFC 6691). Integer bytes; 0 means
        # "no clamp — emit our usual rcv_mss in the SYN's MSS
        # option". When set, the SYN-options assembly clamps
        # the emitted MSS to no more than this value. Linux
        # requires the value be ≥ TCP__MIN_MSS (88); a smaller
        # value is rejected by setsockopt.
        self._tcp_maxseg: int = 0

        # RFC 9438 congestion-control algorithm selector,
        # settable via 'setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        # ...)' with values: CcMode.RENO.value (=1) or
        # CcMode.CUBIC.value (=2). Default is CcMode.CUBIC,
        # mirroring Linux's default since kernel 2.6.18.
        # Propagated to the freshly-constructed 'TcpSession'
        # by 'connect()' / 'listen()' before the FSM starts.
        self._cc_mode: CcMode = CcMode.CUBIC

        # RFC 1122 §4.2.3.4 Nagle disable, settable via
        # 'setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)'. Default is
        # False (Nagle enabled per RFC 1122 SHOULD). Latency-
        # sensitive applications opt out so partial segments
        # fire immediately instead of being deferred while a
        # previous partial is unacked. Propagated to the
        # session at 'connect()' / 'listen()' time.
        self._tcp_nodelay: bool = False

        # Create established socket based on established TCP session, called by
        # listening sockets only.
        if tcp_session:
            self._local_ip_address = tcp_session.local_ip_address
            self._remote_ip_address = tcp_session.remote_ip_address
            self._local_port = tcp_session.local_port
            self._remote_port = tcp_session.remote_port
            self._parent_socket = tcp_session.socket
            stack.sockets.register(self)

        # Fresh socket initialization.
        else:
            match self._address_family:
                case AddressFamily.INET6:
                    self._local_ip_address = Ip6Address()
                    self._remote_ip_address = Ip6Address()
                case AddressFamily.INET4:
                    self._local_ip_address = Ip4Address()
                    self._remote_ip_address = Ip4Address()

            self._local_port = 0
            self._remote_port = 0

        __debug__ and log("socket", f"<g>[{self}]</> - Create socket")

    @property
    def state(self) -> FsmState:
        """
        Return FSM state of associated TCP session.
        """

        if self.tcp_session is not None:
            return self.tcp_session.state

        return FsmState.CLOSED

    @property
    def tcp_session(self) -> TcpSession | None:
        """
        Get the '_tcp_session' attribute.
        """

        return self._tcp_session

    @property
    def parent_socket(self) -> TcpSocket | None:
        """
        Get the '_parent_socket' attribute.
        """

        return self._parent_socket

    @override
    def _default_sndbuf(self) -> int:
        """
        Get the unset-SO_SNDBUF send-buffer default for TCP: the
        operator-tunable 'tcp.wmem.default' (Linux 'tcp_wmem[1]'),
        distinct from the datagram 'net.core.wmem_default'. Read via
        qualified module access so a runtime sysctl override is picked
        up live.
        """

        return tcp__constants.TCP__WMEM__DEFAULT

    @override
    def _default_rcvbuf(self) -> int:
        """
        Get the unset-SO_RCVBUF receive-buffer default for TCP: the
        operator-tunable 'tcp.rmem.default' (Linux 'tcp_rmem[1]'),
        distinct from the datagram 'net.core.rmem_default'. Seeds the
        advertised-window cap ('rcv_wnd_max') at session construction.
        """

        return tcp__constants.TCP__RMEM__DEFAULT

    def status(self) -> TcpStatus:
        """
        Return a read-only snapshot of the connection's
        user-visible state per RFC 9293 §3.9.1 STATUS.

        On a fresh socket with no associated TCP session, the
        returned snapshot has 'state = FsmState.CLOSED' and
        zero-valued / unspecified addresses.
        """

        session = self._tcp_session
        if session is None:
            return TcpStatus(
                state=FsmState.CLOSED,
                local_address=self._local_ip_address,
                local_port=self._local_port,
                remote_address=self._remote_ip_address,
                remote_port=self._remote_port,
                snd_una=0,
                snd_nxt=0,
                snd_wnd=0,
                rcv_nxt=0,
                rcv_wnd=0,
                snd_mss=0,
                rcv_mss=0,
                snd_wsc=0,
                rcv_wsc=0,
                tx_buffer_len=0,
                rx_buffer_len=0,
            )
        return TcpStatus(
            state=session.state,
            local_address=session.local_ip_address,
            local_port=session.local_port,
            remote_address=session.remote_ip_address,
            remote_port=session.remote_port,
            snd_una=session.snd_una,
            snd_nxt=session.snd_nxt,
            snd_wnd=session.snd_wnd,
            rcv_nxt=session.rcv_nxt,
            rcv_wnd=session.rcv_wnd,
            snd_mss=session.snd_mss,
            rcv_mss=session.rcv_mss,
            snd_wsc=session.snd_wsc,
            rcv_wsc=session.rcv_wsc,
            tx_buffer_len=session.tx_buffer_len,
            rx_buffer_len=session.rx_buffer_len,
        )

    @override
    def setsockopt(self, level: int | IpProto, optname: int, value: int | float | bytes, /) -> None:
        """
        Set a socket option per the BSD 'setsockopt' API.

        Currently supports the RFC 1122 §4.2.3.6 keep-alive
        option 'SO_KEEPALIVE' at the 'SOL_SOCKET' level. Boolean
        options collapse any non-zero 'value' to 1; setting 0
        disables. Unknown 'level' / 'optname' pairs raise OSError
        (mirrors POSIX 'ENOPROTOOPT' / 'EINVAL' shape, kept as
        plain OSError so callers can grep without importing
        errno enums). 'value' is 'int' for scalar options and
        'bytes' for IP_OPTIONS (RFC 1122 §4.1.3.2).

        Example:

            sock = socket(family=AddressFamily.INET4, type_=SocketType.SOCK_STREAM)
            sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
            sock.connect(("10.0.1.7", 80))
            # Connection now has RFC 1122 §4.2.3.6 keep-alive enabled.
        """

        # A float value is only valid for the SOL_SOCKET float-seconds
        # timeouts (SO_RCVTIMEO / SO_SNDTIMEO); route it there so the
        # int / bytes option paths below never receive a float.
        if isinstance(value, float):
            if level == SOL_SOCKET and self._sol_socket_setsockopt(optname, value):
                return
            raise OSError(
                errno.ENOPROTOOPT,
                f"setsockopt: unsupported (level, optname) pair for a float value: "
                f"level={level!r}, optname={optname!r}",
            )
        if isinstance(value, int) and level == SOL_SOCKET and optname == SO_KEEPALIVE:
            self._so_keepalive = bool(value)
            return
        if level == SOL_SOCKET and optname == SO_LINGER:
            # Drives the 3-way close-path branch in 'close()'
            # (graceful FIN / lingering wait / abortive RST).
            self._so_linger_set(value)
            return
        if isinstance(value, int) and level == SOL_SOCKET and optname == SO_RCVBUF:
            self._sol_socket_setsockopt(optname, value)
            # Propagate a mid-connection SO_RCVBUF change to the live
            # session grow-only: it may enlarge the advertised receive
            # window but never shrink it (RFC 9293 §3.8.6.2.1 — a
            # receiver SHOULD NOT retract the window's right edge).
            if self._tcp_session is not None:
                self._tcp_session.grow_rcv_wnd_max(self._effective_rcvbuf())
            return
        if isinstance(value, int) and level == SOL_SOCKET and self._sol_socket_setsockopt(optname, value):
            return
        # IPPROTO_IP / IPPROTO_IPV6 round-trip storage for TCP
        # sockets: the per-socket TTL / Hop-Limit / TOS / TClass
        # values are stored on the base; behavioral propagation to
        # the FSM segment-emit path is a follow-up commit.
        if level == IPPROTO_IP and self._ipproto_ip_setsockopt(optname, value):
            return
        if level == IPPROTO_IPV6 and self._ipproto_ipv6_setsockopt(optname, value):
            return
        if isinstance(value, int) and level == IPPROTO_TCP and optname == TCP_KEEPIDLE:
            self._tcp_keepidle = int(value)
            return
        if level == IPPROTO_TCP and optname == TCP_KEEPINTVL:
            self._tcp_keepintvl = int(value)
            return
        if level == IPPROTO_TCP and optname == TCP_KEEPCNT:
            self._tcp_keepcnt = int(value)
            return
        if level == IPPROTO_TCP and optname == TCP_FASTOPEN:
            self._tcp_fastopen_qlen = int(value)
            return
        if level == IPPROTO_TCP and optname == TCP_CONGESTION:
            mode = CcMode(int(value))
            self._cc_mode = mode
            # If the session already exists (post-connect()),
            # propagate immediately so an in-flight connection
            # picks up the mode change. Pre-connect calls only
            # touch the socket field; 'connect()' / 'listen()'
            # propagate at session-construction time.
            if self._tcp_session is not None:
                self._tcp_session.set_congestion_control(mode)
            return
        if level == IPPROTO_TCP and optname == TCP_NODELAY:
            flag = bool(value)
            self._tcp_nodelay = flag
            # Mid-connection toggle is honoured: the next
            # '_transmit_data' tick reads the new flag and
            # either gates Nagle on (False) or off (True).
            if self._tcp_session is not None:
                self._tcp_session.set_nodelay(flag)
            return
        if isinstance(value, int) and level == IPPROTO_TCP and optname == TCP_USER_TIMEOUT:
            # Linux: positive ms = budget; 0 = no override. A
            # negative value is rejected.
            if value < 0:
                raise OSError(
                    errno.EINVAL,
                    f"setsockopt(TCP_USER_TIMEOUT) rejects negative value {value!r}; pass 0 for no override.",
                )
            self._tcp_user_timeout = int(value)
            # Mid-connection mutation honoured so the next R2
            # check reads the new budget.
            if self._tcp_session is not None:
                self._tcp_session.set_user_timeout_ms(int(value))
            return
        if isinstance(value, int) and level == IPPROTO_TCP and optname == TCP_MAXSEG:
            # Linux: positive bytes = clamp; 0 = no clamp.
            # Value below TCP__MIN_MSS (88) is rejected — Linux
            # uses 88 as the floor too (include/net/tcp.h).
            if value < 0 or (value > 0 and value < _LINUX__TCP_MIN_MSS):
                raise OSError(
                    errno.EINVAL,
                    f"setsockopt(TCP_MAXSEG) rejects {value!r}; pass 0 (no clamp) or ≥ {_LINUX__TCP_MIN_MSS}.",
                )
            self._tcp_maxseg = int(value)
            # Mid-connection mutation has no effect on the
            # already-sent SYN; only the per-session storage
            # is refreshed so any future SYN (e.g. RFC 6191
            # ID-reuse re-handshake) consults it.
            if self._tcp_session is not None:
                self._tcp_session.set_maxseg_override(int(value))
            return
        raise OSError(
            errno.ENOPROTOOPT,
            f"setsockopt: unsupported (level, optname) pair: level={level!r}, optname={optname!r}",
        )

    @override
    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | float | bytes:
        """
        Get a socket option per the BSD 'getsockopt' API.

        Symmetric to 'setsockopt': only the (level, optname)
        pairs accepted by 'setsockopt' are accepted here.
        Returns the stored value as 'int' (boolean options
        return 0 or 1) or 'bytes' (IP_OPTIONS).
        """

        if level == SOL_SOCKET and optname == SO_KEEPALIVE:
            return int(self._so_keepalive)
        if level == SOL_SOCKET and (sol_value := self._sol_socket_getsockopt(optname)) is not None:
            return sol_value
        if level == IPPROTO_IP and (ip_value := self._ipproto_ip_getsockopt(optname)) is not None:
            return ip_value
        if level == IPPROTO_IPV6 and (ip6_value := self._ipproto_ipv6_getsockopt(optname)) is not None:
            return ip6_value
        if level == IPPROTO_TCP and optname == TCP_KEEPIDLE:
            # 0 means "no override set"; the session falls back
            # to 'tcp__constants.TCP__KEEPALIVE__IDLE_TIME_MS' at runtime.
            return self._tcp_keepidle if self._tcp_keepidle is not None else 0
        if level == IPPROTO_TCP and optname == TCP_KEEPINTVL:
            return self._tcp_keepintvl if self._tcp_keepintvl is not None else 0
        if level == IPPROTO_TCP and optname == TCP_KEEPCNT:
            return self._tcp_keepcnt if self._tcp_keepcnt is not None else 0
        if level == IPPROTO_TCP and optname == TCP_FASTOPEN:
            return self._tcp_fastopen_qlen
        if level == IPPROTO_TCP and optname == TCP_CONGESTION:
            return int(self._cc_mode.value)
        if level == IPPROTO_TCP and optname == TCP_NODELAY:
            return int(self._tcp_nodelay)
        if level == IPPROTO_TCP and optname == TCP_USER_TIMEOUT:
            return self._tcp_user_timeout
        if level == IPPROTO_TCP and optname == TCP_MAXSEG:
            # Linux's TCP_MAXSEG getsockopt returns the current
            # effective MSS — the override when set, else the
            # session's live 'snd_mss'. Pre-connect (no session)
            # falls through to the stored override (or 0).
            if self._tcp_session is not None:
                return self._tcp_session.snd_mss
            return self._tcp_maxseg
        if level == IPPROTO_TCP and optname == TCP_INFO:
            # Linux exposes ~50 fields of per-connection state via
            # 'getsockopt(IPPROTO_TCP, TCP_INFO)' — the wire-format
            # diagnostic tools ('ss -i') key off. PyTCP packs the
            # snapshot from the underlying 'TcpSession'; on a
            # never-connected socket the packer returns the
            # canonical 'all zeros + state=TCP_CLOSE' struct.
            return tcp__info.pack_tcp_info(self._tcp_session)
        raise OSError(
            errno.ENOPROTOOPT,
            f"getsockopt: unsupported (level, optname) pair: level={level!r}, optname={optname!r}",
        )

    def _get_ip_addresses(
        self,
        *,
        remote_address: tuple[str, int],
    ) -> tuple[Ip6Address, Ip6Address] | tuple[Ip4Address, Ip4Address]:
        """
        Validate the remote address and pick appropriate local IP
        address as needed.
        """

        try:
            remote_ip_address: Ip6Address | Ip4Address = (
                Ip6Address(remote_address[0])
                if self._address_family is AddressFamily.INET6
                else Ip4Address(remote_address[0])
            )
        except (Ip6AddressFormatError, Ip4AddressFormatError) as error:
            raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]") from error

        if remote_ip_address.is_unspecified:
            raise ConnectionRefusedError(
                errno.ECONNREFUSED,
                "Connection refused - [Unspecified remote IP address]",
            )

        local_ip_address = self._local_ip_address

        if local_ip_address.is_unspecified:
            local_ip_address = pick_local_ip_address(remote_ip_address=remote_ip_address)

            if local_ip_address.is_unspecified:
                raise gaierror("[Errno -2] Name or service not known - [Malformed remote IP address]")

        return local_ip_address, remote_ip_address  # type: ignore[return-value]

    ###############################
    ##  BSD socket API methods.  ##
    ###############################

    @override
    def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the socket to local address.
        """

        # The 'bind' call will bind socket to specific / unspecified local IP
        # address and specific local port in case provided port equals zero
        # port value will be picked automatically.

        # Check if "bound" already.
        if self._local_port in range(1, 65536):
            raise OSError(
                errno.EINVAL,
                "Invalid argument - [Socket bound to specific port already]",
            )

        local_ip_address: Ip6Address | Ip4Address

        match self._address_family:
            case AddressFamily.INET6:
                try:
                    if (local_ip_address := Ip6Address(address[0])) not in set(stack.local_ip6_unicast()) | {
                        Ip6Address()
                    }:
                        raise OSError(
                            errno.EADDRNOTAVAIL,
                            "Cannot assign requested address - [Local IP address not owned by stack]",
                        )
                except Ip6AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

            case AddressFamily.INET4:
                try:
                    if (local_ip_address := Ip4Address(address[0])) not in set(stack.local_ip4_unicast()) | {
                        Ip4Address()
                    }:
                        raise OSError(
                            errno.EADDRNOTAVAIL,
                            "Cannot assign requested address - [Local IP address not owned by stack]",
                        )
                except Ip4AddressFormatError as error:
                    raise gaierror("[Errno -2] Name or service not known - [Malformed local IP address]") from error

            case _:
                raise AssertionError(f"unreachable: unsupported address family {self._address_family!r}")

        # Sanity check on local port number
        if address[1] not in range(0, 65536):
            raise OverflowError("bind(): port must be 0-65535. - [Port out of range]")

        # Confirm or pick local port number
        if (local_port := address[1]) > 0:
            # SO_REUSEADDR bypasses the in-use check (Linux parity).
            # dual_stack=True flags an AF_INET6 V6ONLY=0 bind to '::'
            # so the in-use check picks up cross-family conflicts
            # with existing AF_INET listeners on the same port — the
            # H3 dual-stack reservation rule.
            if not self._so_reuseaddr and is_address_in_use(
                local_ip_address=local_ip_address,
                local_port=local_port,
                address_family=self._address_family,
                socket_type=self._socket_type,
                dual_stack=(self._address_family is AddressFamily.INET6 and not self._ipv6_v6only),
                reuseport=self._so_reuseport,
            ):
                raise OSError(
                    errno.EADDRINUSE,
                    "Address already in use - [Local address already in use]",
                )
        else:
            local_port = pick_local_port()

        # Assigning local port makes socket "bound".
        stack.sockets.unregister(self)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        stack.sockets.register(self)

        __debug__ and log("socket", f"<g>[{self}]</> - Bound socket")

    @override
    def connect(self, address: tuple[str, int], *, data: bytes = b"") -> None:
        """
        Connect local socket to remote socket.

        'data' optionally pre-loads the session's TX buffer
        before the FSM is driven into SYN_SENT. When a TFO
        cookie is cached for the peer
        ('stack.tcp_stack.fastopen_cookies'), the
        connect-with-data path emits SYN-with-data on the
        wire, eliminating the data RTT for short-lived
        connections (RFC 7413 §3.1).
        """

        # The 'connect' call will bind socket to specific local ip address
        # (will rebind if necessary), specific local port, specific remote
        # IP address and specific remote port.

        # Sanity check on remote port number (0 is a valid remote port in
        # BSD socket implementation).
        if (remote_port := address[1]) not in range(0, 65536):
            raise OverflowError("connect(): port must be 0-65535. - [Port out of range]")

        # Set local and remote ip addresses appropriately. Resolving the
        # remote IP first lets the local-port picker key its
        # RFC 6056 §3.3.3 Algorithm 3 offset on the full destination
        # tuple — per-destination isolation the bare 'pick_local_port'
        # cannot provide.
        local_ip_address, remote_ip_address = self._get_ip_addresses(
            remote_address=address,
        )

        # Assigning local port makes socket "bound" if not "bound" already.
        # When the socket wasn't pre-bound (no explicit bind()), use the
        # destination-aware Algorithm 3 picker; the per-(local, remote)
        # secret-keyed offset means an off-path attacker cannot predict
        # the source port from observations of other flows.
        if (local_port := self._local_port) not in range(1, 65536):
            local_port = pick_local_port_for(
                local_ip=local_ip_address,
                remote_ip=remote_ip_address,
                remote_port=remote_port,
            )

        # Re-register socket with new socket id.
        stack.sockets.unregister(self)
        self._local_ip_address = local_ip_address
        self._local_port = local_port
        self._remote_ip_address = remote_ip_address
        self._remote_port = remote_port
        stack.sockets.register(self)

        self._tcp_session = TcpSession(
            local_ip_address=self._local_ip_address,
            local_port=self._local_port,
            remote_ip_address=self._remote_ip_address,
            remote_port=self._remote_port,
            socket=self,
        )

        # RFC 1122 §4.2.3.6: propagate the SO_KEEPALIVE flag (and
        # the Linux-style per-connection probe overrides) to the
        # freshly-constructed TcpSession before the FSM starts
        # firing. Without this hook, 'setsockopt(SO_KEEPALIVE, 1)'
        # would have no effect.
        self._tcp_session.set_keepalive(
            enabled=self._so_keepalive,
            idle_override=self._tcp_keepidle,
            interval_override=self._tcp_keepintvl,
            max_count_override=self._tcp_keepcnt,
        )

        # RFC 9438 §1: propagate the CC algorithm selector to
        # the freshly-constructed TcpSession. Default is
        # CcMode.CUBIC; opt-in to RENO via
        # 'setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        # CcMode.RENO.value)' before 'connect()'.
        self._tcp_session.set_congestion_control(self._cc_mode)

        # RFC 1122 §4.2.3.4: propagate the TCP_NODELAY flag.
        # Default False (Nagle enabled); opt-out for latency-
        # sensitive applications via 'setsockopt(IPPROTO_TCP,
        # TCP_NODELAY, 1)'.
        self._tcp_session.set_nodelay(self._tcp_nodelay)

        # Linux TCP_USER_TIMEOUT / TCP_MAXSEG per-connection
        # overrides — propagate so the FSM's R2 abort and the
        # SYN-options MSS clamp can consult them.
        self._tcp_session.set_user_timeout_ms(self._tcp_user_timeout)
        self._tcp_session.set_maxseg_override(self._tcp_maxseg)

        # RFC 7413 §3.1 connect-with-data: pre-load the
        # session's TX buffer with caller-supplied bytes
        # before driving the FSM into SYN_SENT. The session-
        # internal '_transmit_data' SYN-with-data emission
        # picks the pre-loaded bytes up when a TFO cookie is
        # cached for the peer ('stack.tcp_stack.fastopen_cookies'),
        # eliminating the data RTT of a vanilla 3WHS-then-
        # send sequence. Empty 'data' (the default) is a
        # no-op; the standard 3WHS path runs unchanged.
        if data:
            self._tcp_session.preload_tx_buffer(data)

        __debug__ and log("socket", f"<g>[{self}]</> - Socket attempting connection")

        try:
            self._tcp_session.connect()
        except TcpSessionError as error:
            if str(error) == "Connection refused":
                raise ConnectionRefusedError(
                    errno.ECONNREFUSED,
                    "Connection refused - [Received RST packet from remote host]",
                ) from error
            if str(error) == "Connection timeout":
                raise TimeoutError(
                    errno.ETIMEDOUT,
                    "Connection timed out - [No valid response received from remote host]",
                ) from error

        __debug__ and log("socket", f"<g>[{self}]</> - Connected socket")

    @override
    def listen(self, *, backlog: int = TCP__DEFAULT_BACKLOG) -> None:
        """
        Starts to listen for incoming connections.

        'backlog' bounds the accept queue ('self._tcp_accept');
        SYNs received while the queue is at capacity are silently
        dropped at '_tcp_fsm_listen's admission gate so the peer's
        TCP retry cycle drives the recovery once the application
        has drained a slot via 'accept()'. Mirrors POSIX
        'listen(2)' semantics. Per-stack default is
        'TCP__DEFAULT_BACKLOG'.
        """

        assert backlog > 0, f"The 'backlog' argument must be positive. Got: {backlog!r}"

        # Linux 'inet_csk_listen_start' auto-binds an unbound socket to
        # an ephemeral local port before it starts listening; PyTCP
        # mirrors that rather than requiring an explicit prior bind()
        # (which would otherwise leave the listener on the invalid port
        # 0). A socket already bound to a specific port keeps it.
        if self._local_port not in range(1, 65536):
            stack.sockets.unregister(self)
            self._local_port = pick_local_port()
            stack.sockets.register(self)

        self._backlog = backlog
        self._tcp_session = TcpSession(
            local_ip_address=self._local_ip_address,
            local_port=self._local_port,
            remote_ip_address=self._remote_ip_address,
            remote_port=self._remote_port,
            socket=self,
        )

        # RFC 1122 §4.2.3.6: propagate SO_KEEPALIVE (and the
        # per-connection probe overrides) to the listening
        # TcpSession so accepted children inherit through the
        # listener-fork pivot in
        # 'pytcp/protocols/tcp/fsm/tcp__fsm__listen.py' (which
        # mutates this session in-place into the child).
        self._tcp_session.set_keepalive(
            enabled=self._so_keepalive,
            idle_override=self._tcp_keepidle,
            interval_override=self._tcp_keepintvl,
            max_count_override=self._tcp_keepcnt,
        )

        # RFC 9438 §1: propagate the CC algorithm selector so
        # accepted children inherit through the listener-fork
        # pivot.
        self._tcp_session.set_congestion_control(self._cc_mode)

        # RFC 1122 §4.2.3.4: propagate Nagle disable so
        # accepted children inherit through the listener-fork
        # pivot.
        self._tcp_session.set_nodelay(self._tcp_nodelay)

        # Linux TCP_USER_TIMEOUT / TCP_MAXSEG per-connection
        # overrides — same pattern: the listener-fork pivot
        # mutates the listening session in-place into the
        # accepted child, so the overrides on the listener
        # naturally inherit.
        self._tcp_session.set_user_timeout_ms(self._tcp_user_timeout)
        self._tcp_session.set_maxseg_override(self._tcp_maxseg)

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - Socket starting to listen for inbound connections " f"(backlog={backlog})",
        )

        stack.sockets.register(self)
        self._tcp_session.listen()

    @override
    def accept(self, *, timeout: float | None = None) -> tuple[socket, tuple[str, int]]:
        """
        Wait for the established inbound connection, once available return
        it's socket.
        """

        __debug__ and log("socket", f"<g>[{self}]</> - Waiting for inbound connection")

        # Per-call 'timeout' takes precedence over 'setblocking()';
        # otherwise non-blocking mode equates to a non-blocking
        # acquire that surfaces as 'BlockingIOError(EAGAIN)'.
        if timeout is None and not self._blocking:
            acquired = self._event__tcp_session_established.acquire(blocking=False)
        else:
            acquired = self._event__tcp_session_established.acquire(timeout=timeout)

        if not acquired:
            if timeout is None and not self._blocking:
                raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
            raise TimeoutError("TCP Socket - Accept operation timed out.")

        socket = cast(TcpSocket, self._tcp_accept.pop(0))
        # POSIX accept(2) inherits the listener's O_NONBLOCK on the
        # accepted child; mirror that so apps that flip the listener
        # to non-blocking get non-blocking children.
        socket._blocking = self._blocking
        if not self._tcp_accept:
            self._drain_readable()
            # Producer race: the FSM may have appended another
            # child between the empty-check and drain — re-check
            # under the GIL and re-signal so the selector wakes.
            if self._tcp_accept:
                self._signal_readable()

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - Socket accepted connection from "
            f"{(str(socket.remote_ip_address), socket.remote_port)}",
        )

        return socket, (str(socket.remote_ip_address), socket.remote_port)

    @override
    def send(self, data: bytes) -> int:
        """
        Send the data to connected remote host.
        """

        # The 'send' call requires 'connect' call to be run prior to it.

        if self._remote_ip_address.is_unspecified or self._remote_port == 0:
            raise BrokenPipeError(
                errno.EPIPE,
                "Broken pipe - [Socket has no destination address set]",
            )

        assert self._tcp_session is not None

        try:
            bytes_sent = self._tcp_session.send(data=data)
        except TcpSessionError as error:
            raise BrokenPipeError(errno.EPIPE, f"Broken pipe - [{error}]") from error

        __debug__ and log(
            "socket",
            f"<g>[{self}]</> - Sent data segment, len {bytes_sent}",
        )
        return bytes_sent

    @override
    def sendmsg(
        self,
        buffers: Iterable[Buffer],
        ancdata: Iterable[tuple[int, int, Buffer]] = (),
        flags: int = 0,
        address: tuple[str, int] | None = None,
    ) -> int:
        """
        Send the scatter-gather 'buffers' iterable over the connected
        stream, mirroring stdlib 'socket.sendmsg'. The buffers are
        concatenated and handed to the session's byte-stream send().

        A non-None 'address' is invalid on a connected stream socket
        and raises 'OSError(EISCONN)' (Linux 'tcp_sendmsg' rejects a
        destination on an already-connected socket). Phase-1 PyTCP
        honours no send-side cmsg type, so 'ancdata' is validated for
        shape then ignored.
        """

        if address is not None:
            raise OSError(
                errno.EISCONN,
                "Transport endpoint is already connected - " "[sendmsg() address is invalid on a connected TCP socket]",
            )

        self._validate_sendmsg_ancdata(ancdata)

        return self.send(b"".join(bytes(buffer) for buffer in buffers))

    @override
    def recv(self, bufsize: int | None = None, timeout: float | None = None) -> bytes:
        """
        Receive data from socket.
        """

        assert self._tcp_session is not None

        # Per-call 'timeout' takes precedence over 'setblocking()';
        # SO_RCVTIMEO supplies the next-best default; non-blocking
        # mode forwards 'timeout=0' so the session's 'Event.wait(0)'
        # returns immediately. The resulting 'TimeoutError' is
        # translated into 'BlockingIOError(EAGAIN)' iff non-blocking.
        if timeout is not None:
            effective_timeout: float | None = timeout
        elif self._so_rcvtimeo is not None:
            effective_timeout = self._so_rcvtimeo
        elif not self._blocking:
            effective_timeout = 0
        else:
            effective_timeout = None

        try:
            if data_rx := self._tcp_session.receive(byte_count=bufsize, timeout=effective_timeout):
                __debug__ and log(
                    "socket",
                    f"<g>[{self}]</> - Received {len(data_rx)} bytes of data",
                )
            else:
                __debug__ and log(
                    "socket",
                    f"<g>[{self}]</> - Received empty data byte string, remote end closed connection",
                )
            return data_rx

        except TimeoutError as error:
            if timeout is None and not self._blocking:
                raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN)) from error
            raise TimeoutError("TCP Socket - Receive operation timed out.") from error

    @override
    def close(self) -> None:
        """
        Close socket and the TCP session(s) it owns.
        """

        assert self._tcp_session is not None

        linger = self._so_linger

        # SO_LINGER {l_onoff=1, l_linger=0}: abortive close — emit a
        # RST and discard queued data instead of the graceful FIN
        # exchange (the well-known "SO_LINGER zero -> RST" idiom; RFC
        # 9293 §3.10.7.4 abort semantics).
        if linger is not None and linger[0] != 0 and linger[1] == 0:
            self._tcp_session.abort()
            self._mark_closed()
            __debug__ and log("socket", f"<g>[{self}]</> - Closed socket (SO_LINGER 0 -> abort)")
            return

        # Graceful close: initiate the FIN exchange.
        self._tcp_session.close()

        # SO_LINGER {l_onoff=1, l_linger>0}: block until the session
        # reaches CLOSED or 'l_linger' seconds elapse, whichever comes
        # first. In a running stack the RX / timer threads advance the
        # FSM (and set '_event__closed') while this call waits; the
        # deadline is computed at close() entry per Linux's lingering
        # close semantics (tcp(7) / socket(7) SO_LINGER).
        if linger is not None and linger[0] != 0:
            deadline = time.monotonic() + linger[1]
            remaining = deadline - time.monotonic()
            if remaining > 0:
                self._tcp_session.wait_closed(timeout=remaining)

        # '_mark_closed' sets '_closed' for consistency; TCP delivery
        # ('process_tcp_packet') is drained by 'TcpSession._lock__fsm'
        # (close() routes through the same FSM lock), not by the
        # socket-level '_lock__io'.
        self._mark_closed()

        __debug__ and log("socket", f"<g>[{self}]</> - Closed socket")

    def shutdown(self, how: int, /) -> None:
        """
        BSD 'shutdown(how)' half-close per POSIX:
            SHUT_RD   (0): no further reads.
            SHUT_WR   (1): no further writes; FIN emitted.
            SHUT_RDWR (2): both.

        On a fresh / closed socket with no associated session,
        this is a no-op.
        """

        if self._tcp_session is not None:
            self._tcp_session.shutdown(how=how)

        __debug__ and log("socket", f"<g>[{self}]</> - shutdown(how={how})")

    def abort(self) -> None:
        """
        Abort the TCP connection per RFC 9293 §3.9.1 ABORT.

        Emits a RST for synchronized states (ESTABLISHED, FIN_WAIT_*,
        CLOSE_WAIT, SYN_RCVD) and tears down the session immediately
        without graceful close. Pending recv() / connect() callers
        unblock with a connection error. On a fresh / closed socket
        with no associated session, this is a no-op.
        """

        if self._tcp_session is not None:
            self._tcp_session.abort()

        __debug__ and log("socket", f"<g>[{self}]</> - Aborted socket")

    def process_tcp_packet(self, packet_rx_md: TcpMetadata) -> None:
        """
        Process incoming packet's metadata.
        """

        if self._tcp_session:
            self._tcp_session.tcp_fsm(packet_rx_md)

    ###############################
    ##  RFC 1122 §4.2.3.9 / Linux IP_RECVERR error-queue surface.
    ###############################

    def _is_recverr_enabled(self) -> bool:
        """
        Return True when the per-family RECVERR flag is set so the
        notify_* paths should enqueue the error for later
        'recvmsg(MSG_ERRQUEUE)' dequeue. Mirrors
        'UdpSocket._is_recverr_enabled' so the gate semantics are
        identical across UDP / TCP.
        """

        if self._address_family is AddressFamily.INET6:
            return self._ipv6_recverr
        return self._ip_recverr

    def _enqueue_error(self, entry: ErrorQueueEntry, /) -> None:
        """
        Append an 'ErrorQueueEntry' to the per-socket error queue
        and release the readability semaphore so a blocking
        'recvmsg(MSG_ERRQUEUE)' wakes up. No-op when the per-family
        RECVERR flag is unset.
        """

        if not self._is_recverr_enabled():
            return
        self._error_queue.append(entry)
        self._error_queue_ready.release()

    def notify_unreachable(
        self,
        *,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        icmp_type: ProtoEnum | int = 0,
        icmp_code: ProtoEnum | int = 0,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMP Destination Unreachable matched against this
        TCP socket. When 'IP_RECVERR' / 'IPV6_RECVERR' is set on
        the socket, appends an 'ErrorQueueEntry' so the
        application can dequeue the full ICMP context via
        'recvmsg(MSG_ERRQUEUE)'. The legacy FSM-event path
        ('session.tcp_fsm(IcmpMetadata(...))') is unchanged and
        still fires alongside this surface, mirroring Linux's
        independent error-queue + ICMP-error-to-TCP-session
        layering.

        Reference: RFC 1122 §4.2.3.9 (TCP MUST report ICMP errors
        to the application).
        """

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_error(
            build_icmp_error_entry(
                icmp_origin=icmp_origin,
                icmp_type=int(icmp_type),
                icmp_code=int(icmp_code),
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
        )

    def notify_time_exceeded(
        self,
        *,
        icmp_type: ProtoEnum | int,
        icmp_code: ProtoEnum | int,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMP Time Exceeded matched against this TCP
        socket. Surfaces via 'recvmsg(MSG_ERRQUEUE)' when the
        per-family RECVERR flag is set. RFC 1122 §3.2.2.4
        mandates pass-to-transport; the FSM-event side already
        fires from the ICMP demux.
        """

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_error(
            build_icmp_error_entry(
                icmp_origin=icmp_origin,
                icmp_type=int(icmp_type),
                icmp_code=int(icmp_code),
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
        )

    def notify_parameter_problem(
        self,
        *,
        icmp_type: ProtoEnum | int,
        icmp_code: ProtoEnum | int,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMP Parameter Problem matched against this TCP
        socket. Surfaces via 'recvmsg(MSG_ERRQUEUE)' when the
        per-family RECVERR flag is set. RFC 1122 §3.2.2.5
        mandates pass-to-transport.
        """

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_error(
            build_icmp_error_entry(
                icmp_origin=icmp_origin,
                icmp_type=int(icmp_type),
                icmp_code=int(icmp_code),
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
        )

    def notify_pmtu(
        self,
        *,
        next_hop_mtu: int,
        icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
        icmp_type: ProtoEnum | int = 0,
        icmp_code: ProtoEnum | int = 0,
        offender_ip: Ip4Address | Ip6Address | None = None,
        embedded_datagram: bytes = b"",
    ) -> None:
        """
        Inbound ICMPv4 Fragmentation Needed or ICMPv6 Packet Too
        Big matched against this TCP socket. The PMTU FSM event
        side ('session.tcp_fsm(IcmpMetadata(category=PMTU, ...))')
        is dispatched separately by the ICMP demux and updates the
        per-destination 'stack.pmtu_cache' + 'snd_mss' recompute.
        When 'IP_RECVERR' / 'IPV6_RECVERR' is set, this method
        also appends an 'ErrorQueueEntry' carrying errno=EMSGSIZE
        + ee_info=next_hop_mtu per Linux semantics so
        'recvmsg(MSG_ERRQUEUE)' applications can read the new
        MTU.

        Reference: RFC 1191 §3 (ICMPv4 PMTUD next-hop MTU surface).
        Reference: RFC 8201 §4 (IPv6 PMTUD next-hop MTU surface).
        """

        if offender_ip is None or not self._is_recverr_enabled():
            return

        self._enqueue_error(
            ErrorQueueEntry(
                errno=errno.EMSGSIZE,
                origin=icmp_origin,
                icmp_type=int(icmp_type),
                icmp_code=int(icmp_code),
                ee_info=next_hop_mtu,
                offender_ip=offender_ip,
                embedded_datagram=embedded_datagram,
            )
        )

    @override
    def recvmsg(
        self,
        bufsize: int | None = None,
        ancbufsize: int = 0,
        flags: int = 0,
        timeout: float | None = None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive a TCP error-queue entry along with ancillary data
        (control messages) and the offender's address. Mirrors the
        Python stdlib 'socket.recvmsg(bufsize, ancbufsize=0,
        flags=0)' signature.

        Currently the data-path 'recvmsg' on TCP is not
        implemented — TCP applications use 'recv()' for the byte
        stream; only the 'flags & MSG_ERRQUEUE' branch is
        meaningful here. Passing 'flags=0' raises 'OSError' so the
        partial surface is visible to callers; the data-path
        equivalent for TCP can land in a future commit if a
        consumer needs it (Linux supports it for TCP cmsgs like
        TCP_TIMESTAMP).
        """

        if flags & MSG_ERRQUEUE:
            return self._recvmsg_errqueue(ancbufsize=ancbufsize, timeout=timeout)

        raise OSError(
            errno.EOPNOTSUPP,
            "recvmsg() on TCP socket without MSG_ERRQUEUE is not yet supported.",
        )

    def _recvmsg_errqueue(
        self,
        *,
        ancbufsize: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Dequeue one entry from the per-socket ICMP error queue
        and return it in the Linux 'recvmsg(MSG_ERRQUEUE)'
        4-tuple shape: '(embedded_datagram, ancdata,
        MSG_ERRQUEUE, offender_address)'. The data portion is the
        original outbound segment quoted in the ICMP error 'data'
        field; the ancillary data carries an 'IP_RECVERR' /
        'IPV6_RECVERR' cmsg whose payload is the packed Linux
        'struct sock_extended_err' + offender 'sockaddr_in' /
        'sockaddr_in6'.

        Mirrors 'UdpSocket._recvmsg_errqueue' wire shape so an
        application written for the UDP IP_RECVERR API works
        unchanged against TCP.

        Reference: RFC 1122 §4.2.3.9 (TCP MUST report ICMP errors).
        Reference: Linux 'ip(7)' / 'ipv6(7)' (IP_RECVERR /
        IPV6_RECVERR API shape).
        """

        effective_timeout = timeout if timeout is not None else self._so_rcvtimeo
        if effective_timeout is None and not self._blocking:
            acquired = self._error_queue_ready.acquire(blocking=False)
        else:
            acquired = self._error_queue_ready.acquire(timeout=effective_timeout)

        if not acquired:
            if effective_timeout is None and not self._blocking:
                raise BlockingIOError(errno.EAGAIN, os.strerror(errno.EAGAIN))
            raise TimeoutError("TCP Socket - Receive operation timed out.")

        entry = self._error_queue.popleft()
        cmsg_payload = pack_sock_extended_err(entry)
        ancdata: list[tuple[int, int, bytes]] = []
        if ancbufsize > 0:
            if isinstance(entry.offender_ip, Ip4Address):
                ancdata.append((int(IPPROTO_IP), int(IP_RECVERR), cmsg_payload))
            else:
                ancdata.append((int(IPPROTO_IPV6), int(IPV6_RECVERR), cmsg_payload))

        address: tuple[str, int] | tuple[str, int, int, int]
        if isinstance(entry.offender_ip, Ip4Address):
            address = (str(entry.offender_ip), 0)
        else:
            address = (str(entry.offender_ip), 0, 0, 0)

        return entry.embedded_datagram, ancdata, int(MSG_ERRQUEUE), address
