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
This module contains the DHCPv4 client (RFC 2131 §4.4 FSM).

pytcp/protocols/dhcp4/dhcp4__client.py

ver 3.0.8
"""

import random
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable, override

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, MacAddress

if TYPE_CHECKING:
    from pytcp.stack.address import AddressApi
    from pytcp.stack.route import RouteApi

from net_proto.protocols.dhcp4.dhcp4__assembler import Dhcp4Assembler
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__errors import (
    Dhcp4IntegrityError,
    Dhcp4SanityError,
)
from net_proto.protocols.dhcp4.dhcp4__parser import Dhcp4Parser
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    Dhcp4Option,
    Dhcp4OptionType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__client_id import (
    Dhcp4OptionClientId,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__end import (
    Dhcp4OptionEnd,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__host_name import (
    Dhcp4OptionHostName,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__lease_time import (
    Dhcp4OptionLeaseTime,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__max_msg_size import (
    Dhcp4OptionMaxMsgSize,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__req_ip_addr import (
    Dhcp4OptionReqIpAddr,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__server_id import (
    Dhcp4OptionServerId,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options
from pytcp.lib.logger import log
from pytcp.protocols.dhcp4 import dhcp4__constants
from pytcp.protocols.dhcp4.dhcp4__lease_cache import (
    delete_cached_lease,
    read_cached_lease,
    write_cached_lease,
)
from pytcp.protocols.dhcp4.dhcp4__uid import build_client_id
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.runtime.socket import (
    AF_INET4,
    SO_BINDTODEVICE,
    SO_BROADCAST,
    SOCK_DGRAM,
    SOL_SOCKET,
    AddressFamily,
    socket,
)
from pytcp.runtime.subsystem import Subsystem

# 'secs' is a 16-bit field in the DHCP header; cap the elapsed-
# since-acquisition seconds at UINT16_MAX so a long-lived restart
# loop cannot overflow.
_DHCP4__SECS_MAX: int = 0xFFFF


class Dhcp4State(Enum):
    """
    RFC 2131 §4.4 DHCPv4 client FSM states. Driven by
    'Dhcp4Client._subsystem_loop' when the client runs as a
    daemon ('start()' / 'stop()'); irrelevant in sync mode
    where 'fetch()' runs INIT → BOUND inline and returns.
    """

    INIT = "INIT"
    INIT_REBOOT = "INIT-REBOOT"
    SELECTING = "SELECTING"
    REQUESTING = "REQUESTING"
    REBOOTING = "REBOOTING"
    BOUND = "BOUND"
    RENEWING = "RENEWING"
    REBINDING = "REBINDING"


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Lease:
    """
    A negotiated DHCPv4 lease — the address+mask+gateway bundle plus
    the lease-time / server-identity / acquisition-time metadata the
    lifecycle thread needs to schedule RENEW/REBIND/RELEASE.

    'gateway_mac' is the gateway's link-layer address at the moment
    the lease was last cached. Populated lazily by
    'write_cached_lease' from the ARP cache; consumed by Phase 6
    RFC 4436 DNAv4 to send a unicast ARP probe to the cached
    gateway and short-circuit the DHCP exchange if it answers.
    None when the gateway has not yet been resolved (typical on
    first boot before any IP traffic flowed) or when the cache
    pre-dates Phase 6.

    't1_override' / 't2_override' carry the server-supplied
    Renewal (option 58, RFC 2132 §9.7) and Rebinding (option 59,
    RFC 2132 §9.8) values from the ACK. RFC 2131 §4.4.5 mandates
    "If the DHCP server returns a 'renewal time value' option in
    a DHCPACK, the client MUST use this value as T1" — so when
    set, '_t1_deadline' / '_t2_deadline' prefer these over the
    factor-based defaults. None when the server omitted the
    option or when the cached lease pre-dates this field.
    """

    ip4_host: Ip4IfAddr
    lease_time__sec: int
    server_id: Ip4Address
    acquired_at_monotonic: float
    # Leased default gateway (DHCP option 3, first router). Lives
    # on the lease, not on 'ip4_host' — the Ip4IfAddr value type
    # carries no gateway (host-mode routing is the FIB's job; the
    # Route API installs this as the protocol=DHCP default route
    # on BOUND). None when the server omitted option 3.
    gateway: Ip4Address | None = None
    gateway_mac: MacAddress | None = None
    t1_override: int | None = None
    t2_override: int | None = None
    # Leased classless static routes (DHCP option 121, RFC 3442) as
    # (destination, router) pairs. When present the client installs
    # these into the FIB and IGNORES option 3 (RFC 3442 MUST); the
    # 0.0.0.0/0 entry, if any, is the default route. None when the
    # server omitted option 121.
    classless_static_routes: list[tuple[Ip4Network, Ip4Address]] | None = None


class _NakRestart:
    """
    Sentinel — DHCPNAK received in response to REQUEST; restart from
    DISCOVER (RFC 2131 §3.1 step 4).
    """


_NAK_RESTART: _NakRestart = _NakRestart()


class Dhcp4Client(Subsystem):
    """
    DHCPv4 client — RFC 2131 §4.4 FSM body.

    Two invocation modes:

      - Sync: 'Dhcp4Client(...).fetch()' runs one INIT → BOUND
        cycle inline in the caller's thread, returns the lease,
        tears down. The 'Subsystem' machinery is not engaged —
        no thread spawned, no '_state' mutation. Used by tests
        and operator CLI tools.
      - Daemon: 'Dhcp4Client(...).start()' spawns the Subsystem
        thread which drives '_subsystem_loop' through the full
        FSM (INIT → SELECTING → REQUESTING → BOUND → RENEWING
        → REBINDING → ...). Used by 'stack.start()' in
        production.

    The two modes share '_do_init_to_bound' — the INIT-side wire
    exchange.

    The FSM-driven RENEW/REBIND/expiry/RELEASE handlers and the
    'address_api' integration are stubs in this commit; Phase 4
    follow-ups wire them in.
    """

    _subsystem_name = "DHCP4 Client"

    def __init__(
        self,
        *,
        mac_address: MacAddress,
        acd: Ip4Acd | None = None,
        address_api: "AddressApi | None" = None,
        route_api: "RouteApi | None" = None,
        interface_name: str | None = None,
    ) -> None:
        """
        Initialize the DHCPv4 client.

        The optional 'acd' is the RFC 5227 IPv4 Address Conflict
        Detection engine (the userspace 'sd-ipv4acd' equivalent over
        the AF_PACKET socket). When supplied:

          - the INIT path runs the RFC 2131 §3.1-step-5 / RFC 5227
            §2.1.1 ARP Probe against the offered 'yiaddr' after a
            valid ACK ('acd.probe'); on conflict the client emits
            DHCPDECLINE and restarts from DISCOVER;
          - the BOUND transition (daemon mode only) begins ongoing
            §2.4 conflict defense via 'acd.start_defense' (emit the
            §2.3 Announcement burst + hold the defense socket), and
            each BOUND tick polls 'acd.poll_conflict' — a sustained
            conflict makes the client DECLINE and re-acquire.

        Sync 'fetch()' uses only the probe (no ongoing defender — the
        caller owns the returned lease and there is no FSM loop to
        poll or release the held socket).

        The optional 'address_api' is the kernel/userspace
        boundary surface (Phase-3 north-star); on BOUND transition
        (daemon mode only) the lifecycle calls
        'address_api.add(...)' to install the leased
        Ip4IfAddr on the stack's address list. Sync 'fetch()' does
        not touch the API — the caller owns the returned lease.
        """

        super().__init__(info=str(mac_address))
        self._mac_address = mac_address
        self._acd = acd
        self._address_api = address_api
        self._route_api = route_api
        # Interface this client configures. Pins every client socket's
        # egress to this interface via SO_BINDTODEVICE so the pre-lease
        # limited-broadcast (255.255.255.255) DISCOVER / REQUEST egress
        # is unambiguous on a multi-homed host (Linux dhclient model).
        self._interface_name = interface_name
        # Set at the top of '_do_init_to_bound'; reused by every
        # outbound TX in this acquisition cycle to populate the
        # DHCP header 'secs' field per RFC 1542 §3.2.
        self._fetch_started_at_monotonic: float = 0.0
        # Current lease — set on BOUND transition; sync 'fetch()'
        # returns it directly without writing to this attribute.
        self._lease: Dhcp4Lease | None = None
        # Signalled by the daemon-mode INIT handler on BOUND
        # transition. 'start_and_wait_for_bind' blocks on this
        # event up to the boot-wait timeout.
        self._event__bound: threading.Event = threading.Event()

        # Phase 5 — RFC 2131 §4.4.2 INIT-REBOOT cached-lease
        # fast-path. If a cached lease is on disk and still
        # within its 'lease_time', start the FSM in INIT-REBOOT
        # so the first wire emission is a unicast-on-server-id-
        # less REQUEST asking for the cached IP, not a fresh
        # DISCOVER. The cache is consulted only when the path
        # sysctl is non-empty.
        cached = read_cached_lease(dhcp4__constants.DHCP4__LEASE_CACHE_PATH)
        if cached is not None:
            __debug__ and log(
                "dhcp4",
                f"<lg>Found cached lease</>: {cached.ip4_host} "
                f"(server={cached.server_id}, "
                f"lease_time={cached.lease_time__sec}s); "
                f"starting in INIT-REBOOT",
            )
            self._lease = cached
            self._state: Dhcp4State = Dhcp4State.INIT_REBOOT
        else:
            # FSM state — driven by '_subsystem_loop' in daemon
            # mode; untouched by sync 'fetch()'.
            self._state = Dhcp4State.INIT

    @property
    def state(self) -> Dhcp4State:
        """
        Read-only snapshot of the current FSM state. Exposed
        so external coordinators (e.g. the RFC 3927 IPv4
        link-local autoconfig client per §1.9 / §2.11) can
        poll DHCP state without reaching into '_state'.
        """

        return self._state

    @property
    def _expected_client_id(self) -> bytes:
        """
        RFC 4361 §6.1 Client Identifier — type=0xff + IAID + DUID.
        Recomputed on every access so an operator override of
        'dhcp.duid' between emissions takes effect immediately.
        """

        return build_client_id(self._mac_address)

    def fetch(self) -> Dhcp4Lease | None:
        """
        Synchronous DHCPv4 acquisition — runs one INIT → BOUND
        cycle inline and returns the resulting lease (or None on
        failure). Does not spawn the Subsystem thread; does not
        mutate the FSM state; does not call into the address API.

        Equivalent to Linux's 'dhcpcd -1' / 'dhclient -1' one-shot
        flag. Production code uses 'start()' / 'stop()' instead.
        """

        return self._do_init_to_bound()

    @override
    def _subsystem_loop(self) -> None:
        """
        Daemon-mode FSM driver. Dispatches on '_state'; one
        iteration per call. The 'Subsystem' base class loop wraps
        this in 'while not stop_event'.

        INIT runs '_do_init_to_bound', installs the lease on the
        stack via 'address_api.add', begins RFC 5227 §2.4
        ongoing conflict defense via 'acd.start_defense' (which emits
        the §2.3 Announcements and holds the defense socket), signals
        'self._event__bound', and transitions to BOUND. The BOUND
        handler polls the ACD conflict signal each tick and drives
        the T1/T2/expiry lease-lifecycle transitions.
        """

        # Daemon-loop guard: the base 'Subsystem' worker thread dies if
        # '_subsystem_loop' raises (e.g. a wire send returning
        # EHOSTUNREACH out of '_do_init_to_bound'), silently taking the
        # DHCPv4 client down. Catch any unexpected exception, log it, and
        # signal stop so the client halts cleanly instead of crashing the
        # thread. ('Exception' — not 'BaseException' — so KeyboardInterrupt
        # / SystemExit still propagate; Phase 4's retry policy will turn the
        # halt into a backoff-and-retry.)
        try:
            match self._state:
                case Dhcp4State.INIT:
                    lease = self._do_init_to_bound()
                    if lease is not None:
                        self._on_bound(lease)
                    else:
                        # Phase 4 follow-up: retry policy. For now,
                        # signal stop to avoid a tight retry loop.
                        self._event__stop_subsystem.set()
                case Dhcp4State.INIT_REBOOT:
                    self._do_init_reboot()
                case Dhcp4State.BOUND:
                    self._do_bound()
                case Dhcp4State.RENEWING:
                    self._do_renewing()
                case Dhcp4State.REBINDING:
                    self._do_rebinding()
                case _:
                    # SELECTING / REQUESTING / REBOOTING — collapsed
                    # into the synchronous wire exchanges inside
                    # '_do_init_to_bound' / '_do_init_reboot' so the
                    # FSM never observes them as separate states.
                    # Idle on stop event so 'stop()' is responsive.
                    self._event__stop_subsystem.wait(timeout=1.0)
        except Exception as error:  # noqa: BLE001 — daemon-loop guard must not let the worker thread die
            __debug__ and log(
                "dhcp4",
                f"<WARN>DHCPv4 client loop raised {type(error).__name__}: {error}; "
                f"halting the client (state was {self._state})</>",
            )
            self._event__stop_subsystem.set()

    def _on_bound(self, lease: Dhcp4Lease, /) -> None:
        """
        Transition to BOUND: install the lease's Ip4IfAddr via the
        address API, begin RFC 5227 §2.4 ongoing conflict defense of
        the committed address via 'acd.start_defense' (which emits
        the §2.3 ANNOUNCE_NUM gratuitous-ARP burst and holds the
        defense socket for 'poll_conflict'), persist the lease to
        disk for the next boot's INIT-REBOOT fast-path (Phase 5),
        and signal 'start_and_wait_for_bind' watchers via the
        'self._event__bound' event.
        """

        # Clear the prior lease's classless static routes before
        # installing the refreshed set so a RENEW / REBIND does not
        # accumulate duplicate FIB entries (add_route does not
        # de-duplicate). The default route is replaced atomically by
        # the install below.
        previous_lease = self._lease
        if previous_lease is not None:
            self._remove_lease_routes(previous_lease)

        self._lease = lease
        if self._address_api is not None:
            self._address_api.add(ifaddr=lease.ip4_host)
        # Install the lease's routes — Phase 3 of
        # docs/refactor/routing_table_host_mode.md. The FIB is
        # the single source of truth for the next hop;
        # 'lease.gateway' no longer rides on 'ip4_host'.
        self._install_lease_routes(lease)
        if self._acd is not None:
            self._acd.start_defense(address=lease.ip4_host.address)
        write_cached_lease(dhcp4__constants.DHCP4__LEASE_CACHE_PATH, lease)
        self._state = Dhcp4State.BOUND
        self._event__bound.set()

    def _install_lease_routes(self, lease: Dhcp4Lease, /) -> None:
        """
        Install the lease's routes into the FIB via the Route API.

        When the server returned Classless Static Routes (option 121)
        the client installs those routes and IGNORES the Router option
        (option 3) per the RFC 3442 MUST. Each option-121 route with a
        non-zero router becomes a protocol=DHCP route — the 0.0.0.0/0
        entry, if present, is the default; a router of 0.0.0.0 denotes
        an on-link destination that PyTCP's host FIB does not install
        (RFC 3442 explicitly permits a stack that does not provide that
        capability to ignore such routes). Absent option 121 the client
        falls back to the option-3 gateway as the default route.
        """

        if self._route_api is None:
            return

        if lease.classless_static_routes is not None:
            for destination, router in lease.classless_static_routes:
                if router == Ip4Address("0.0.0.0"):
                    # Phase 2: install as an on-link route once
                    # DHCP-learned routes carry an output-interface
                    # index in the FIB.
                    continue
                if destination == Ip4Network("0.0.0.0/0"):
                    self._route_api.replace_default(gateway=router, protocol=RouteProtocol.DHCP)
                    continue
                self._route_api.add_route(
                    route=Route(destination=destination, gateway=router, protocol=RouteProtocol.DHCP),
                )
            return

        if lease.gateway is not None:
            self._route_api.replace_default(gateway=lease.gateway, protocol=RouteProtocol.DHCP)

    def _remove_lease_routes(self, lease: Dhcp4Lease, /) -> None:
        """
        Remove the lease's non-default classless static routes from the
        FIB. The 0.0.0.0/0 default and the on-link (router 0.0.0.0)
        entries are not removed here — the default is dropped via
        'remove_default' (lease loss) or replaced atomically (RENEW),
        and on-link entries are never installed.
        """

        if self._route_api is None or lease.classless_static_routes is None:
            return

        for destination, router in lease.classless_static_routes:
            if router == Ip4Address("0.0.0.0") or destination == Ip4Network("0.0.0.0/0"):
                continue
            self._route_api.remove_route(destination=destination, gateway=router)

    def start_and_wait_for_bind(self, *, timeout_s: float) -> bool:
        """
        Spawn the Subsystem thread and block up to 'timeout_s'
        seconds for the FSM to reach BOUND. Returns True if BOUND
        was reached, False on timeout (the FSM keeps running in
        the background regardless).

        Mirrors Linux 'dhcpcd -t<n>' one-shot boot-blocking
        semantics. 'stack.start()' calls this with
        'dhcp.boot_wait_ms / 1000' as the timeout.
        """

        self.start()
        return self._event__bound.wait(timeout=timeout_s)

    # ------------------------------------------------------------
    # RFC 2131 §4.4.5 — lease-lifecycle (T1, T2, expiry)
    # ------------------------------------------------------------

    def _t1_deadline(self) -> float:
        """
        RFC 2131 §4.4.5 — T1 deadline (monotonic seconds): the
        client moves BOUND → RENEWING at this time. Prefers the
        server-supplied Renewal Time override (option 58,
        RFC 2132 §9.7) when present on the lease; falls back to
        the factor-based default 'acquired_at + lease_time ×
        dhcp.t1_factor'.
        """

        assert self._lease is not None
        if self._lease.t1_override is not None:
            return self._lease.acquired_at_monotonic + self._lease.t1_override
        return self._lease.acquired_at_monotonic + self._lease.lease_time__sec * dhcp4__constants.DHCP4__T1_FACTOR

    def _t2_deadline(self) -> float:
        """
        RFC 2131 §4.4.5 — T2 deadline (monotonic seconds): the
        client moves RENEWING → REBINDING at this time. Prefers
        the server-supplied Rebinding Time override (option 59,
        RFC 2132 §9.8) when present on the lease; falls back to
        the factor-based default 'acquired_at + lease_time ×
        dhcp.t2_factor'.
        """

        assert self._lease is not None
        if self._lease.t2_override is not None:
            return self._lease.acquired_at_monotonic + self._lease.t2_override
        return self._lease.acquired_at_monotonic + self._lease.lease_time__sec * dhcp4__constants.DHCP4__T2_FACTOR

    def _extract_t1_t2_overrides(
        self,
        ack: Dhcp4Parser,
        lease_time__sec: int,
    ) -> tuple[int | None, int | None]:
        """
        Read RFC 2132 §9.7 / §9.8 Renewal (T1) and Rebinding (T2)
        Time options from a freshly-received ACK. Returns the
        '(t1_override, t2_override)' pair to stamp on the
        resulting 'Dhcp4Lease'.

        RFC 2131 §4.4.5 mandates 't1 < t2 < lease_time'. When the
        server supplies values that violate that ordering, PyTCP
        deliberately deviates from a strict RFC reject: log a
        warning and treat the offending value as absent, so the
        factor-based default takes over for that timer. A
        misconfigured server should not punish the client with a
        rejected lease — Linux dhcpcd takes the same lenient
        line.
        """

        t1 = ack.renewal_time
        t2 = ack.rebinding_time

        # Ordering invariants. The lease_time bound is the hard
        # ceiling; the t1 < t2 bound enforces the FSM's RENEW →
        # REBIND ordering.
        if t1 is not None and t1 >= lease_time__sec:
            __debug__ and log(
                "dhcp4",
                f"<WARN>Server-supplied T1={t1} ≥ lease_time={lease_time__sec}; "
                f"ignoring (falling back to factor-based default)</>",
            )
            t1 = None
        if t2 is not None and t2 >= lease_time__sec:
            __debug__ and log(
                "dhcp4",
                f"<WARN>Server-supplied T2={t2} ≥ lease_time={lease_time__sec}; "
                f"ignoring (falling back to factor-based default)</>",
            )
            t2 = None
        if t1 is not None and t2 is not None and t1 >= t2:
            __debug__ and log(
                "dhcp4",
                f"<WARN>Server-supplied T1={t1} ≥ T2={t2}; "
                f"ignoring both (falling back to factor-based defaults)</>",
            )
            t1 = None
            t2 = None

        return t1, t2

    def _lease_expiry_deadline(self) -> float:
        """
        RFC 2131 §4.4.5 — lease-expiry deadline (monotonic
        seconds): the client halts IPv4 if no ACK arrives by
        this point. Computed as 'acquired_at + lease_time'.
        """

        assert self._lease is not None
        return self._lease.acquired_at_monotonic + self._lease.lease_time__sec

    def _do_bound(self) -> None:
        """
        BOUND-state handler. First drains the RFC 5227 §2.4 ACD
        conflict signal: a peer using our leased address makes the
        client abandon the lease (DHCPDECLINE + re-acquire). Then
        checks T1; if elapsed, transitions to RENEWING. Otherwise
        blocks on the stop event up to 'remaining_until_T1' so
        'stop()' is responsive while the thread sleeps through the
        lease's BOUND interval.

        Reference: RFC 5227 §2.4 (defend / abandon a claimed address on conflict).
        Reference: RFC 2131 §4.4.5 (T1 = 0.5 × lease default).
        """

        assert self._lease is not None
        if self._acd is not None and (peer_mac := self._acd.poll_conflict()) is not None:
            self._handle_bound_conflict(peer_mac)
            return
        now = time.monotonic()
        t1 = self._t1_deadline()
        if now >= t1:
            __debug__ and log(
                "dhcp4",
                f"Initiating lease renewal (T1 elapsed; lease " f"{now - self._lease.acquired_at_monotonic:.0f} s old)",
            )
            self._state = Dhcp4State.RENEWING
            return
        # Wait up to (t1 - now) for stop or for T1.
        self._event__stop_subsystem.wait(timeout=t1 - now)

    def _do_renewing(self) -> None:
        """
        RENEWING-state handler. Sends a unicast REQUEST to the
        leasing server (ciaddr = current IP, no server-id /
        requested-ip options per RFC 2131 §4.3.2 Table 4) and
        waits for an ACK. On ACK refreshes the lease and returns
        to BOUND. On NAK falls back to INIT. On T2 elapsed
        without an ACK, escalates to REBINDING.

        Reference: RFC 2131 §4.4.5 (RENEW: unicast REQUEST after T1).
        """

        assert self._lease is not None
        now = time.monotonic()
        t2 = self._t2_deadline()
        if now >= t2:
            __debug__ and log("dhcp4", "Lease renewal unanswered; broadcasting REBINDING REQUEST")
            self._state = Dhcp4State.REBINDING
            return

        outcome = self._do_renew_or_rebind_exchange(lease=self._lease, broadcast=False)
        self._consume_renew_or_rebind_outcome(outcome)

    def _do_rebinding(self) -> None:
        """
        REBINDING-state handler. Sends a broadcast REQUEST
        (ciaddr = current IP, no server-id / requested-ip per
        RFC 2131 §4.3.2 Table 4) and waits for an ACK from any
        DHCP server on the segment. On ACK refreshes the lease
        and returns to BOUND. On NAK falls back to INIT. On
        lease-expiry without an ACK, halts IPv4 + removes the
        host and re-enters INIT.

        Reference: RFC 2131 §4.4.5 (REBIND: broadcast REQUEST after T2; lease expires → halt).
        """

        assert self._lease is not None
        now = time.monotonic()
        expiry = self._lease_expiry_deadline()
        if now >= expiry:
            __debug__ and log(
                "dhcp4",
                f"<WARN>Lease expired; halting IPv4 (lease was " f"{self._lease.lease_time__sec} s long)</>",
            )
            self._halt_ipv4_and_reset_to_init()
            return

        outcome = self._do_renew_or_rebind_exchange(lease=self._lease, broadcast=True)
        self._consume_renew_or_rebind_outcome(outcome)

    def _do_renew_or_rebind_exchange(
        self,
        *,
        lease: Dhcp4Lease,
        broadcast: bool,
    ) -> "Dhcp4Lease | _NakRestart | None":
        """
        Open a one-shot socket, send one unicast (RENEW) or
        broadcast (REBIND) REQUEST, wait for an ACK / NAK / no
        reply, close the socket. Returns 'Dhcp4Lease' on a
        validated ACK, '_NAK_RESTART' on NAK (caller falls back
        to INIT), or None on timeout (caller stays in the
        current state; the loop re-enters and rechecks the
        time-budget).

        The 'lease' parameter is the lease being refreshed —
        passed explicitly so both daemon-mode FSM handlers (which
        read from 'self._lease') and sync-mode 'renew()' /
        'rebind()' (which take the lease as an argument) share
        the same wire-exchange method.
        """

        xid = random.randint(0, 0xFFFFFFFF)
        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("0.0.0.0", 68))
            target = "255.255.255.255" if broadcast else str(lease.server_id)
            client_socket.connect((target, 67))

            def _send() -> None:
                self._send_request_renew(
                    client_socket,
                    xid=xid,
                    ciaddr=lease.ip4_host.address,
                    broadcast=broadcast,
                )

            _send()
            result = self._recv_with_backoff(
                client_socket,
                expected_type=Dhcp4MessageType.ACK,
                xid=xid,
                resend=_send,
                allow_nak=True,
            )
        finally:
            client_socket.close()

        if isinstance(result, _NakRestart):
            return _NAK_RESTART
        if result is None:
            return None
        assert isinstance(result, Dhcp4Parser)

        # Validate the ACK and build a refreshed lease.
        if result.subnet_mask is None or result.lease_time is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>RENEW/REBIND ACK missing mandatory option; ignoring</>",
            )
            return None
        ip4_host = Ip4IfAddr((result.yiaddr, result.subnet_mask))
        t1_override, t2_override = self._extract_t1_t2_overrides(result, result.lease_time)
        return Dhcp4Lease(
            ip4_host=ip4_host,
            gateway=result.router[0] if result.router else None,
            classless_static_routes=result.classless_static_route,
            lease_time__sec=result.lease_time,
            server_id=result.server_id if result.server_id is not None else lease.server_id,
            acquired_at_monotonic=time.monotonic(),
            t1_override=t1_override,
            t2_override=t2_override,
        )

    def _consume_renew_or_rebind_outcome(
        self,
        outcome: "Dhcp4Lease | _NakRestart | None",
        /,
    ) -> None:
        """
        Apply the outcome of a RENEW or REBIND exchange. Refresh
        the lease + return to BOUND on success; fall back to
        INIT on NAK; stay in the current state on timeout (the
        next loop iteration re-checks the time-budget).
        """

        if isinstance(outcome, _NakRestart):
            __debug__ and log("dhcp4", "<WARN>DHCPNAK on RENEW/REBIND; restarting from DISCOVER</>")
            self._reset_to_init(remove_lease_host=True)
            return
        if outcome is None:
            # Timeout — stay in the current state; loop will
            # re-enter and check T2 / lease-expiry deadlines.
            return
        # Successful refresh — log under the renewal channel and
        # re-enter BOUND (no announce, no re-add via address_api
        # — same IP, lease just extended).
        assert isinstance(outcome, Dhcp4Lease)
        prior = self._lease
        assert prior is not None
        if prior.ip4_host.address == outcome.ip4_host.address:
            __debug__ and log(
                "dhcp4",
                f"<lg>Lease renewed</>: same IP retained "
                f"(lease_time={outcome.lease_time__sec}s, "
                f"next renewal in "
                f"~{int(outcome.lease_time__sec * dhcp4__constants.DHCP4__T1_FACTOR)}s)",
            )
            self._lease = outcome
            self._state = Dhcp4State.BOUND
            # Phase 6 — refresh the on-disk cache on every
            # successful same-IP RENEW/REBIND so the next-boot
            # DNAv4 probe has an up-to-date 'gateway_mac' and
            # 'acquired_at_wall'. The cache write is best-effort
            # (silently swallows OSError); skipping it would
            # leave the cache stale across long uptime spans.
            write_cached_lease(dhcp4__constants.DHCP4__LEASE_CACHE_PATH, outcome)
        else:
            # Cross-IP RENEW/REBIND: atomic 'replace' swap
            # via the address API. The 'abort_bound_sessions'
            # flag is sysctl-gated so operators can opt into
            # Linux-parity silent-rot behaviour
            # ('dhcp.abort_sessions_on_lease_change=0').
            __debug__ and log(
                "dhcp4",
                f"<lg>Lease swapped</>: {prior.ip4_host.address} → "
                f"{outcome.ip4_host.address} "
                f"(lease_time={outcome.lease_time__sec}s)",
            )
            if self._address_api is not None:
                self._address_api.replace(
                    old_address=prior.ip4_host.address,
                    new_ifaddr=outcome.ip4_host,
                    abort_bound_sessions=bool(
                        dhcp4__constants.DHCP4__ABORT_SESSIONS_ON_LEASE_CHANGE,
                    ),
                )
            # Move the RFC 5227 §2.4 defense claim to the new
            # address: drop the old claim's held socket and begin
            # defending the swapped-in address (announce + hold).
            if self._acd is not None:
                self._acd.release()
                self._acd.start_defense(address=outcome.ip4_host.address)
            self._lease = outcome
            self._state = Dhcp4State.BOUND

    def _reset_to_init(self, *, remove_lease_host: bool) -> None:
        """
        Return the FSM to INIT after a NAK or lease-loss event.
        Optionally remove the leased Ip4IfAddr via the address API
        (NAK case: the lease is invalid, abort sessions per the
        'dhcp.abort_sessions_on_lease_change' sysctl). Clears
        '_event__bound' so a subsequent 'start_and_wait_for_bind'
        watcher unblocks fresh on the next BOUND.
        """

        if remove_lease_host and self._lease is not None and self._address_api is not None:
            self._address_api.remove(
                address=self._lease.ip4_host.address,
                abort_bound_sessions=bool(
                    dhcp4__constants.DHCP4__ABORT_SESSIONS_ON_LEASE_CHANGE,
                ),
            )
        # Lease lost ⇒ the DHCP default route goes with it
        # (Linux drops the default on lease expiry / NAK). Guarded
        # independently of 'address_api' — the route plane and
        # address plane are separate Phase-3 surfaces.
        if remove_lease_host and self._lease is not None and self._route_api is not None:
            self._route_api.remove_default(family=AddressFamily.INET4)
            # Drop the lease's classless static routes (option 121)
            # alongside the default — they were installed on BOUND.
            self._remove_lease_routes(self._lease)
        # Phase 5 — purge the on-disk lease cache so the next
        # boot does not try INIT-REBOOT on an invalidated
        # lease. Always invalidate on the NAK / expiry paths,
        # regardless of whether the address was removed (a
        # server NAK invalidates the prior IP irrespective of
        # whether sync-mode fetch() owned the address).
        if remove_lease_host:
            delete_cached_lease(dhcp4__constants.DHCP4__LEASE_CACHE_PATH)
        # Drop the RFC 5227 §2.4 defense claim (closes the held ACD
        # socket). Idempotent — safe whether or not a claim was held
        # (sync 'fetch()' never starts defense; a NAK on RENEW does).
        if self._acd is not None:
            self._acd.release()
        self._lease = None
        self._state = Dhcp4State.INIT
        self._event__bound.clear()

    def _halt_ipv4_and_reset_to_init(self) -> None:
        """
        Lease-expiry handler: remove the address and re-enter
        INIT. The FSM's INIT handler will then try to acquire a
        fresh lease.
        """

        self._reset_to_init(remove_lease_host=True)

    def _handle_bound_conflict(self, peer_mac: MacAddress, /) -> None:
        """
        RFC 5227 §2.4 / RFC 2131 §3.1 ongoing-conflict handler for a
        BOUND DHCP address: a peer ('peer_mac') is using our leased
        IPv4 address. A DHCP-assigned address is the server's to give,
        so PyTCP yields it (the systemd-networkd / dhcpcd response) —
        send DHCPDECLINE to the leasing server, then drop the address
        (and the held ACD claim) and re-enter INIT to acquire a fresh
        lease.

        Reference: RFC 5227 §2.4 (host yields a claimed address on sustained conflict).
        Reference: RFC 2131 §3.1 step 5 (DHCPDECLINE then restart configuration).
        """

        assert self._lease is not None
        __debug__ and log(
            "dhcp4",
            f"<WARN>ACD reported ongoing conflict on leased "
            f"{self._lease.ip4_host.address} from {peer_mac}; "
            f"declining and re-acquiring</>",
        )
        self._decline_leased_address(
            address=self._lease.ip4_host.address,
            server_id=self._lease.server_id,
        )
        self._reset_to_init(remove_lease_host=True)

    def _decline_leased_address(self, *, address: Ip4Address, server_id: Ip4Address) -> None:
        """
        Open a one-shot UDP socket and emit a single DHCPDECLINE for a
        previously-BOUND address whose ACD detected an ongoing
        conflict (RFC 2131 §3.1 step 5). Unlike the INIT-path decline,
        there is no in-flight DISCOVER socket to reuse, so this opens
        and tears down its own. Best-effort — a socket error must not
        block the abandon-and-reacquire path.
        """

        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect((str(server_id), 67))
            self._send_decline(
                client_socket,
                xid=random.randint(0, 0xFFFFFFFF),
                srv_id=server_id,
                yiaddr=address,
            )
        except OSError as error:
            __debug__ and log(
                "dhcp4",
                f"<WARN>DHCPDECLINE on BOUND conflict raised {type(error).__name__}: {error}</>",
            )
        finally:
            client_socket.close()

    # ------------------------------------------------------------
    # RFC 2131 §4.4.2 INIT-REBOOT (Phase 5)
    # ------------------------------------------------------------

    def _do_init_reboot(self) -> None:
        """
        INIT-REBOOT-state handler. Opens a one-shot UDP socket,
        broadcasts a REQUEST asking the leasing server to
        re-confirm the cached IP per RFC 2131 §4.3.2 Table 4
        (ciaddr=0, requested-ip=cached, NO server-id), waits for
        the ACK / NAK / timeout. On ACK transitions to BOUND with
        the server-confirmed lease. On NAK invalidates the cache
        and falls back to INIT (§4.4.2 second-to-last paragraph).
        On timeout (60 s / 4 tries default), MAY adopt the cached
        lease as-is per the §4.4.2 last paragraph; PyTCP takes
        the MAY since the operator's deliberate '_lease_cache_path'
        setting signals they want fast boot even when the server
        is unreachable.
        """

        assert self._lease is not None, "INIT-REBOOT entered without a cached lease"
        cached = self._lease

        # Phase 6 — RFC 4436 DNAv4 fast-path. When enabled and
        # the cache recorded the gateway's link-layer address,
        # send a unicast ARP probe; if the gateway answers
        # within 'dhcp.dnav4_timeout_ms', the host is on the
        # same L2 segment as before and the cached lease is
        # adopted as-is, skipping the DHCP wire exchange
        # entirely. On miss / disabled, fall through to the
        # standard RFC 2131 §4.4.2 INIT-REBOOT REQUEST.
        if self._dnav4_probe(cached):
            __debug__ and log(
                "dhcp4",
                f"<lg>DNAv4 succeeded</>: cached gateway "
                f"{cached.gateway} answered; adopting "
                f"{cached.ip4_host} without DHCP traffic",
            )
            self._on_bound(cached)
            return

        xid = random.randint(0, 0xFFFFFFFF)
        self._fetch_started_at_monotonic = time.monotonic()
        __debug__ and log(
            "dhcp4",
            f"INIT-REBOOT: requesting cached {cached.ip4_host.address}",
        )

        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect(("255.255.255.255", 67))

            def _send() -> None:
                self._send_request_init_reboot(
                    client_socket,
                    xid=xid,
                    requested_ip=cached.ip4_host.address,
                )

            _send()
            # Phase 5: clamp the recv attempts to
            # 'dhcp.reboot_max_attempts' (default 4) so the
            # INIT-REBOOT window stays close to the RFC's 60-
            # second budget regardless of how the operator has
            # tuned the standard retransmission budget.
            attempts_prior = dhcp4__constants.DHCP4__RETRANS_MAX_ATTEMPTS
            from pytcp.stack import sysctl as sysctl_module

            with sysctl_module.override(
                "dhcp.retrans_max_attempts",
                min(attempts_prior, dhcp4__constants.DHCP4__REBOOT_MAX_ATTEMPTS),
            ):
                result = self._recv_with_backoff(
                    client_socket,
                    expected_type=Dhcp4MessageType.ACK,
                    xid=xid,
                    resend=_send,
                    allow_nak=True,
                )
        finally:
            client_socket.close()

        if isinstance(result, _NakRestart):
            __debug__ and log(
                "dhcp4",
                "<WARN>INIT-REBOOT NAK; falling back to DISCOVER</>",
            )
            self._reset_to_init(remove_lease_host=True)
            return

        if result is None:
            # RFC 2131 §4.4.2 last paragraph MAY — adopt the
            # cached lease as-is. The lease's
            # 'acquired_at_monotonic' was anchored against the
            # cache's wall-clock age, so the T1/T2/expiry
            # deadlines still line up with the original
            # acquisition time.
            __debug__ and log(
                "dhcp4",
                f"<lg>INIT-REBOOT silent server; adopting cached lease "
                f"{cached.ip4_host} as-is (RFC 2131 §4.4.2 MAY)</>",
            )
            self._on_bound(cached)
            return

        assert isinstance(result, Dhcp4Parser)
        if result.subnet_mask is None or result.lease_time is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>INIT-REBOOT ACK missing mandatory option; " "falling back to DISCOVER</>",
            )
            self._reset_to_init(remove_lease_host=True)
            return

        ip4_host = Ip4IfAddr((result.yiaddr, result.subnet_mask))
        t1_override, t2_override = self._extract_t1_t2_overrides(result, result.lease_time)
        refreshed = Dhcp4Lease(
            ip4_host=ip4_host,
            gateway=result.router[0] if result.router else None,
            classless_static_routes=result.classless_static_route,
            lease_time__sec=result.lease_time,
            server_id=(result.server_id if result.server_id is not None else cached.server_id),
            acquired_at_monotonic=time.monotonic(),
            t1_override=t1_override,
            t2_override=t2_override,
        )
        __debug__ and log(
            "dhcp4",
            f"<lg>INIT-REBOOT confirmed</>: {refreshed.ip4_host} "
            f"(lease_time={refreshed.lease_time__sec}s, "
            f"server={refreshed.server_id})",
        )
        self._on_bound(refreshed)

    def _send_request_init_reboot(
        self,
        client_socket: socket,
        *,
        xid: int,
        requested_ip: Ip4Address,
    ) -> None:
        """
        Build and send the INIT-REBOOT DHCPREQUEST per RFC 2131
        §4.3.2 Table 4 — ciaddr=0, requested-ip=cached IP, NO
        server-id, broadcast flag set so the server can reply
        even though the client has not yet bound the cached
        address on its IPv4 stack.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.REQUEST),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionMaxMsgSize(dhcp4__constants.DHCP4__MAX_MSG_SIZE),
                Dhcp4OptionReqIpAddr(requested_ip),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _dnav4_probe(self, lease: Dhcp4Lease, /) -> bool:
        """
        RFC 4436 DNAv4 unicast ARP probe. Returns True if the
        cached gateway answers a unicast ARP Request within the
        configured 'dhcp.dnav4_timeout_ms' window — proving the
        host is on the same L2 segment and the gateway is the
        same physical device, so the cached lease can be adopted
        without further DHCP traffic.

        Returns False unconditionally when:
          - 'dhcp.dnav4' is 0 (operator override);
          - the cached lease has no gateway (point-to-point or
            link-local-only configuration);
          - the cached lease has no recorded gateway_mac (first
            boot after a cold cache write; the gateway had not
            yet been resolved by ordinary traffic);
          - no interface egresses toward the gateway, or that
            interface has no ARP cache (sync-mode 'fetch()'
            invocations from tests, before 'stack.init()').

        On a True return the caller should adopt 'lease' as-is
        via '_on_bound(lease)' and skip the DHCP exchange. On a
        False return the caller falls through to the standard
        RFC 2131 §4.4.2 INIT-REBOOT REQUEST.
        """

        if not dhcp4__constants.DHCP4__DNAV4:
            return False
        if lease.gateway is None or lease.gateway_mac is None:
            return False
        # The ACD engine is the client's raw-link ARP surface (the same
        # AF_PACKET socket the §2.1.1 Probe uses). It is None in sync-mode
        # 'fetch()' (no interface engine wired) or on an L3 (TUN) egress
        # with no ARP — DNAv4 is moot in both, so fall through.
        if self._acd is None:
            return False

        timeout_s = dhcp4__constants.DHCP4__DNAV4_TIMEOUT_MS / 1000.0
        try:
            # RFC 4436 §4.3 — the sender protocol address (ar$spa) MUST be
            # the candidate IPv4 address. Pass the cached lease's host IP
            # explicitly; at INIT-REBOOT it is not yet assigned to the
            # interface, and an spa of 0.0.0.0 would be an RFC 5227 §1.1
            # ACD Probe, not a DNAv4 reachability probe. The reply is read
            # off the ACD socket, so the stack's ARP cache / ARP-TX path
            # is uninvolved.
            reachable = self._acd.probe_reachable(
                target=lease.gateway,
                target_mac=lease.gateway_mac,
                sender=lease.ip4_host.address,
                timeout=timeout_s,
            )
        except OSError as error:  # defensive against a raw-socket failure
            __debug__ and log(
                "dhcp4",
                f"<WARN>DNAv4 unicast ARP probe failed: {error}; falling through to INIT-REBOOT</>",
            )
            return False

        if not reachable:
            __debug__ and log(
                "dhcp4",
                f"<WARN>DNAv4: cached gateway {lease.gateway} "
                f"did not answer within {dhcp4__constants.DHCP4__DNAV4_TIMEOUT_MS} ms; "
                f"falling through to INIT-REBOOT</>",
            )
        return reachable

    def _send_request_renew(
        self,
        client_socket: socket,
        *,
        xid: int,
        ciaddr: Ip4Address,
        broadcast: bool,
    ) -> None:
        """
        Build and send a RENEWING / REBINDING DHCPREQUEST per
        RFC 2131 §4.3.2 Table 4: 'ciaddr' = current IPv4
        address, NO 'server identifier' option, NO 'requested
        IP address' option. 'broadcast=False' for RENEW (unicast
        UDP to the leasing server), True for REBIND (broadcast).
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=broadcast,
            dhcp4__ciaddr=ciaddr,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.REQUEST),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionMaxMsgSize(dhcp4__constants.DHCP4__MAX_MSG_SIZE),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _send_release(
        self,
        client_socket: socket,
        *,
        lease: Dhcp4Lease,
        xid: int,
    ) -> None:
        """
        Build and send a DHCPRELEASE packet per RFC 2131 §4.4.6.
        ciaddr = current IPv4 address; carries Server Identifier
        (option 54) and Client Identifier; no reply expected
        from the server (RELEASE is fire-and-forget).
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__flag_b=False,
            dhcp4__ciaddr=lease.ip4_host.address,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.RELEASE),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionServerId(lease.server_id),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    # ------------------------------------------------------------
    # Phase 4 commit D — public sync 'release' / 'renew' / 'rebind'
    # ------------------------------------------------------------

    def release(self, lease: Dhcp4Lease, /) -> None:
        """
        Synchronous one-shot DHCPRELEASE — emits a single
        RELEASE message to the server that issued 'lease' and
        tears down the socket. No reply is expected
        (RFC 2131 §4.4.6). The FSM state is not mutated; this
        is a fire-and-forget convenience for operator CLI tools
        and tests (Linux 'dhclient -r' / 'dhcpcd -k' equivalent).
        """

        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect((str(lease.server_id), 67))
            self._send_release(
                client_socket,
                lease=lease,
                xid=random.randint(0, 0xFFFFFFFF),
            )
        finally:
            client_socket.close()

    def renew(self, lease: Dhcp4Lease, /) -> Dhcp4Lease | None:
        """
        Synchronous one-shot DHCPRENEW — unicast REQUEST to the
        leasing server, wait for ACK, return the refreshed
        'Dhcp4Lease'. Returns None on NAK, timeout, or other
        failure. The FSM state is not mutated. Linux 'dhcpcd -n'
        equivalent.
        """

        outcome = self._do_renew_or_rebind_exchange(lease=lease, broadcast=False)
        return outcome if isinstance(outcome, Dhcp4Lease) else None

    def rebind(self, lease: Dhcp4Lease, /) -> Dhcp4Lease | None:
        """
        Synchronous one-shot DHCPREBIND — broadcast REQUEST,
        wait for ACK from any DHCP server, return the refreshed
        'Dhcp4Lease'. Returns None on NAK, timeout, or other
        failure. The FSM state is not mutated.
        """

        outcome = self._do_renew_or_rebind_exchange(lease=lease, broadcast=True)
        return outcome if isinstance(outcome, Dhcp4Lease) else None

    # ------------------------------------------------------------
    # Subsystem hook — emit DHCPRELEASE on graceful shutdown
    # ------------------------------------------------------------

    @override
    def _stop(self) -> None:
        """
        Subsystem post-stop hook. Runs after the FSM thread has
        joined. If the FSM was BOUND at stop time, emit a
        DHCPRELEASE for the held lease (RFC 2131 §4.4.6 SHOULD)
        and remove the address via the address API (the
        'dhcp.abort_sessions_on_lease_change' sysctl gates the
        active TCP-session abort).
        """

        if self._state == Dhcp4State.BOUND and self._lease is not None:
            try:
                self.release(self._lease)
            except OSError as error:
                # Don't let a socket error in the
                # release-on-shutdown path block the rest of
                # the stack-stop sequence. Log and continue.
                __debug__ and log(
                    "dhcp4",
                    f"<WARN>DHCPRELEASE on shutdown raised {type(error).__name__}: {error}</>",
                )
            if self._address_api is not None:
                self._address_api.remove(
                    address=self._lease.ip4_host.address,
                    abort_bound_sessions=bool(
                        dhcp4__constants.DHCP4__ABORT_SESSIONS_ON_LEASE_CHANGE,
                    ),
                )
            # RELEASE on shutdown ⇒ drop the DHCP default route
            # too (same plane-separation rationale as
            # '_reset_to_init').
            if self._route_api is not None:
                self._route_api.remove_default(family=AddressFamily.INET4)
            # Drop the RFC 5227 §2.4 defense claim (closes the held
            # ACD socket) so shutdown leaves no dangling AF_PACKET fd.
            if self._acd is not None:
                self._acd.release()

    def _do_init_to_bound(self) -> Dhcp4Lease | None:
        """
        Run one INIT → SELECTING → REQUESTING → BOUND cycle.
        Shared by sync 'fetch()' and daemon-mode
        '_subsystem_loop' INIT handler.

        Begins with an RFC 2131 §4.4.1 startup desynchronisation
        delay (random uniform in 'dhcp.init_delay_{min,max}_ms')
        so a fleet of hosts powered on simultaneously does not
        all DISCOVER at the same instant. The delay is bypassed
        entirely when both bounds are 0 — the canonical
        disable-for-tests configuration.

        On a DHCPNAK to the REQUEST, restart from DISCOVER up to
        'dhcp.nak_max_restarts' times before giving up. Every
        recv wait runs under the RFC 2131 §4.1 retransmission
        backoff (initial / max / attempts / jitter all
        sysctl-tunable).
        """

        self._initial_delay()
        self._fetch_started_at_monotonic = time.monotonic()
        __debug__ and log(
            "dhcp4",
            f"Starting DHCPv4 acquisition (mac={self._mac_address})",
        )

        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("0.0.0.0", 68))
            client_socket.connect(("255.255.255.255", 67))

            for _ in range(dhcp4__constants.DHCP4__NAK_MAX_RESTARTS + 1):
                outcome = self._discover_request_once(client_socket)
                if not isinstance(outcome, _NakRestart):
                    if isinstance(outcome, Dhcp4Lease):
                        __debug__ and log(
                            "dhcp4",
                            f"<lg>Lease acquired</>: {outcome.ip4_host} "
                            f"(lease_time={outcome.lease_time__sec}s, "
                            f"server={outcome.server_id})",
                        )
                    else:
                        __debug__ and log(
                            "dhcp4",
                            "<WARN>DHCPv4 acquisition failed (see earlier " "warnings for cause)</>",
                        )
                    return outcome
            __debug__ and log(
                "dhcp4",
                "<WARN>DHCPv4 acquisition failed: NAK restart budget " "exhausted</>",
            )
            return None
        finally:
            client_socket.close()

    def _discover_request_once(self, client_socket: socket) -> Dhcp4Lease | _NakRestart | None:
        """
        Run a single DISCOVER/OFFER/REQUEST/ACK round-trip with
        retransmission backoff on each recv leg.

        Returns a 'Dhcp4Lease' on success, '_NAK_RESTART' on DHCPNAK
        (caller restarts from DISCOVER), or None on any hard failure
        (silence across the backoff window, mismatched xid/CID,
        wrong message type, missing mandatory option).
        """

        xid = random.randint(0, 0xFFFFFFFF)

        self._send_discover(client_socket, xid=xid)
        offer = self._recv_with_backoff(
            client_socket,
            expected_type=Dhcp4MessageType.OFFER,
            xid=xid,
            resend=lambda: self._send_discover(client_socket, xid=xid),
        )
        if offer is None:
            return None
        # 'allow_nak' defaults to False on the OFFER leg, so a NAK
        # would have been treated as 'wrong message type' and dropped
        # — narrow to 'Dhcp4Parser' for downstream attribute access.
        assert isinstance(offer, Dhcp4Parser)

        # RFC 2131 §4.4.1 multi-OFFER collection window — after the
        # first valid OFFER, listen briefly for additional OFFERs
        # so the operator's log captures the full auction. The first
        # OFFER remains the selection (dhcpcd / ISC dhclient-alike).
        # Setting 'dhcp.offer_collection_ms' to 0 disables the
        # window — the RFC's "e.g. the first DHCPOFFER message"
        # path is strictly compliant in that mode.
        self._collect_additional_offers(client_socket, xid=xid, first_offer=offer)

        srv_id = offer.server_id
        if srv_id is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Offer message - missing server identifier</>",
            )
            return None
        yiaddr = offer.yiaddr

        self._send_request(client_socket, xid=xid, srv_id=srv_id, yiaddr=yiaddr)
        ack = self._recv_with_backoff(
            client_socket,
            expected_type=Dhcp4MessageType.ACK,
            xid=xid,
            resend=lambda: self._send_request(client_socket, xid=xid, srv_id=srv_id, yiaddr=yiaddr),
            allow_nak=True,
        )
        if isinstance(ack, _NakRestart):
            return _NAK_RESTART
        if ack is None:
            return None
        # 'allow_nak' was True on the ACK leg, but the NAK case was
        # handled by the 'isinstance' branch above — narrow to
        # 'Dhcp4Parser' for downstream attribute access.
        assert isinstance(ack, Dhcp4Parser)

        if ack.subnet_mask is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Ack message - missing subnet mask</>",
            )
            return None

        if ack.lease_time is None:
            __debug__ and log(
                "dhcp4",
                "<WARN>Didn't receive DHCP Ack message - missing IP address lease time</>",
            )
            return None

        ip4_host = Ip4IfAddr((ack.yiaddr, ack.subnet_mask))

        # RFC 2131 §3.1 step 5 — probe the offered address before
        # claiming it. On conflict, emit DHCPDECLINE, wait at
        # least 10 s, and restart from DISCOVER via the same
        # outer-loop sentinel used by the NAK path. The probe runs
        # over the userspace RFC 5227 ACD engine ('acd.probe'); the
        # daemon-mode BOUND transition later begins ongoing defense
        # of the committed address via 'acd.start_defense'.
        if self._acd is not None and not self._acd.probe(address=ip4_host.address).success:
            __debug__ and log(
                "dhcp4",
                f"<WARN>ARP DAD reported conflict on {ip4_host.address}; sending DHCPDECLINE</>",
            )
            self._send_decline(
                client_socket,
                xid=xid,
                srv_id=srv_id,
                yiaddr=ip4_host.address,
            )
            backoff_s = dhcp4__constants.DHCP4__DECLINE_BACKOFF_MS / 1000.0
            if backoff_s > 0:
                time.sleep(backoff_s)
            return _NAK_RESTART

        t1_override, t2_override = self._extract_t1_t2_overrides(ack, ack.lease_time)
        return Dhcp4Lease(
            ip4_host=ip4_host,
            gateway=ack.router[0] if ack.router else None,
            classless_static_routes=ack.classless_static_route,
            lease_time__sec=ack.lease_time,
            server_id=srv_id,
            acquired_at_monotonic=time.monotonic(),
            t1_override=t1_override,
            t2_override=t2_override,
        )

    def _recv_with_backoff(
        self,
        client_socket: socket,
        *,
        expected_type: Dhcp4MessageType,
        xid: int,
        resend: "Callable[[], None]",  # noqa: F821 — typing alias defined below
        allow_nak: bool = False,
    ) -> "Dhcp4Parser | _NakRestart | None":
        """
        Wait for an inbound DHCP message of 'expected_type' using the
        RFC 2131 §4.1 retransmission backoff. On each per-attempt
        timeout the caller-provided 'resend' callback retransmits the
        prior TX and the delay doubles (capped at
        'dhcp.retrans_max_ms'). Returns the parsed message on
        success, '_NAK_RESTART' if a NAK arrives and 'allow_nak' is
        True, or None when the attempt budget is exhausted.

        Bogus inbound packets (malformed, mismatched xid, mismatched
        CID echo, wrong message type) are silently dropped without
        burning the current attempt's wait window — the loop keeps
        listening until the monotonic deadline expires.
        """

        delay_ms = dhcp4__constants.DHCP4__RETRANS_INITIAL_MS
        max_ms = dhcp4__constants.DHCP4__RETRANS_MAX_MS
        max_attempts = dhcp4__constants.DHCP4__RETRANS_MAX_ATTEMPTS
        jitter_ms = dhcp4__constants.DHCP4__RETRANS_JITTER_MS

        for attempt in range(max_attempts):
            jitter_s = random.uniform(-jitter_ms / 1000.0, jitter_ms / 1000.0)
            timeout_s = max(0.001, delay_ms / 1000.0 + jitter_s)
            result = self._recv_within_window(
                client_socket,
                expected_type=expected_type,
                xid=xid,
                timeout_s=timeout_s,
                allow_nak=allow_nak,
            )
            if result is not None:
                return result
            if attempt < max_attempts - 1:
                __debug__ and log(
                    "dhcp4",
                    f"recv window expired ({timeout_s:.2f}s); retransmitting "
                    f"(attempt {attempt + 2} of {max_attempts})",
                )
                resend()
                delay_ms = min(delay_ms * 2, max_ms)
        return None

    def _recv_within_window(
        self,
        client_socket: socket,
        *,
        expected_type: Dhcp4MessageType,
        xid: int,
        timeout_s: float,
        allow_nak: bool,
    ) -> "Dhcp4Parser | _NakRestart | None":
        """
        Wait up to 'timeout_s' seconds for a valid DHCP message,
        silently dropping bogus packets (malformed, wrong type, bad
        xid, bad CID echo) without consuming the entire window.
        Returns the parsed message on success, '_NAK_RESTART' on a
        valid NAK if 'allow_nak' is True, or None if the deadline
        elapses with no valid response.

        The first 'recv__mv' call uses 'timeout_s' directly so the
        caller's intended window value reaches the socket layer
        verbatim; subsequent iterations (only entered after dropping
        a bogus packet) compute the remaining budget against a
        monotonic deadline anchored at the start of the window.
        """

        deadline = time.monotonic() + timeout_s
        remaining = timeout_s
        first_iter = True
        while True:
            if not first_iter:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
            first_iter = False
            try:
                packet = Dhcp4Parser(client_socket.recv__mv(timeout=remaining))
            except TimeoutError:
                return None
            except Dhcp4IntegrityError, Dhcp4SanityError:
                __debug__ and log(
                    "dhcp4",
                    "<WARN>Dropping malformed inbound DHCP frame; continuing wait window</>",
                )
                continue
            __debug__ and log("dhcp4", f"<lg>RX</> - {packet}")

            if allow_nak and packet.message_type == Dhcp4MessageType.NAK:
                if packet.xid != xid or not self._cid_echo_ok(packet):
                    __debug__ and log(
                        "dhcp4",
                        "<WARN>Dropping NAK with mismatched xid or CID echo</>",
                    )
                    continue
                __debug__ and log("dhcp4", "DHCP NAK received - restarting from DISCOVER")
                return _NAK_RESTART

            if packet.message_type != expected_type:
                __debug__ and log(
                    "dhcp4",
                    f"<WARN>Dropping DHCP frame with unexpected message type "
                    f"{packet.message_type!r}; expected {expected_type!r}</>",
                )
                continue
            if packet.xid != xid:
                __debug__ and log(
                    "dhcp4",
                    f"<WARN>Dropping DHCP frame with mismatched xid " f"(sent={xid:#010x}, got={packet.xid:#010x})</>",
                )
                continue
            if not self._cid_echo_ok(packet):
                __debug__ and log(
                    "dhcp4",
                    "<WARN>Dropping DHCP frame with mismatched Client Identifier echo</>",
                )
                continue

            return packet

    def _collect_additional_offers(
        self,
        client_socket: socket,
        *,
        xid: int,
        first_offer: Dhcp4Parser,
    ) -> None:
        """
        RFC 2131 §4.4.1 multi-OFFER collection window. After the
        first valid DHCPOFFER, keep listening for additional
        OFFERs for 'dhcp.offer_collection_ms' milliseconds, then
        return without changing the selection. The first OFFER
        stays selected — the dhcpcd / ISC dhclient policy —
        while the window gives the operator log visibility into
        the full auction (which DHCP servers responded and how
        fast).

        Mismatched xid / CID / wrong-type frames are silently
        dropped by '_recv_within_window' as in the rest of the
        FSM; bogus packets do not extend or shorten the window.
        Setting the sysctl to 0 short-circuits to a no-op — the
        RFC 2131 §4.4.1 "e.g. the first DHCPOFFER message" path.
        """

        window_ms = dhcp4__constants.DHCP4__OFFER_COLLECTION_MS
        if window_ms <= 0:
            return

        __debug__ and log(
            "dhcp4",
            f"<lg>OFFER from {first_offer.server_id}</> selected; " f"collecting additional OFFERs for {window_ms} ms",
        )

        deadline = time.monotonic() + window_ms / 1000.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            result = self._recv_within_window(
                client_socket,
                expected_type=Dhcp4MessageType.OFFER,
                xid=xid,
                timeout_s=remaining,
                allow_nak=False,
            )
            if result is None:
                # Window expired before another OFFER arrived.
                return
            assert isinstance(result, Dhcp4Parser)
            __debug__ and log(
                "dhcp4",
                f"<lg>OFFER from {result.server_id}</> received "
                f"during collection window; ignored (first OFFER retained)",
            )

    def _open_client_socket(self) -> socket:
        """
        Open the UDP socket used for a DHCPv4 exchange, pinned to this
        client's interface via SO_BINDTODEVICE when known. The pin makes
        the pre-lease limited-broadcast (255.255.255.255) egress
        unambiguous on a multi-homed host, where the FIB cannot pick a
        single egress for the all-ones destination.
        """

        client_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        if self._interface_name is not None:
            client_socket.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, self._interface_name.encode())
        # The DHCPv4 INIT / REBINDING / REBOOT egress targets the
        # IPv4 limited broadcast '255.255.255.255' (RFC 2131 §4.1).
        # The H5 SO_BROADCAST gate in 'UdpSocket.send' / 'sendto'
        # refuses unflagged broadcasts with EACCES; mark the client
        # socket as broadcast-permitted at construction so every
        # pre-lease send path is gate-clean.
        client_socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        return client_socket

    def _send_discover(self, client_socket: socket, *, xid: int) -> None:
        """
        Build and send the DHCP DISCOVER packet.
        """

        # Phase 8.2 — emit a Lease Time hint when the operator
        # configured one (default 86400 = 1 day; set 0 to omit).
        lease_time_hint = dhcp4__constants.DHCP4__REQUESTED_LEASE_TIME__SEC
        opts: list[Dhcp4Option] = [
            Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DISCOVER),
            Dhcp4OptionClientId(self._expected_client_id),
            Dhcp4OptionParamReqList(
                [
                    Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                    Dhcp4OptionType.SUBNET_MASK,
                    Dhcp4OptionType.ROUTER,
                ]
            ),
            # Phase 8.1 — Maximum DHCP Message Size advertised
            # so the server may use the full interface MTU.
            Dhcp4OptionMaxMsgSize(dhcp4__constants.DHCP4__MAX_MSG_SIZE),
            Dhcp4OptionHostName("PyTCP"),
        ]
        if lease_time_hint > 0:
            opts.append(Dhcp4OptionLeaseTime(lease_time_hint))
        opts.append(Dhcp4OptionEnd())

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(*opts),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _send_request(
        self,
        client_socket: socket,
        *,
        xid: int,
        srv_id: Ip4Address,
        yiaddr: Ip4Address,
    ) -> None:
        """
        Build and send the DHCP REQUEST packet.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.REQUEST),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,
                        Dhcp4OptionType.SUBNET_MASK,
                        Dhcp4OptionType.ROUTER,
                    ]
                ),
                Dhcp4OptionMaxMsgSize(dhcp4__constants.DHCP4__MAX_MSG_SIZE),
                Dhcp4OptionServerId(srv_id),
                Dhcp4OptionReqIpAddr(yiaddr),
                Dhcp4OptionHostName("PyTCP"),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _send_decline(
        self,
        client_socket: socket,
        *,
        xid: int,
        srv_id: Ip4Address,
        yiaddr: Ip4Address,
    ) -> None:
        """
        Build and send the DHCPDECLINE packet per RFC 2131 §3.1 step
        5. The DECLINE carries Server Identifier (option 54) and
        Requested IP Address (option 50) identifying the rejected
        offer, plus the Client Identifier (RFC 2131 §2 / RFC 6842
        §3). 'ciaddr' is 0 because the address has not been
        claimed.
        """

        dhcp4_packet_tx = Dhcp4Assembler(
            dhcp4__operation=Dhcp4Operation.REQUEST,
            dhcp4__xid=xid,
            dhcp4__secs=self._elapsed_secs(),
            dhcp4__flag_b=True,
            dhcp4__chaddr=self._mac_address,
            dhcp4__options=Dhcp4Options(
                Dhcp4OptionMessageType(message_type=Dhcp4MessageType.DECLINE),
                Dhcp4OptionClientId(self._expected_client_id),
                Dhcp4OptionServerId(srv_id),
                Dhcp4OptionReqIpAddr(yiaddr),
                Dhcp4OptionEnd(),
            ),
        )
        __debug__ and log("dhcp4", f"<lr>TX</> - {dhcp4_packet_tx}")
        client_socket.send(bytes(dhcp4_packet_tx))

    def _initial_delay(self) -> None:
        """
        Sleep for an RFC 2131 §4.4.1 startup desynchronisation
        delay drawn uniformly from
        '[dhcp.init_delay_min_ms, dhcp.init_delay_max_ms]'.
        Bypassed when 'init_delay_max_ms' is 0 — the canonical
        disable-for-tests configuration.
        """

        max_ms = dhcp4__constants.DHCP4__INIT_DELAY_MAX_MS
        if max_ms == 0:
            return
        min_ms = dhcp4__constants.DHCP4__INIT_DELAY_MIN_MS
        delay_s = random.uniform(min_ms / 1000.0, max_ms / 1000.0)
        __debug__ and log("dhcp4", f"Initial desync delay: {delay_s:.2f}s")
        time.sleep(delay_s)

    def _elapsed_secs(self) -> int:
        """
        Compute the DHCP header 'secs' field per RFC 1542 §3.2 —
        seconds elapsed since the client began the address-
        acquisition process. Capped at UINT16_MAX so a long-running
        restart loop cannot overflow the 16-bit field.
        """

        return min(
            _DHCP4__SECS_MAX,
            max(0, int(time.monotonic() - self._fetch_started_at_monotonic)),
        )

    def _cid_echo_ok(self, packet: Dhcp4Parser) -> bool:
        """
        Validate the Client Identifier echo per RFC 6842 §3 — when the
        server echoes the CID option, the value MUST match what the
        client emitted. An absent echo is acceptable (RFC 6842 says
        "if the client identifier option is present").
        """

        echoed = packet.client_id
        return echoed is None or echoed == self._expected_client_id
