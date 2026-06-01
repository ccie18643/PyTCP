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
This module contains the DHCPv6 (RFC 8415) client — the stateless
INFORMATION-REQUEST exchange (other-config: DNS, etc.) and the
stateful SOLICIT / ADVERTISE / REQUEST / REPLY exchange that leases a
non-temporary address (IA_NA). The leased address is handed to the
caller as a 'Dhcp6Lease'; the Address-API assignment + lease lifecycle
land in a later phase.

pytcp/protocols/dhcp6/dhcp6__client.py

ver 3.0.8
"""

import math
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, override

from net_addr import Ip6Address, Ip6IfAddr, MacAddress
from net_proto import (
    Dhcp6Assembler,
    Dhcp6IntegrityError,
    Dhcp6MessageType,
    Dhcp6OptionClientId,
    Dhcp6OptionElapsedTime,
    Dhcp6OptionIaAddr,
    Dhcp6OptionIaNa,
    Dhcp6OptionOro,
    Dhcp6OptionRapidCommit,
    Dhcp6Options,
    Dhcp6OptionServerId,
    Dhcp6OptionType,
    Dhcp6Parser,
    Dhcp6SanityError,
    Dhcp6StatusCode,
)
from pytcp.lib.logger import log
from pytcp.protocols.dhcp6 import dhcp6__constants
from pytcp.protocols.dhcp6.dhcp6__uid import get_client_duid, get_iaid
from pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem
from pytcp.socket import (
    AF_INET6,
    SO_BINDTODEVICE,
    SOCK_DGRAM,
    SOL_SOCKET,
    socket,
)

if TYPE_CHECKING:
    from pytcp.stack.address import AddressApi

# RFC 8415 §8 — the transaction-id is a 24-bit field.
_DHCP6__XID_MAX = 0xFFFFFF

# RFC 8415 §7.5 / §21.6 — a lifetime / timer field of 0xFFFFFFFF means
# "infinity": the address never expires and the corresponding timer
# never fires. T1 / T2 = 0 instead means "the server defers the choice
# to the client" (derived from the preferred lifetime via the factors).
_DHCP6__LIFETIME_INFINITY = 0xFFFFFFFF

# RFC 8415 carries no prefix length in the IA Address option; the
# on-link prefix is learned from Router Advertisements, so a leased
# address is installed as a /128 host (matching Linux dhclient -6 and
# systemd-networkd, which assign DHCPv6 addresses as /128).
_DHCP6__LEASE_PREFIX_LEN = 128


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6StatelessConfig:
    """
    The RFC 8415 §18.2.6 "other configuration" returned by a
    stateless INFORMATION-REQUEST exchange. Carries only the
    non-address parameters a stateless client asks for; today that
    is the DNS recursive name-server list (RFC 3646).
    """

    dns_servers: list[Ip6Address] = field(default_factory=list)


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp6Lease:
    """
    A negotiated DHCPv6 non-temporary-address (IA_NA) lease — the
    assigned address + its preferred / valid lifetimes, plus the
    IA_NA T1 / T2 renewal timers, the IAID, and the issuing server's
    DUID. DHCPv6 carries no prefix length in the IA Address option;
    the on-link prefix is learned from Router Advertisements, so the
    Address-API assignment installs the leased address as a /128 host.
    """

    address: Ip6Address
    preferred_lifetime: int
    valid_lifetime: int
    t1: int
    t2: int
    iaid: int
    server_duid: bytes


class Dhcp6Client(Subsystem):
    """
    DHCPv6 client (RFC 8415).

    Two invocation modes:

      - Sync: 'fetch_other_config()' / 'acquire_lease()' run one
        exchange inline in the caller's thread and return the result.
        The 'Subsystem' machinery is not engaged. Used by tests and
        operator CLI tools.
      - Daemon: 'start()' spawns the 'Subsystem' worker thread which
        blocks on a trigger 'Event'; the RA RX handler calls
        'trigger(managed=..., other=...)' on receipt of a Router
        Advertisement with the Managed / Other-config flags set, and
        the worker runs the stateful ('managed') or stateless
        ('other') exchange. Used by 'stack.start()' in production.

    Both exchanges share the §15 retransmission backoff and the
    inbound-frame validation in '_run_exchange' / '_recv_within_window'.
    """

    _subsystem_name = "DHCP6 Client"

    def __init__(
        self,
        *,
        mac_address: MacAddress,
        interface_name: str | None = None,
        address_api: "AddressApi | None" = None,
    ) -> None:
        """
        Initialize the DHCPv6 client.

        The optional 'address_api' is the kernel/userspace Address-API
        boundary used to install a leased address. When None (the
        sync / test default) 'acquire_lease()' returns the lease
        without touching the interface's address set.
        """

        super().__init__()

        self._mac_address = mac_address
        self._interface_name = interface_name
        self._address_api = address_api

        # Trigger state. 'trigger()' (RX thread) sets the pending
        # config-mode flags under '_lock__trigger' and wakes the worker
        # via '_event__trigger'; the worker reads + clears them. The
        # lease + debounce state ('_lease' / '_other_acquired') and the
        # T1 / T2 / valid deadlines are worker-only — read and written
        # solely from the '_subsystem_loop' thread (sync-mode callers do
        # not engage the loop) so they need no lock.
        self._event__trigger = threading.Event()
        self._lock__trigger = threading.Lock()
        self._pending_managed = False
        self._pending_other = False
        self._pending_decline_address: Ip6Address | None = None
        self._lease: Dhcp6Lease | None = None
        self._other_acquired = False

        # Monotonic deadlines for the BOUND lease lifecycle, armed by
        # '_arm_timers' whenever a lease is adopted: RENEW at T1, REBIND
        # at T2, discard-and-restart at the valid-lifetime expiry.
        self._t1_deadline = math.inf
        self._t2_deadline = math.inf
        self._valid_deadline = math.inf

    def trigger(self, *, managed: bool, other: bool) -> None:
        """
        Record a config-mode request from an inbound Router
        Advertisement and wake the worker thread. Called from the RX
        thread; non-blocking and idempotent — the worker debounces so a
        periodic RA does not re-run a completed exchange.
        """

        with self._lock__trigger:
            self._pending_managed = self._pending_managed or managed
            self._pending_other = self._pending_other or other
        self._event__trigger.set()

    def notify_dad_conflict(self, address: Ip6Address) -> None:
        """
        Record that Duplicate Address Detection found 'address' to be a
        duplicate on the link and wake the worker. Called from the
        DAD / RX thread; non-blocking. The worker DECLINEs the address
        (RFC 8415 §18.2.8) only if it matches the currently held lease,
        so a stale or unrelated conflict is harmless.
        """

        with self._lock__trigger:
            self._pending_decline_address = address
        self._event__trigger.set()

    @override
    def _subsystem_loop(self) -> None:
        """
        Run one worker iteration: handle a pending RA-driven trigger
        (acquire a lease / fetch other config), then service the held
        lease's renewal timers. The trigger wait doubles as the poll
        interval for the timer servicing, so a bound client wakes at
        least once per 'SUBSYSTEM_SLEEP_TIME__SEC' to check its
        deadlines even when no RA arrives.
        """

        if self._event__trigger.wait(timeout=SUBSYSTEM_SLEEP_TIME__SEC):
            self._event__trigger.clear()
            self._handle_trigger()
        self._service_lease()

    def _handle_trigger(self) -> None:
        """
        Run the exchange a pending RA-driven trigger requests.

        'managed' takes precedence over 'other' (a Managed RA drives the
        full stateful address lease, which itself fetches other config
        via its Option Request); each is run at most once until the host
        is configured, so a periodic RA does not re-solicit. A fresh
        lease arms the renewal timers.
        """

        with self._lock__trigger:
            managed = self._pending_managed
            other = self._pending_other
            decline_address = self._pending_decline_address
            self._pending_managed = False
            self._pending_other = False
            self._pending_decline_address = None

        # A DAD conflict on the held address supersedes a same-tick
        # acquire/fetch — the address is unusable and must be declined
        # and replaced before anything else.
        if decline_address is not None:
            self._handle_dad_conflict(decline_address)
            return

        if managed and self._lease is None:
            lease = self.acquire_lease()
            if lease is not None:
                self._lease = lease
                self._arm_timers(lease)
        elif other and not self._other_acquired:
            if self.fetch_other_config() is not None:
                self._other_acquired = True

    def _handle_dad_conflict(self, address: Ip6Address) -> None:
        """
        Handle a DAD conflict reported for 'address': if it is the
        currently leased address, DECLINE it to the server (RFC 8415
        §18.2.8), remove it from the interface, and restart the stateful
        exchange to obtain a fresh address. A conflict for any other
        address (stale notification, a lease already replaced) is ignored.
        """

        lease = self._lease
        if lease is None or lease.address != address:
            return

        __debug__ and log("dhcp6", f"DAD conflict on leased {address}; declining and re-soliciting")
        self.decline(lease)
        if self._address_api is not None:
            self._address_api.remove(address=address)
        self._lease = None
        self._t1_deadline = self._t2_deadline = self._valid_deadline = math.inf

        new_lease = self.acquire_lease()
        if new_lease is not None:
            self._lease = new_lease
            self._arm_timers(new_lease)

    @override
    def _stop(self) -> None:
        """
        Subsystem post-stop hook (runs after the worker thread has
        joined). Wake the trigger event for prompt teardown, then — if a
        lease is held — emit a graceful RELEASE for it and remove the
        leased address through the Address API (RFC 8415 §18.2.7). A
        socket error in the best-effort RELEASE is swallowed so it cannot
        abort the rest of the stack-stop sequence.
        """

        self._event__trigger.set()

        lease = self._lease
        if lease is None:
            return

        try:
            self.release(lease)
        except OSError as error:
            __debug__ and log("dhcp6", f"<WARN>RELEASE on shutdown raised {type(error).__name__}: {error}</>")
        if self._address_api is not None:
            self._address_api.remove(address=lease.address)
        self._lease = None

    # --- message builders ---

    def _client_id_option(self) -> Dhcp6OptionClientId:
        """
        Build the Client Identifier option carrying the host DUID.
        """

        return Dhcp6OptionClientId(get_client_duid(self._mac_address))

    @staticmethod
    def _elapsed_centisecs(start: float) -> int:
        """
        Compute the RFC 8415 §21.9 Elapsed Time value — the time since
        'start' (the exchange's first transmission) in hundredths of a
        second, clamped to the 16-bit field maximum (0xFFFF, which the
        RFC defines as "any elapsed-time value greater than" the field
        can hold).
        """

        return min(0xFFFF, max(0, round((time.monotonic() - start) * 100)))

    def _build_information_request(self, *, xid: int, elapsed: int = 0) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.6 INFORMATION-REQUEST carrying the
        Client Identifier (DUID), the Elapsed Time, and an Option
        Request listing the other-config options the client wants.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionElapsedTime(elapsed),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.INFORMATION_REQUEST,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_solicit(self, *, xid: int, elapsed: int = 0, rapid_commit: bool = False) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.1 SOLICIT carrying the Client
        Identifier, an IA_NA (the client's IAID; T1 / T2 = 0 to let
        the server choose), the Elapsed Time, an Option Request for DNS
        servers, and — when 'rapid_commit' is set — a Rapid Commit option
        requesting the two-message exchange.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionIaNa(iaid=get_iaid(), t1=0, t2=0),
            Dhcp6OptionElapsedTime(elapsed),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
            *((Dhcp6OptionRapidCommit(),) if rapid_commit else ()),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.SOLICIT,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_request(self, *, xid: int, server_duid: bytes, elapsed: int = 0) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.2 REQUEST addressed to the selected
        server (its DUID in the Server Identifier option), carrying the
        Client Identifier, the IA_NA, the Elapsed Time, and an
        Option Request for DNS servers.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionServerId(server_duid),
            Dhcp6OptionIaNa(iaid=get_iaid(), t1=0, t2=0),
            Dhcp6OptionElapsedTime(elapsed),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.REQUEST,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    @staticmethod
    def _ia_na_for_lease(lease: Dhcp6Lease) -> Dhcp6OptionIaNa:
        """
        Build the IA_NA option that echoes a currently held lease — its
        IAID and T1 / T2, with the leased address nested as an IA
        Address sub-option — for inclusion in a RENEW / REBIND so the
        server knows which binding to extend (RFC 8415 §18.2.4).
        """

        ia_addr = Dhcp6OptionIaAddr(
            address=lease.address,
            preferred_lifetime=lease.preferred_lifetime,
            valid_lifetime=lease.valid_lifetime,
        )
        return Dhcp6OptionIaNa(
            iaid=lease.iaid,
            t1=lease.t1,
            t2=lease.t2,
            options=bytes(Dhcp6Options(ia_addr)),
        )

    def _build_renew(self, *, xid: int, lease: Dhcp6Lease, elapsed: int = 0) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.4 RENEW addressed to the server that
        granted the lease (its DUID in the Server Identifier option),
        carrying the Client Identifier, the IA_NA being renewed (with
        the leased address), the Elapsed Time, and an Option Request.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionServerId(lease.server_duid),
            self._ia_na_for_lease(lease),
            Dhcp6OptionElapsedTime(elapsed),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.RENEW,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_rebind(self, *, xid: int, lease: Dhcp6Lease, elapsed: int = 0) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.5 REBIND — like RENEW but without a
        Server Identifier so any server on the link may extend the
        binding — carrying the Client Identifier, the IA_NA being
        rebound (with the leased address), the Elapsed Time, and an
        Option Request.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            self._ia_na_for_lease(lease),
            Dhcp6OptionElapsedTime(elapsed),
            Dhcp6OptionOro([Dhcp6OptionType.DNS_SERVERS]),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=Dhcp6MessageType.REBIND,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_teardown(
        self, *, msg_type: Dhcp6MessageType, xid: int, lease: Dhcp6Lease, elapsed: int = 0
    ) -> Dhcp6Assembler:
        """
        Build a server-directed teardown message (RELEASE or DECLINE)
        for the held lease: the granting server's DUID (Server
        Identifier), the Client Identifier, the IA_NA carrying the
        affected address, and the Elapsed Time.
        """

        options = Dhcp6Options(
            self._client_id_option(),
            Dhcp6OptionServerId(lease.server_duid),
            self._ia_na_for_lease(lease),
            Dhcp6OptionElapsedTime(elapsed),
        )

        return Dhcp6Assembler(
            dhcp6__msg_type=msg_type,
            dhcp6__xid=xid,
            dhcp6__options=options,
        )

    def _build_release(self, *, xid: int, lease: Dhcp6Lease, elapsed: int = 0) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.7 RELEASE for the held lease.
        """

        return self._build_teardown(msg_type=Dhcp6MessageType.RELEASE, xid=xid, lease=lease, elapsed=elapsed)

    def _build_decline(self, *, xid: int, lease: Dhcp6Lease, elapsed: int = 0) -> Dhcp6Assembler:
        """
        Build an RFC 8415 §18.2.8 DECLINE for the held lease (sent when
        its address has been found to be a duplicate on the link).
        """

        return self._build_teardown(msg_type=Dhcp6MessageType.DECLINE, xid=xid, lease=lease, elapsed=elapsed)

    def _open_client_socket(self) -> socket:
        """
        Open the UDP/IPv6 socket used for the exchange, pinned to this
        client's interface via SO_BINDTODEVICE when known so the
        link-scoped multicast egress is unambiguous on a multi-homed
        host.
        """

        client_socket = socket(family=AF_INET6, type=SOCK_DGRAM)
        if self._interface_name is not None:
            client_socket.setsockopt(SOL_SOCKET, SO_BINDTODEVICE, self._interface_name.encode())
        return client_socket

    def _multicast_target(self) -> tuple[str, int]:
        """
        Get the All_DHCP_Relay_Agents_and_Servers (address, port) the
        client transmits to.
        """

        return (
            str(dhcp6__constants.DHCP6__ALL_DHCP_RELAY_AGENTS_AND_SERVERS),
            dhcp6__constants.DHCP6__SERVER_PORT,
        )

    # --- stateless exchange ---

    def fetch_other_config(self) -> Dhcp6StatelessConfig | None:
        """
        Run one stateless INFORMATION-REQUEST / REPLY exchange and
        return the other-configuration bundle, or None when no server
        answers within the RFC 8415 §15 retransmission budget.
        """

        xid = random.randint(0, _DHCP6__XID_MAX)
        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()
            started = time.monotonic()

            def _send() -> None:
                elapsed = self._elapsed_centisecs(started)
                client_socket.sendto(bytes(self._build_information_request(xid=xid, elapsed=elapsed)), target)

            __debug__ and log("dhcp6", f"Sending INFORMATION-REQUEST (xid={xid:#08x}) to {target[0]}")
            _send()

            reply = self._run_exchange(
                client_socket,
                xid=xid,
                expected_type=Dhcp6MessageType.REPLY,
                resend=_send,
                irt_ms=dhcp6__constants.DHCP6__INF_TIMEOUT_MS,
                mrt_ms=dhcp6__constants.DHCP6__INF_MAX_RT_MS,
                max_attempts=dhcp6__constants.DHCP6__RETRANS_MAX_ATTEMPTS,
            )
            if reply is None:
                __debug__ and log("dhcp6", "INFORMATION-REQUEST unanswered; no other configuration obtained")
                return None

            dns_servers = reply.dns_servers or []
            __debug__ and log("dhcp6", f"Stateless config acquired: dns_servers={[str(s) for s in dns_servers]}")
            return Dhcp6StatelessConfig(dns_servers=dns_servers)
        finally:
            client_socket.close()

    # --- stateful exchange ---

    @staticmethod
    def _delay_first_solicit() -> None:
        """
        Delay the first SOLICIT by a random interval drawn uniformly from
        [0, SOL_MAX_DELAY] (RFC 8415 §18.2.1) to desynchronise a fleet of
        hosts that boot — or observe the Managed RA flag — at the same
        instant. A drawn delay of 0 (the 'dhcp6.sol_max_delay_ms = 0'
        operator override, or simply the random draw) transmits immediately.
        """

        delay_s = random.uniform(0.0, dhcp6__constants.DHCP6__SOL_MAX_DELAY_MS) / 1000.0
        if delay_s > 0:
            time.sleep(delay_s)

    def acquire_lease(self) -> Dhcp6Lease | None:
        """
        Run the RFC 8415 §18.2.1-§18.2.2 stateful exchange and return the
        leased IA_NA address, or None when no usable lease is obtained.

        SOLICIT collects ADVERTISEs (or, with Rapid Commit, a two-message
        REPLY); the ADVERTISEs are tried highest-preference first
        (§18.2.9), and if the chosen server does not answer the REQUEST or
        returns no usable lease the client falls back to the next-best
        server (§18.2.9 alternate-server selection / §18.2.10.1).
        """

        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()

            self._delay_first_solicit()

            rapid_commit = bool(dhcp6__constants.DHCP6__RAPID_COMMIT)
            sol_xid = random.randint(0, _DHCP6__XID_MAX)
            sol_started = time.monotonic()

            def _send_solicit() -> None:
                elapsed = self._elapsed_centisecs(sol_started)
                client_socket.sendto(
                    bytes(self._build_solicit(xid=sol_xid, elapsed=elapsed, rapid_commit=rapid_commit)), target
                )

            __debug__ and log("dhcp6", f"Sending SOLICIT (xid={sol_xid:#08x}) to {target[0]}")

            rapid_reply, advertises = self._solicit_for_advertise(
                client_socket, xid=sol_xid, send=_send_solicit, rapid_commit=rapid_commit
            )

            # RFC 8415 §18.2.1 — a Rapid Commit REPLY answers the SOLICIT
            # directly; lease from it without the REQUEST/REPLY round-trip.
            if rapid_reply is not None and rapid_reply.server_id is not None:
                __debug__ and log("dhcp6", "Rapid Commit REPLY received; leasing from the two-message exchange")
                lease = self._extract_lease(rapid_reply, server_duid=rapid_reply.server_id)
                if lease is not None:
                    self._assign_lease(lease)
                return lease

            if not advertises:
                __debug__ and log("dhcp6", "SOLICIT unanswered; no lease obtained")
                return None

            # RFC 8415 §18.2.9 — try servers highest-preference first; on a
            # non-responding server or an unusable REPLY (§18.2.10.1) fall
            # back to the next-best ADVERTISE.
            for advertise in advertises:
                server_duid = advertise.server_id
                assert server_duid is not None  # collection filters Server-Identifier-less ADVERTISEs
                reply = self._request_from_server(client_socket, target=target, server_duid=server_duid)
                if reply is None:
                    __debug__ and log("dhcp6", "REQUEST unanswered; trying the next advertised server")
                    continue
                lease = self._extract_lease(reply, server_duid=server_duid)
                if lease is not None:
                    self._assign_lease(lease)
                    return lease
                __debug__ and log("dhcp6", "REQUEST REPLY unusable; trying the next advertised server")

            return None
        finally:
            client_socket.close()

    def _request_from_server(
        self,
        client_socket: socket,
        *,
        target: tuple[str, int],
        server_duid: bytes,
    ) -> Dhcp6Parser | None:
        """
        Run one RFC 8415 §18.2.2 REQUEST / REPLY exchange to the server
        identified by 'server_duid' (REQ_TIMEOUT / REQ_MAX_RT / REQ_MAX_RC
        backoff). Returns the REPLY, or None when the server does not
        answer within the retransmission budget.
        """

        req_xid = random.randint(0, _DHCP6__XID_MAX)
        req_started = time.monotonic()

        def _send_request() -> None:
            elapsed = self._elapsed_centisecs(req_started)
            client_socket.sendto(
                bytes(self._build_request(xid=req_xid, server_duid=server_duid, elapsed=elapsed)), target
            )

        __debug__ and log("dhcp6", f"Sending REQUEST (xid={req_xid:#08x}) to server {server_duid.hex()}")
        _send_request()

        return self._run_exchange(
            client_socket,
            xid=req_xid,
            expected_type=Dhcp6MessageType.REPLY,
            resend=_send_request,
            irt_ms=dhcp6__constants.DHCP6__REQ_TIMEOUT_MS,
            mrt_ms=dhcp6__constants.DHCP6__REQ_MAX_RT_MS,
            max_attempts=dhcp6__constants.DHCP6__REQ_MAX_RC,
        )

    # --- SOLICIT / ADVERTISE collection + selection (RFC 8415 §18.2.1 / §18.2.9) ---

    def _solicit_for_advertise(
        self,
        client_socket: socket,
        *,
        xid: int,
        send: Callable[[], None],
        rapid_commit: bool = False,
    ) -> tuple[Dhcp6Parser | None, list[Dhcp6Parser]]:
        """
        Run the SOLICIT phase with the RFC 8415 §18.2.1 ADVERTISE
        collection modification: transmit the SOLICIT, collect valid
        ADVERTISEs for the whole first retransmission window (or
        short-circuit on a preference-255 ADVERTISE). Returns
        '(rapid_reply, advertises)' where 'advertises' is the collected
        set sorted highest-preference first (§18.2.9) for the caller's
        alternate-server fallback. If no ADVERTISE arrives during the
        first window, fall back to the §15 retransmission and return the
        first ADVERTISE received — the client acts on it without waiting
        for further ADVERTISEs.

        When 'rapid_commit' is set the window additionally accepts a valid
        REPLY carrying the Rapid Commit option; such a REPLY is returned
        as 'rapid_reply' (the two-message exchange) and 'advertises' is
        empty. A REPLY without the Rapid Commit option is discarded.
        """

        rand_factor = dhcp6__constants.DHCP6__RAND_FACTOR
        irt_ms = dhcp6__constants.DHCP6__SOL_TIMEOUT_MS
        mrt_ms = dhcp6__constants.DHCP6__SOL_MAX_RT_MS
        max_attempts = dhcp6__constants.DHCP6__RETRANS_MAX_ATTEMPTS
        accept_types = (
            (Dhcp6MessageType.ADVERTISE, Dhcp6MessageType.REPLY) if rapid_commit else (Dhcp6MessageType.ADVERTISE,)
        )

        send()

        # RFC 8415 §18.2.1 — the first RT MUST be strictly greater than
        # IRT (RAND chosen strictly greater than 0).
        rt_ms = irt_ms + random.uniform(0.0, rand_factor) * irt_ms
        deadline = time.monotonic() + max(0.001, rt_ms / 1000.0)

        rapid_reply, collected = self._collect_advertises(
            client_socket, xid=xid, deadline=deadline, accept_types=accept_types
        )
        if rapid_reply is not None:
            return rapid_reply, []
        if collected:
            return None, self._sort_advertises(collected)

        # No response in the first window — apply the §15 retransmission,
        # terminating on the first valid ADVERTISE (or Rapid Commit REPLY).
        for _ in range(1, max_attempts):
            rand = random.uniform(-rand_factor, rand_factor)
            rt_ms = 2 * rt_ms + rand * rt_ms
            if rt_ms > mrt_ms:
                rt_ms = mrt_ms + rand * mrt_ms
            send()
            packet = self._recv_within_window(
                client_socket,
                xid=xid,
                expected_types=accept_types,
                timeout_s=max(0.001, rt_ms / 1000.0),
            )
            if packet is None:
                continue
            if packet.msg_type is Dhcp6MessageType.REPLY:
                if packet.rapid_commit:
                    return packet, []
                continue
            if packet.server_id is not None:
                return None, [packet]

        return None, []

    def _collect_advertises(
        self,
        client_socket: socket,
        *,
        xid: int,
        deadline: float,
        accept_types: tuple[Dhcp6MessageType, ...],
    ) -> tuple[Dhcp6Parser | None, list[Dhcp6Parser]]:
        """
        Collect every valid ADVERTISE (matching 'xid', carrying a Server
        Identifier) until 'deadline' ('time.monotonic'), returning
        '(None, advertises)'. Returns early with '(None, advertises)' the
        moment an ADVERTISE with a preference value of 255 arrives
        (RFC 8415 §18.2.1). If 'accept_types' includes REPLY (Rapid
        Commit), a valid REPLY carrying the Rapid Commit option is
        returned immediately as '(reply, advertises)'; a REPLY without it
        is discarded.
        """

        collected: list[Dhcp6Parser] = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, collected
            packet = self._recv_within_window(
                client_socket,
                xid=xid,
                expected_types=accept_types,
                timeout_s=remaining,
            )
            if packet is None:
                return None, collected
            if packet.msg_type is Dhcp6MessageType.REPLY:
                # RFC 8415 §18.2.1 — accept a Rapid Commit REPLY, discard a
                # REPLY that does not carry the Rapid Commit option.
                if packet.rapid_commit:
                    return packet, collected
                continue
            if packet.server_id is None:
                # RFC 8415 §16.3 — an Advertise without a Server
                # Identifier is not valid; ignore it.
                continue
            collected.append(packet)
            if (packet.preference or 0) == 255:
                return None, collected

    @staticmethod
    def _sort_advertises(advertises: list[Dhcp6Parser]) -> list[Dhcp6Parser]:
        """
        Order ADVERTISEs highest-preference first (an absent Preference
        option counts as 0), keeping the first-received order among equal
        preferences (RFC 8415 §18.2.9). The caller requests the head and
        falls back down the list when a server does not answer.
        """

        # Negated key (ascending sort) keeps Python's stable order for
        # equal-preference ADVERTISEs — first-received is tried first.
        return sorted(advertises, key=lambda advertise: -(advertise.preference or 0))

    # --- lease maintenance (RENEW / REBIND) ---

    def _renew(self, lease: Dhcp6Lease, *, deadline: float) -> Dhcp6Lease | None:
        """
        Run an RFC 8415 §18.2.4 RENEW exchange for the held 'lease',
        retransmitting (REN_TIMEOUT / REN_MAX_RT backoff) until the
        granting server answers with a REPLY or the 'deadline'
        ('time.monotonic', the moment T2 is reached) elapses. Returns
        the refreshed lease, or None when no usable REPLY arrives in time.
        """

        xid = random.randint(0, _DHCP6__XID_MAX)
        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()
            started = time.monotonic()

            def _send() -> None:
                elapsed = self._elapsed_centisecs(started)
                client_socket.sendto(bytes(self._build_renew(xid=xid, lease=lease, elapsed=elapsed)), target)

            __debug__ and log("dhcp6", f"Sending RENEW (xid={xid:#08x}) for {lease.address}")
            _send()

            reply = self._run_exchange(
                client_socket,
                xid=xid,
                expected_type=Dhcp6MessageType.REPLY,
                resend=_send,
                irt_ms=dhcp6__constants.DHCP6__REN_TIMEOUT_MS,
                mrt_ms=dhcp6__constants.DHCP6__REN_MAX_RT_MS,
                mrd_deadline=deadline,
            )
            if reply is None:
                __debug__ and log("dhcp6", "RENEW unanswered before T2; escalating to REBIND")
                return None

            return self._extract_lease(reply, server_duid=lease.server_duid)
        finally:
            client_socket.close()

    def _rebind(self, lease: Dhcp6Lease, *, deadline: float) -> Dhcp6Lease | None:
        """
        Run an RFC 8415 §18.2.5 REBIND exchange for the held 'lease',
        retransmitting (REB_TIMEOUT / REB_MAX_RT backoff) until any
        server answers with a REPLY or the 'deadline' ('time.monotonic',
        the moment the valid lifetime expires) elapses. The responding
        server's DUID is taken from the REPLY. Returns the refreshed
        lease, or None when no usable REPLY arrives in time.
        """

        xid = random.randint(0, _DHCP6__XID_MAX)
        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()
            started = time.monotonic()

            def _send() -> None:
                elapsed = self._elapsed_centisecs(started)
                client_socket.sendto(bytes(self._build_rebind(xid=xid, lease=lease, elapsed=elapsed)), target)

            __debug__ and log("dhcp6", f"Sending REBIND (xid={xid:#08x}) for {lease.address}")
            _send()

            reply = self._run_exchange(
                client_socket,
                xid=xid,
                expected_type=Dhcp6MessageType.REPLY,
                resend=_send,
                irt_ms=dhcp6__constants.DHCP6__REB_TIMEOUT_MS,
                mrt_ms=dhcp6__constants.DHCP6__REB_MAX_RT_MS,
                mrd_deadline=deadline,
            )
            if reply is None:
                __debug__ and log("dhcp6", "REBIND unanswered before valid-lifetime expiry; lease lost")
                return None

            server_duid = reply.server_id
            if server_duid is None:
                __debug__ and log("dhcp6", "<WARN>REBIND REPLY missing Server Identifier; lease not refreshed")
                return None

            return self._extract_lease(reply, server_duid=server_duid)
        finally:
            client_socket.close()

    def release(self, lease: Dhcp6Lease, /) -> None:
        """
        Run an RFC 8415 §18.2.7 RELEASE exchange — retransmit the Release
        to the granting server up to REL_MAX_RC times at REL_TIMEOUT
        spacing, stopping on the server's REPLY. The MRT is capped at
        REL_TIMEOUT so the silent-server worst case is bounded to roughly
        REL_MAX_RC * REL_TIMEOUT (no unbounded §15 doubling) — a graceful
        shutdown is therefore never wedged. The REPLY is advisory and its
        content is discarded; the binding ages out server-side regardless.
        """

        self._teardown_exchange(
            msg_type=Dhcp6MessageType.RELEASE,
            lease=lease,
            irt_ms=dhcp6__constants.DHCP6__REL_TIMEOUT_MS,
            max_rc=dhcp6__constants.DHCP6__REL_MAX_RC,
        )

    def decline(self, lease: Dhcp6Lease, /) -> None:
        """
        Run an RFC 8415 §18.2.8 DECLINE exchange for an address that
        failed Duplicate Address Detection — retransmit up to DEC_MAX_RC
        times at DEC_TIMEOUT spacing (MRT capped at DEC_TIMEOUT to bound
        the silent-server worst case), stopping on the server's REPLY so
        the conflict handler can proceed to re-soliciting a fresh address.
        """

        self._teardown_exchange(
            msg_type=Dhcp6MessageType.DECLINE,
            lease=lease,
            irt_ms=dhcp6__constants.DHCP6__DEC_TIMEOUT_MS,
            max_rc=dhcp6__constants.DHCP6__DEC_MAX_RC,
        )

    def _teardown_exchange(self, *, msg_type: Dhcp6MessageType, lease: Dhcp6Lease, irt_ms: int, max_rc: int) -> None:
        """
        Send a RELEASE / DECLINE and await the server's REPLY, retransmit-
        ting up to 'max_rc' times at 'irt_ms' spacing (the MRT is set to
        'irt_ms' so the backoff stays flat and the silent-server worst
        case is bounded). The REPLY is acknowledgement only — its content
        is discarded.
        """

        xid = random.randint(0, _DHCP6__XID_MAX)
        client_socket = self._open_client_socket()
        try:
            client_socket.bind(("::", dhcp6__constants.DHCP6__CLIENT_PORT))
            target = self._multicast_target()
            started = time.monotonic()

            def _send() -> None:
                elapsed = self._elapsed_centisecs(started)
                client_socket.sendto(
                    bytes(self._build_teardown(msg_type=msg_type, xid=xid, lease=lease, elapsed=elapsed)), target
                )

            __debug__ and log("dhcp6", f"Sending {msg_type!s} (xid={xid:#08x}) for {lease.address}")
            _send()

            self._run_exchange(
                client_socket,
                xid=xid,
                expected_type=Dhcp6MessageType.REPLY,
                resend=_send,
                irt_ms=irt_ms,
                mrt_ms=irt_ms,
                max_attempts=max_rc,
            )
        finally:
            client_socket.close()

    # --- BOUND lifecycle (timer servicing) ---

    @staticmethod
    def _effective_timers(lease: Dhcp6Lease) -> tuple[float, float, float]:
        """
        Resolve a lease's (T1, T2, valid-lifetime) into seconds-from-now
        durations. A server T1 / T2 of 0 means "client's choice" and is
        derived as a fraction of the preferred lifetime (RFC 8415 §14.2);
        a field of 0xFFFFFFFF means infinity (the timer never fires).
        """

        preferred = lease.preferred_lifetime
        t1_factor = dhcp6__constants.DHCP6__T1_FACTOR
        t2_factor = dhcp6__constants.DHCP6__T2_FACTOR

        if lease.t1 == 0:
            t1 = math.inf if preferred == _DHCP6__LIFETIME_INFINITY else t1_factor * preferred
        else:
            t1 = math.inf if lease.t1 == _DHCP6__LIFETIME_INFINITY else float(lease.t1)

        if lease.t2 == 0:
            t2 = math.inf if preferred == _DHCP6__LIFETIME_INFINITY else t2_factor * preferred
        else:
            t2 = math.inf if lease.t2 == _DHCP6__LIFETIME_INFINITY else float(lease.t2)

        valid = math.inf if lease.valid_lifetime == _DHCP6__LIFETIME_INFINITY else float(lease.valid_lifetime)
        return t1, t2, valid

    def _arm_timers(self, lease: Dhcp6Lease) -> None:
        """
        Compute and store the monotonic T1 / T2 / valid-lifetime
        deadlines for 'lease' relative to the current time.
        """

        now = time.monotonic()
        t1, t2, valid = self._effective_timers(lease)
        self._t1_deadline = now + t1
        self._t2_deadline = now + t2
        self._valid_deadline = now + valid

    def _service_lease(self) -> None:
        """
        Advance the held lease's renewal state machine by one tick:
        RENEW once T1 is reached, REBIND once T2 is reached, and
        discard-and-restart once the valid lifetime expires. A no-op
        when the client holds no lease.
        """

        lease = self._lease
        if lease is None:
            return

        now = time.monotonic()
        if now >= self._valid_deadline:
            self._expire_lease(lease)
        elif now >= self._t2_deadline:
            refreshed = self._rebind(lease, deadline=self._valid_deadline)
            if refreshed is not None:
                self._adopt_refreshed(refreshed, previous=lease)
            else:
                # Do not re-rebind every tick — wait for the valid
                # lifetime to expire and restart from SOLICIT.
                self._t2_deadline = self._valid_deadline
        elif now >= self._t1_deadline:
            refreshed = self._renew(lease, deadline=self._t2_deadline)
            if refreshed is not None:
                self._adopt_refreshed(refreshed, previous=lease)
            else:
                # Do not re-renew every tick — defer to REBIND at T2.
                self._t1_deadline = self._t2_deadline

    def _adopt_refreshed(self, refreshed: Dhcp6Lease, *, previous: Dhcp6Lease) -> None:
        """
        Adopt a RENEW / REBIND result: reconcile the interface address
        (a no-op unless the server returned a different one), replace the
        held lease, and re-arm the renewal timers.
        """

        if self._address_api is not None and previous.address != refreshed.address:
            __debug__ and log("dhcp6", f"Lease address changed {previous.address} -> {refreshed.address}; swapping")
            self._address_api.replace(
                old_address=previous.address,
                new_ifaddr=self._lease_ifaddr(refreshed),
            )
        self._lease = refreshed
        self._arm_timers(refreshed)

    def _expire_lease(self, lease: Dhcp6Lease) -> None:
        """
        Handle valid-lifetime expiry: remove the leased address from the
        interface (RFC 8415 §18.2.5 — the client must stop using it) and
        restart the stateful exchange from SOLICIT, adopting any fresh
        lease that results.
        """

        __debug__ and log("dhcp6", f"Lease {lease.address} valid lifetime expired; releasing and re-soliciting")
        if self._address_api is not None:
            self._address_api.remove(address=lease.address)
        self._lease = None

        new_lease = self.acquire_lease()
        if new_lease is not None:
            self._lease = new_lease
            self._arm_timers(new_lease)

    @staticmethod
    def _lease_ifaddr(lease: Dhcp6Lease) -> Ip6IfAddr:
        """
        Build the /128 interface address for a leased IA_NA address.
        """

        return Ip6IfAddr(f"{lease.address}/{_DHCP6__LEASE_PREFIX_LEN}")

    def _assign_lease(self, lease: Dhcp6Lease) -> None:
        """
        Install the leased address on the interface through the Address
        API (a no-op when no Address API was configured).
        """

        if self._address_api is None:
            return
        ifaddr = self._lease_ifaddr(lease)
        __debug__ and log("dhcp6", f"Assigning leased address {ifaddr} via the Address API (DAD-checked)")
        # DAD-checked install (RFC 8415 §18.2.8): the address is claimed
        # through the ND DAD engine and only used once it passes; a
        # duplicate calls back into 'notify_dad_conflict' so the worker
        # DECLINEs it and re-solicits.
        self._address_api.add(ifaddr=ifaddr, dad_conflict_callback=self.notify_dad_conflict)

    # RFC 8415 §18.2.10 / §18.2.10.1 — top-level (message-level) Status
    # Codes that mean "this REPLY grants no usable lease": UnspecFail
    # (server could not process the message), UseMulticast (the client
    # must multicast — already PyTCP's only transmit mode), and NotOnLink
    # (the requested address is not valid on this link → restart
    # discovery). On any of these the client discards the REPLY and
    # re-solicits later via the RA trigger / lease-lifecycle timers.
    _TOP_LEVEL_REJECT_STATUS = frozenset(
        {
            Dhcp6StatusCode.UNSPEC_FAIL,
            Dhcp6StatusCode.USE_MULTICAST,
            Dhcp6StatusCode.NOT_ON_LINK,
        }
    )

    def _extract_lease(self, reply: Dhcp6Parser, *, server_duid: bytes) -> Dhcp6Lease | None:
        """
        Extract the leased IA_NA address from a REPLY. Rejects the REPLY
        outright on a top-level UnspecFail / UseMulticast / NotOnLink
        Status Code (RFC 8415 §18.2.10 / §18.2.10.1); otherwise parses the
        IA_NA sub-option block (preserved as opaque bytes by the codec)
        for the IA Address and any nested Status Code, returning None when
        the binding carries no address or a non-Success Status Code.
        """

        top_status = reply.status_code
        if top_status is not None and top_status.status_code in self._TOP_LEVEL_REJECT_STATUS:
            __debug__ and log("dhcp6", f"<WARN>REPLY top-level Status Code {top_status.status_code}; no lease obtained")
            return None

        ia_na = reply.ia_na
        if ia_na is None:
            __debug__ and log("dhcp6", "<WARN>REPLY carries no IA_NA option; no lease obtained")
            return None

        try:
            Dhcp6Options.validate_integrity(frame=ia_na.options, hlen=len(ia_na.options), offset=0)
            ia_options = Dhcp6Options.from_buffer(memoryview(ia_na.options))
        except Dhcp6IntegrityError, Dhcp6SanityError:
            __debug__ and log("dhcp6", "<WARN>REPLY IA_NA sub-options malformed; no lease obtained")
            return None

        status = ia_options.status_code
        if status is not None and status.status_code != Dhcp6StatusCode.SUCCESS:
            __debug__ and log("dhcp6", f"<WARN>REPLY IA_NA Status Code {status.status_code}; no lease obtained")
            return None

        ia_addr = ia_options.ia_addr
        if ia_addr is None:
            __debug__ and log("dhcp6", "<WARN>REPLY IA_NA carries no IA Address; no lease obtained")
            return None

        lease = Dhcp6Lease(
            address=ia_addr.address,
            preferred_lifetime=ia_addr.preferred_lifetime,
            valid_lifetime=ia_addr.valid_lifetime,
            t1=ia_na.t1,
            t2=ia_na.t2,
            iaid=ia_na.iaid,
            server_duid=server_duid,
        )
        __debug__ and log(
            "dhcp6",
            f"Lease acquired: {lease.address} (preferred {lease.preferred_lifetime}s, valid {lease.valid_lifetime}s)",
        )
        return lease

    # --- shared retransmission / recv machinery ---

    def _run_exchange(
        self,
        client_socket: socket,
        *,
        xid: int,
        expected_type: Dhcp6MessageType,
        resend: Callable[[], None],
        irt_ms: int,
        mrt_ms: int,
        max_attempts: int | None = None,
        mrd_deadline: float | None = None,
    ) -> Dhcp6Parser | None:
        """
        Wait for the matching reply ('expected_type', 'xid') using the
        RFC 8415 §15 retransmission backoff seeded with the per-message
        IRT / MRT. On each per-attempt timeout the caller's 'resend'
        retransmits the request and the timeout grows (doubled, capped
        at MRT, each value randomized by RAND). Returns the parsed
        reply, or None once the bound is reached.

        Exactly one bound governs termination: 'max_attempts' caps the
        total recv attempts (the INF / SOL / REQ / REL / DEC max
        retransmission count), while 'mrd_deadline' is a 'time.monotonic'
        deadline expressing the max retransmission duration (the RENEW /
        REBIND MRD — the time remaining until T2 / valid-lifetime
        expiry). When 'mrd_deadline' is set the per-attempt recv window
        is clamped so a retransmit never overshoots the deadline.
        """

        assert (
            max_attempts is not None or mrd_deadline is not None
        ), "_run_exchange requires either a max-attempt count or an MRD deadline to terminate."

        rand_factor = dhcp6__constants.DHCP6__RAND_FACTOR

        rt_ms = 0.0
        attempt = 0
        while True:
            if mrd_deadline is not None and time.monotonic() >= mrd_deadline:
                return None

            # RFC 8415 §15 — RT = IRT + RAND*IRT on the first attempt,
            # then RT = 2*RTprev + RAND*RTprev capped at MRT, where
            # RAND is drawn uniformly from [-0.1, +0.1].
            rand = random.uniform(-rand_factor, rand_factor)
            if attempt == 0:
                rt_ms = irt_ms + rand * irt_ms
            else:
                rt_ms = 2 * rt_ms + rand * rt_ms
                if rt_ms > mrt_ms:
                    rt_ms = mrt_ms + rand * mrt_ms
            timeout_s = rt_ms / 1000.0
            if mrd_deadline is not None:
                timeout_s = min(timeout_s, mrd_deadline - time.monotonic())
            timeout_s = max(0.001, timeout_s)

            result = self._recv_within_window(
                client_socket, xid=xid, expected_types=(expected_type,), timeout_s=timeout_s
            )
            if result is not None:
                return result

            attempt += 1
            if max_attempts is not None and attempt >= max_attempts:
                return None

            __debug__ and log(
                "dhcp6",
                f"recv window expired ({timeout_s:.2f}s); retransmitting (attempt {attempt + 1})",
            )
            resend()

    def _recv_within_window(
        self,
        client_socket: socket,
        *,
        xid: int,
        expected_types: tuple[Dhcp6MessageType, ...],
        timeout_s: float,
    ) -> Dhcp6Parser | None:
        """
        Wait up to 'timeout_s' seconds for a valid message whose msg-type
        is one of 'expected_types' and whose 'xid' matches, silently
        dropping bogus packets (malformed, wrong msg-type, mismatched xid)
        without consuming the entire window. Returns the parsed message on
        success, or None if the deadline elapses with no valid response.
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
                packet = Dhcp6Parser(client_socket.recv__mv(timeout=remaining))
            except TimeoutError:
                return None
            except Dhcp6IntegrityError, Dhcp6SanityError:
                __debug__ and log("dhcp6", "<WARN>Dropping malformed inbound DHCPv6 frame; continuing wait window</>")
                continue

            __debug__ and log("dhcp6", f"<lg>RX</> - {packet}")

            if packet.msg_type not in expected_types:
                __debug__ and log(
                    "dhcp6",
                    f"<WARN>Dropping DHCPv6 frame with unexpected msg-type {packet.msg_type!r}; "
                    f"expected one of {expected_types!r}</>",
                )
                continue
            if packet.xid != xid:
                __debug__ and log(
                    "dhcp6",
                    f"<WARN>Dropping DHCPv6 frame with mismatched xid (sent={xid:#08x}, got={packet.xid:#08x})</>",
                )
                continue

            return packet
