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
This module contains the DHCPv4 lease cache — a small JSON
file PyTCP uses to remember a prior lease across reboots so
the RFC 2131 §4.4.2 INIT-REBOOT fast-path can ask the
leasing server to re-confirm the cached IP instead of
running a full DISCOVER/OFFER/REQUEST/ACK exchange.

The cache file format is a single JSON object with the
shape:

    {
        "version": 3,
        "address": "192.168.1.145",
        "mask": "255.255.255.0",
        "gateway": "192.168.1.1" | null,
        "gateway_mac": "aa:bb:cc:dd:ee:ff" | null,
        "server_id": "192.168.1.1",
        "lease_time__sec": 3600,
        "acquired_at_wall": 1701234567.89,
        "t1_override": 1800 | null,
        "t2_override": 3150 | null
    }

'acquired_at_wall' is 'time.time()' at the moment the lease
was acquired — a wall-clock timestamp so freshness can be
evaluated across reboots. The reader rejects a cache file
whose wall-clock-age exceeds 'lease_time__sec'.

'gateway_mac' (Phase 6) is the gateway's last-known
link-layer address sourced from the live ARP cache at
write time. The Phase 6 RFC 4436 DNAv4 fast-path uses
this to send a unicast ARP probe to the cached gateway
and skip the DHCP exchange entirely if it answers. The
field is optional; cache writers omit it as null when
the ARP cache has not yet resolved the gateway (typical
on first boot before any IP traffic flowed).

't1_override' / 't2_override' carry the server-supplied
RFC 2132 §9.7 Renewal Time (option 58) and RFC 2132 §9.8
Rebinding Time (option 59) values from the ACK that
issued the lease. When present, the Dhcp4Client's
T1 / T2 deadline computation honours them in preference
to the factor-based defaults. Both fields are nullable —
servers that omit options 58 / 59 store null here, and
the silent-server INIT-REBOOT fast-path then falls back
to the factor defaults.

Writes go through 'tempfile.mkstemp' + 'os.replace' for
atomic file replacement — a half-written cache from a
crash never reaches the reader. Reads are defensive: any
structural / type / value error returns 'None' so a
corrupted cache cannot crash the lifecycle.

pytcp/protocols/dhcp4/dhcp4__lease_cache.py

ver 3.0.8
"""

import json
import os
import tempfile
import time
from typing import TYPE_CHECKING, Any

from net_addr import (
    Ip4Address,
    Ip4AddressFormatError,
    Ip4IfAddr,
    Ip4Mask,
    Ip4Network,
    Ip4NetworkFormatError,
    MacAddress,
    MacAddressFormatError,
)
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Lease

# Bump on incompatible format changes; reader rejects unknown
# versions so an older PyTCP binary will not try to consume
# a cache written by a newer one.
_DHCP4__LEASE_CACHE__VERSION: int = 3


def _resolve_gateway_mac(lease: "Dhcp4Lease", /) -> MacAddress | None:
    """
    Resolve the gateway's link-layer address for caching.
    Precedence: explicit 'lease.gateway_mac' (test override) →
    live ARP cache lookup → None. The ARP-cache lookup is best-
    effort: 'pytcp.stack' is imported lazily because this module
    can be imported before 'stack.init()' has populated
    'stack.arp_cache'.
    """

    if lease.gateway_mac is not None:
        return lease.gateway_mac
    if lease.gateway is None:
        return None
    try:
        from pytcp import stack  # noqa: PLC0415 — late import; arp_cache populated at stack.init()
    except ImportError:
        return None
    arp_cache = getattr(stack, "arp_cache", None)
    if arp_cache is None:
        return None
    try:
        mac = arp_cache.find_entry(ip4_address=lease.gateway)
    except AssertionError, AttributeError:
        # Best-effort: 'find_entry' asserts the ARP cache is owner-bound
        # (an 'AttributeError' under 'python -O'); during very early boot
        # or in test fixtures it may not be, so degrade to None rather
        # than propagate the not-yet-wired condition.
        return None
    if mac is None or isinstance(mac, MacAddress):
        return mac
    return None


def write_cached_lease(path: str, lease: "Dhcp4Lease", /) -> None:
    """
    Atomically write 'lease' to the JSON file at 'path'. Best-
    effort — any OSError is logged as a WARNING and swallowed so
    a read-only cache directory cannot prevent the DHCPv4
    lifecycle from completing.

    The wall-clock-time-of-acquisition is computed at call time
    via 'time.time()'; the lease's 'acquired_at_monotonic' is
    not portable across reboots and would be useless to a
    future reader.

    The gateway link-layer address is read from the live ARP
    cache via 'stack.arp_cache.find_entry' so the next-boot
    RFC 4436 DNAv4 probe has a unicast target. The lookup is
    best-effort: on first BOUND the ARP cache may not yet have
    resolved the gateway, in which case 'gateway_mac' is
    persisted as null and DNAv4 falls back to standard
    INIT-REBOOT for that boot. The 'lease.gateway_mac' override
    takes precedence so callers (e.g. unit tests) can pin the
    value explicitly.
    """

    if not path:
        return

    gateway_mac = _resolve_gateway_mac(lease)

    payload: dict[str, Any] = {
        "version": _DHCP4__LEASE_CACHE__VERSION,
        "address": str(lease.ip4_host.address),
        "mask": str(lease.ip4_host.network.mask),
        "gateway": (str(lease.gateway) if lease.gateway is not None else None),
        "gateway_mac": (str(gateway_mac) if gateway_mac is not None else None),
        "server_id": str(lease.server_id),
        "lease_time__sec": lease.lease_time__sec,
        "acquired_at_wall": time.time(),
        "t1_override": lease.t1_override,
        "t2_override": lease.t2_override,
        "classless_static_routes": (
            [[str(destination), str(router)] for destination, router in lease.classless_static_routes]
            if lease.classless_static_routes is not None
            else None
        ),
    }

    try:
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        # Atomic write: tempfile in the same directory + os.replace.
        # A crash mid-write leaves the prior cache intact.
        fd, tmp_path = tempfile.mkstemp(prefix=".dhcp4_lease.", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as cache_file:
                json.dump(payload, cache_file)
            os.replace(tmp_path, path)
        except BaseException:
            # Cleanup the half-written tempfile on any failure.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Failed to write DHCPv4 lease cache to {path!r}: {error}</>",
        )


def read_cached_lease(path: str, /) -> "Dhcp4Lease | None":
    """
    Return the cached lease at 'path' if the file exists, parses
    cleanly, has a known 'version', and the lease has not yet
    expired by wall-clock time. Return 'None' on any failure —
    missing file, malformed JSON, unknown version, expired
    lease, structural errors. Callers should treat 'None' as
    "no usable cache; proceed with INIT".

    Imports 'Dhcp4Lease' lazily to break the
    'dhcp4__client → dhcp4__lease_cache → dhcp4__client'
    circular import chain.
    """

    from pytcp.protocols.dhcp4.dhcp4__client import (  # noqa: PLC0415 — local for cycle break
        Dhcp4Lease,
    )

    if not path:
        return None

    try:
        with open(path, "r", encoding="utf-8") as cache_file:
            payload = json.load(cache_file)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Cannot read DHCPv4 lease cache at {path!r}: {error}</>",
        )
        return None

    if not isinstance(payload, dict):
        return None
    if payload.get("version") != _DHCP4__LEASE_CACHE__VERSION:
        return None

    try:
        address = Ip4Address(payload["address"])
        mask = Ip4Mask(payload["mask"])
        gateway_str = payload.get("gateway")
        gateway: Ip4Address | None = Ip4Address(gateway_str) if gateway_str is not None else None
        gateway_mac_str = payload.get("gateway_mac")
        gateway_mac: MacAddress | None = MacAddress(gateway_mac_str) if gateway_mac_str is not None else None
        server_id = Ip4Address(payload["server_id"])
        lease_time__sec = int(payload["lease_time__sec"])
        acquired_at_wall = float(payload["acquired_at_wall"])
        # v3 fields — RFC 2132 §9.7 / §9.8 T1 / T2 server overrides.
        # Absent in v2 caches (always reads None there); always
        # present in v3 caches but may be JSON null when the
        # original ACK omitted the option.
        t1_raw = payload.get("t1_override")
        t2_raw = payload.get("t2_override")
        t1_override: int | None = int(t1_raw) if t1_raw is not None else None
        t2_override: int | None = int(t2_raw) if t2_raw is not None else None
        # Classless static routes (option 121, RFC 3442). Absent in
        # pre-Phase-7 caches (reads None); present as a list of
        # [destination, router] string pairs otherwise.
        classless_raw = payload.get("classless_static_routes")
        classless_static_routes: list[tuple[Ip4Network, Ip4Address]] | None = (
            [(Ip4Network(destination), Ip4Address(router)) for destination, router in classless_raw]
            if classless_raw is not None
            else None
        )
    except (
        KeyError,
        ValueError,
        TypeError,
        Ip4AddressFormatError,
        Ip4NetworkFormatError,
        MacAddressFormatError,
    ) as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Malformed DHCPv4 lease cache at {path!r}: {error}</>",
        )
        return None

    # Drop expired leases — RFC 2131 §4.4.2 INIT-REBOOT applies
    # only to a "previously allocated network address" that is
    # still within its lease duration.
    age_s = time.time() - acquired_at_wall
    if age_s < 0 or age_s >= lease_time__sec:
        __debug__ and log(
            "dhcp4",
            f"DHCPv4 lease cache at {path!r} is expired "
            f"(age={age_s:.0f}s, lease_time={lease_time__sec}s); dropping",
        )
        return None

    ip4_host = Ip4IfAddr((address, mask))

    # The monotonic clock did not exist before this process
    # started, so we cannot reconstruct the original
    # 'acquired_at_monotonic'. Anchor it so the FSM's T1/T2/
    # expiry deadlines (which subtract from this value) line
    # up with the wall-clock age: 'now_mono - age_s' is the
    # monotonic instant that corresponds to the wall-clock
    # acquisition time within the current process.
    acquired_at_monotonic = time.monotonic() - age_s

    return Dhcp4Lease(
        ip4_host=ip4_host,
        gateway=gateway,
        lease_time__sec=lease_time__sec,
        server_id=server_id,
        acquired_at_monotonic=acquired_at_monotonic,
        gateway_mac=gateway_mac,
        t1_override=t1_override,
        t2_override=t2_override,
        classless_static_routes=classless_static_routes,
    )


def delete_cached_lease(path: str, /) -> None:
    """
    Remove the cache file if it exists. Best-effort — a missing
    file is not an error; an OSError on an existing file is
    logged as a WARNING and swallowed so the DHCPv4 lifecycle
    is never blocked on cache cleanup.
    """

    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    except OSError as error:
        __debug__ and log(
            "dhcp4",
            f"<WARN>Failed to delete DHCPv4 lease cache at {path!r}: {error}</>",
        )
