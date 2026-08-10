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
This module contains the IPv6 Neighbor Discovery runtime
configuration constants. The 'icmp6.*' sysctl namespace mirrors
Linux 'net.ipv6.conf.<iface>.*'.

Knobs land here as their consumers do; speculative API surface is
forbidden per CLAUDE.md ("don't design for hypothetical future
requirements"). The first knob to register is 'icmp6.accept_redirects'
(nd_linux_parity Phase 1B); subsequent phases will add timing knobs
(retrans_timer_ms, dad_transmits) and policy knobs (accept_ra_*) as
their consumers ship.

pytcp/protocols/icmp6/nd/nd__constants.py

ver 3.0.9
"""

from typing import Any

from pytcp.stack.sysctl import register

# Linux net.ipv6.conf.<iface>.accept_redirects policy. Controls
# whether inbound RFC 4861 §8 Redirect messages are processed
# (cache override) or silently dropped.
#   0 = drop every Redirect (kill switch — useful for security-
#       sensitive deployments where the off-link-spoofing risk
#       outweighs the route-optimisation benefit).
#   1 = process Redirects subject to RFC 4861 §8.1 acceptance
#       gates (host-side default; matches Linux's host default).
ICMP6__ACCEPT_REDIRECTS: dict[str, int] = {"default": 1}

# Number of gratuitous Neighbor Advertisement messages emitted
# on host attachment (RFC 9131 §3 — the IPv6 analogue of
# RFC 5227 §2.3 ARP Announcement). Linux's default is 1; a
# value of 0 suppresses gratuitous-NA emission entirely (kill
# switch for stealth deployments).
ICMP6__GRATUITOUS_NA_COUNT: dict[str, int] = {"default": 1}

# Number of DAD (Duplicate Address Detection) probes emitted
# per candidate address per RFC 4862 §5.1 ('DupAddrDetectTransmits',
# default 1). Linux exposes this as 'net.ipv6.conf.<iface>.
# dad_transmits'. A value of 0 disables DAD entirely.
ICMP6__DAD_TRANSMITS: dict[str, int] = {"default": 1}

# Inter-probe wait between successive DAD probes, in
# milliseconds, per RFC 4861 §10 ('RetransTimer', default
# 1000ms). Linux exposes this as
# 'net.ipv6.conf.<iface>.retrans_time_ms'.
ICMP6__RETRANS_TIMER_MS: dict[str, int] = {"default": 1000}

# Linux net.ipv6.conf.<iface>.accept_ra_defrtr policy. Controls
# whether inbound RA messages with a non-zero Router Lifetime
# install / refresh an entry in the host's default-router list
# (RFC 4861 §6.3.4).
#   0 = drop default-router learning entirely (host sees the RA's
#       prefix-info options but never gains a default route from
#       it — useful for static-routing or isolated deployments).
#   1 = process default-router updates per RFC 4861 §6.3.4 (Linux
#       host default).
ICMP6__ACCEPT_RA_DEFRTR: dict[str, int] = {"default": 1}

# Linux net.ipv6.conf.<iface>.accept_ra_pinfo policy. Controls
# whether inbound RA Prefix-Information options install / refresh
# entries in the host's SLAAC prefix table (RFC 4862 §5.5.3).
#   0 = drop PI consumption entirely (no SLAAC state changes from
#       inbound RAs — useful for managed-config-only deployments
#       where addresses come from DHCPv6).
#   1 = process PI options per RFC 4862 §5.5.3 (Linux host
#       default).
ICMP6__ACCEPT_RA_PINFO: dict[str, int] = {"default": 1}

# RFC 4862 §5.5.3 (e)(6) 2-hour rule constant. Defends an
# existing autoconfigured address from a router that advertises
# a short remaining lifetime: an unauthenticated router cannot
# shrink an address's valid lifetime below this floor unless
# the existing remaining is already at or below it. Per spec
# fixed at 2 hours = 7200 seconds; not user-tunable. Defined
# here as a protocol invariant rather than a sysctl because
# Linux exposes no knob for it (RFC compliance).
ICMP6__SLAAC__TWO_HOUR_RULE_S = 7200

# Linux net.ipv6.conf.<iface>.accept_ra_min_hop_limit policy.
# Floors the Cur-Hop-Limit values that PyTCP will accept from
# inbound RAs (RFC 4861 §6.3.4). Values strictly below this
# threshold are dropped — a defense against routers that
# advertise pathologically low Hop Limits which would cause
# legitimate destinations to become unreachable. Linux's
# default is 1.
ICMP6__ACCEPT_RA_MIN_HOP_LIMIT: dict[str, int] = {"default": 1}

# RFC 4861 §6.3.7 RTR_SOLICITATION_INTERVAL — the initial
# retransmission timeout for the host's Router Solicitation
# loop, in milliseconds. RFC 7559 §2 amends this to be the
# IRT base for truncated binary exponential backoff. Default
# 4000 ms (4 s).
ICMP6__RTR_SOLICITATION_INTERVAL_MS: dict[str, int] = {"default": 4000}

# RFC 7559 §2 maximum retransmission timeout (MRT cap) for
# the RS exponential-backoff loop, in milliseconds. Default
# 3 600 000 ms (1 hour). Combined with MAX_RTR_SOLICITATIONS
# this bounds how long a host pauses between unsuccessful RS
# retransmissions.
ICMP6__RTR_SOLICITATION_MAX_RT_MS: dict[str, int] = {"default": 3600000}

# RFC 4861 §6.3.7 MAX_RTR_SOLICITATIONS — the maximum number
# of RS messages the host emits before giving up on RA-driven
# auto-configuration. Default 3 per RFC 4861. A value of 0
# disables RS entirely (kill switch for static-config-only
# deployments).
ICMP6__MAX_RTR_SOLICITATIONS: dict[str, int] = {"default": 3}

# RFC 7527 Enhanced DAD — when enabled, every NS(DAD) probe
# carries a randomly-generated 6-byte Nonce option. The host
# tracks emitted nonces during the DAD session and silently
# drops inbound NS messages whose Nonce matches one of ours
# (loop-hairpin detection — distinguishes a switch echoing
# our probe back from a genuine peer DAD conflict). Default
# 1 per RFC 7527 / Linux 'enhanced_dad'. 0 disables the
# feature; DAD then uses RFC 4861 plain semantics where any
# NS targeting our tentative address aborts the claim.
ICMP6__ENHANCED_DAD: dict[str, int] = {"default": 1}

# RFC 8981 §3.8 REGEN_ADVANCE — number of seconds before
# a temporary address's preferred lifetime expires that the
# host should generate a replacement. The §3.8 formula is
# 2 + (TEMP_IDGEN_RETRIES * RetransTimer / 1000), which
# yields ~5 seconds for default DAD parameters
# (DupAddrDetectTransmits=1, RetransTimer=1000ms,
# TEMP_IDGEN_RETRIES=3). PyTCP uses 5 as a flat default.
# Setting to 0 disables advance regeneration (the host
# regenerates exactly at preferred_until expiry, leaving
# no overlap window).
ICMP6__REGEN_ADVANCE_S: dict[str, int] = {"default": 5}

# Interval (seconds) between RFC 8981 temporary-address
# sweeps. The PacketHandler subsystem loop wakes up at
# least this often to inspect '_icmp6_temp_addresses' and
# remove entries whose 'valid_until' deadline has passed.
# Default 60 seconds — a balance between cleanup latency
# and per-tick overhead. Linux drives the equivalent via
# 'addr_chk_timer'; the value isn't directly user-tunable
# in the kernel, but PyTCP exposes it for test runs that
# want a tighter sweep interval. Must be > 0 (a zero
# interval would tight-loop).
ICMP6__TEMP_ADDR_SWEEP_INTERVAL_S: dict[str, int] = {"default": 60}

# RFC 7217 §6 IDGEN_RETRIES — the host re-derives the
# Interface Identifier and retries DAD up to this many times
# on collision before giving up. RFC 7217 §6 specifies 3 as
# the default; RFC 8981 §3.3.3 reuses the same constant for
# temporary-address regeneration on DAD failure. PyTCP exposes
# this as 'icmp6.idgen_retries'; the boot loop wires it for
# RFC 7217 stable addresses (re-deriving with an incremented
# 'dad_counter') and the §18b temp-address mutator wires it
# for RFC 8981 (each retry mints a fresh random IID). A value
# of 0 disables retry entirely (give up on first DAD failure).
ICMP6__IDGEN_RETRIES: dict[str, int] = {"default": 3}

# Linux net.ipv6.conf.<iface>.accept_dad policy. Tristate
# matching Linux's host-side semantics:
#   0 = skip DAD entirely. The candidate goes straight to
#       VALID; no probes are emitted; no initial random delay
#       is taken. Equivalent in effect to 'dad_transmits=0'.
#   1 = normal DAD (default). DAD failure removes the
#       candidate from the host's address list but leaves
#       IPv6 enabled.
#   2 = strict DAD. Any DAD failure additionally disables
#       IPv6 on the interface ('_ip6_support = False'). Used
#       by paranoid deployments where conflicting addresses
#       are treated as a security incident. Linux's kernel
#       has the same behaviour.
ICMP6__ACCEPT_DAD: dict[str, int] = {"default": 1}

# RFC 4861 §10 MAX_RTR_SOLICITATION_DELAY — the upper bound
# on the random initial delay before the first DAD probe (RFC
# 4862 §5.4.2) and the first Router Solicitation (RFC 4861
# §6.3.7). The host SHOULD wait a uniform random duration in
# [0, MAX_RTR_SOLICITATION_DELAY) before transmitting either
# message; this alleviates fleet-wide synchronisation when
# many hosts boot at the same instant. Default 1000 ms (1 s)
# per RFC 4861 §10. A value of 0 disables the delay entirely
# (kill switch — useful for low-latency boot environments
# where the operator accepts the synchronisation risk).
ICMP6__MAX_RTR_SOLICITATION_DELAY_MS: dict[str, int] = {"default": 1000}

# Linux net.ipv6.conf.<iface>.use_tempaddr policy. Controls
# whether RFC 8981 temporary addresses are generated alongside
# the stable SLAAC address for each admitted PI. Tristate
# matching Linux:
#   0 = disabled — no temp addresses (default; privacy-conservative
#       deployments rely on RFC 7217 stable opaque IIDs alone).
#   1 = enabled, no preference — temp addresses are generated and
#       DAD-claimed but the source-address selector does not
#       prefer them (matches Linux 'use_tempaddr=1').
#   2 = enabled, prefer temp — RFC 6724 rule 7 makes the temp
#       address the default outbound source. Wired through the
#       PacketHandler '_select_ip6_source' selector at
#       'pytcp/runtime/packet_handler/packet_handler__ip6__tx.py';
#       values 0 and 1 leave rule 7 as a no-op and rule 8
#       decides.
ICMP6__USE_TEMPADDR: dict[str, int] = {"default": 0}

# RFC 8981 §3.8 TEMP_VALID_LIFETIME — total valid lifetime cap
# for temporary addresses. Default 7 days (604800 seconds).
# Linux exposes this as 'net.ipv6.conf.<iface>.temp_valid_lft'.
ICMP6__TEMP_VALID_LIFETIME_S: dict[str, int] = {"default": 604800}

# RFC 8981 §3.8 TEMP_PREFERRED_LIFETIME — preferred lifetime cap
# for temporary addresses. Default 1 day (86400 seconds). Linux
# exposes this as 'net.ipv6.conf.<iface>.temp_prefered_lft'
# (note the kernel's spelling 'prefered' without the second 'r'
# — a long-standing typo PyTCP does NOT propagate; PyTCP uses
# the correct 'preferred' spelling).
ICMP6__TEMP_PREFERRED_LIFETIME_S: dict[str, int] = {"default": 86400}

# RFC 8981 §3.8 MAX_DESYNC_FACTOR — upper bound on the random
# offset subtracted from TEMP_PREFERRED_LIFETIME at address
# creation, preventing fleet-wide synchronised regeneration.
# Default 600 seconds (10 minutes). Linux exposes this as
# 'net.ipv6.conf.<iface>.max_desync_factor'.
ICMP6__MAX_DESYNC_FACTOR_S: dict[str, int] = {"default": 600}

# Linux net.ipv6.conf.<iface>.optimistic_dad policy. Controls
# whether RFC 4429 Optimistic DAD is used: when enabled, a
# tentative address is installed into '_ip6_ifaddr' as OPTIMISTIC
# immediately rather than waiting for DAD to pass. The address
# is usable as outbound source during the DAD probe period, but
# Neighbor Advertisements emitted while OPTIMISTIC clear the
# Override flag per RFC 4429 §3.3 so peers do not overwrite a
# possibly-existing cache entry on the basis of an unverified
# address. Default 0 (off) — Linux defaults to 0 too. RFC 8504
# §6.3 marks the feature as optional / MAY for general-purpose
# devices; it is primarily a mobility / fast-handover
# optimisation.
ICMP6__OPTIMISTIC_DAD: dict[str, int] = {"default": 0}

# RFC 7217 stable opaque IIDs — when enabled, SLAAC derives
# the Interface Identifier via SHA-256(prefix || mac ||
# dad_counter || secret_key) instead of the legacy EUI-64
# scheme that embeds the MAC unmodified. Stable per network
# but unlinkable across networks. Default 1, mirroring
# Linux's modern 'addr_gen_mode = 2' (the kernel default
# since 4.16). 0 falls back to EUI-64 — useful for testing
# and for callers that need MAC-derived addresses for
# legacy interop.
ICMP6__USE_RFC7217: dict[str, int] = {"default": 1}


def _accept_redirects_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.accept_redirects' must be 0 or 1; got {value!r}")


def _gratuitous_na_count_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero is
    explicitly admitted (kill switch).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"sysctl 'icmp6.gratuitous_na_count' must be a non-negative int; got {value!r}")


def _dad_transmits_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero is
    explicitly admitted (DAD disabled).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"sysctl 'icmp6.dad_transmits' must be a non-negative int; got {value!r}")


def _retrans_timer_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive values
    — RetransTimer = 0 would tight-loop the probe sender.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"sysctl 'icmp6.retrans_timer_ms' must be a positive int; got {value!r}")


def _accept_ra_defrtr_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.accept_ra_defrtr' must be 0 or 1; got {value!r}")


def _accept_ra_pinfo_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.accept_ra_pinfo' must be 0 or 1; got {value!r}")


def _accept_ra_min_hop_limit_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and out-of-range
    values — Cur-Hop-Limit is an 8-bit unsigned field, so the
    floor must fit in [0, 255]. Zero accepts any advertised
    Hop Limit.
    """

    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError(
            f"sysctl 'icmp6.accept_ra_min_hop_limit' must be an int in [0, 255]; got {value!r}",
        )


def _rtr_solicitation_interval_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values — IRT = 0 would tight-loop the RS sender.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.rtr_solicitation_interval_ms' must be a positive int; got {value!r}",
        )


def _rtr_solicitation_max_rt_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values — MRT must be at least the IRT default to give
    backoff room. Tests use much smaller values via override.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.rtr_solicitation_max_rt_ms' must be a positive int; got {value!r}",
        )


def _max_rtr_solicitations_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero
    is admitted (kill switch).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"sysctl 'icmp6.max_rtr_solicitations' must be a non-negative int; got {value!r}",
        )


def _enhanced_dad_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.enhanced_dad' must be 0 or 1; got {value!r}")


def _regen_advance_s_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero
    is admitted (regen exactly at preferred_until expiry).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"sysctl 'icmp6.regen_advance_s' must be a non-negative int; got {value!r}",
        )


def _temp_addr_sweep_interval_s_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values. A zero-interval sweep would tight-loop the
    subsystem; a negative interval is meaningless.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.temp_addr_sweep_interval_s' must be a positive int; got {value!r}",
        )


def _idgen_retries_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero
    is admitted (kill switch — disables retry).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"sysctl 'icmp6.idgen_retries' must be a non-negative int; got {value!r}",
        )


def _accept_dad_validator(value: object) -> None:
    """
    Reject values outside {0, 1, 2}. Booleans are rejected
    explicitly because 'isinstance(True, int)' is True in
    Python.
    """

    if isinstance(value, bool) or value not in (0, 1, 2):
        raise ValueError(f"sysctl 'icmp6.accept_dad' must be 0, 1, or 2; got {value!r}")


def _max_rtr_solicitation_delay_ms_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero
    is admitted (kill switch — disables the random initial
    delay).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"sysctl 'icmp6.max_rtr_solicitation_delay_ms' must be a non-negative int; got {value!r}",
        )


def _use_tempaddr_validator(value: object) -> None:
    """
    Reject values outside {0, 1, 2}. Booleans are rejected
    explicitly because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1, 2):
        raise ValueError(f"sysctl 'icmp6.use_tempaddr' must be 0, 1, or 2; got {value!r}")


def _temp_valid_lifetime_s_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values — TEMP_VALID_LIFETIME=0 would mean every temp
    address expires immediately on creation.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.temp_valid_lifetime_s' must be a positive int; got {value!r}",
        )


def _temp_preferred_lifetime_s_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and non-positive
    values. RFC 8981 §3.4 requires preferred ≤ valid; the
    cross-knob check is left to the consumer (the mutator
    clamps preferred against valid).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"sysctl 'icmp6.temp_preferred_lifetime_s' must be a positive int; got {value!r}",
        )


def _max_desync_factor_s_validator(value: Any) -> None:
    """
    Reject non-integer values, booleans, and negatives. Zero
    disables the desync jitter (deterministic regeneration —
    not recommended but a valid kill switch).
    """

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            f"sysctl 'icmp6.max_desync_factor_s' must be a non-negative int; got {value!r}",
        )


def _optimistic_dad_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.optimistic_dad' must be 0 or 1; got {value!r}")


def _use_rfc7217_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans are rejected explicitly
    because 'isinstance(True, int)' is True in Python.
    """

    if isinstance(value, bool) or value not in (0, 1):
        raise ValueError(f"sysctl 'icmp6.use_rfc7217' must be 0 or 1; got {value!r}")


register(
    key="icmp6.accept_redirects",
    module_name=__name__,
    attr="ICMP6__ACCEPT_REDIRECTS",
    default=ICMP6__ACCEPT_REDIRECTS["default"],
    validator=_accept_redirects_validator,
    interface_scope=True,
    description="Linux 'net.ipv6.conf.<iface>.accept_redirects' (0 = drop all RFC 4861 §8 Redirects; 1 = process).",
)
register(
    key="icmp6.gratuitous_na_count",
    module_name=__name__,
    attr="ICMP6__GRATUITOUS_NA_COUNT",
    default=ICMP6__GRATUITOUS_NA_COUNT["default"],
    validator=_gratuitous_na_count_validator,
    interface_scope=True,
    description="Number of gratuitous NAs emitted on host attachment (RFC 9131 §3); 0 = kill switch.",
)
register(
    key="icmp6.dad_transmits",
    module_name=__name__,
    attr="ICMP6__DAD_TRANSMITS",
    default=ICMP6__DAD_TRANSMITS["default"],
    validator=_dad_transmits_validator,
    interface_scope=True,
    description="Number of DAD probes per candidate address (RFC 4862 §5.1 DupAddrDetectTransmits); 0 disables DAD.",
)
register(
    key="icmp6.retrans_timer_ms",
    module_name=__name__,
    attr="ICMP6__RETRANS_TIMER_MS",
    default=ICMP6__RETRANS_TIMER_MS["default"],
    validator=_retrans_timer_ms_validator,
    interface_scope=True,
    description="Inter-probe wait between DAD probes in milliseconds (RFC 4861 §10 RetransTimer; default 1000).",
)
register(
    key="icmp6.accept_ra_defrtr",
    module_name=__name__,
    attr="ICMP6__ACCEPT_RA_DEFRTR",
    default=ICMP6__ACCEPT_RA_DEFRTR["default"],
    validator=_accept_ra_defrtr_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_ra_defrtr' "
        "(0 = drop default-router learning; 1 = process RFC 4861 §6.3.4)."
    ),
)
register(
    key="icmp6.accept_ra_pinfo",
    module_name=__name__,
    attr="ICMP6__ACCEPT_RA_PINFO",
    default=ICMP6__ACCEPT_RA_PINFO["default"],
    validator=_accept_ra_pinfo_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_ra_pinfo' " "(0 = drop PI consumption; 1 = process RFC 4862 §5.5.3)."
    ),
)
register(
    key="icmp6.accept_ra_min_hop_limit",
    module_name=__name__,
    attr="ICMP6__ACCEPT_RA_MIN_HOP_LIMIT",
    default=ICMP6__ACCEPT_RA_MIN_HOP_LIMIT["default"],
    validator=_accept_ra_min_hop_limit_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_ra_min_hop_limit' "
        "(floor for accepting Cur-Hop-Limit; 0 accepts any value)."
    ),
)
register(
    key="icmp6.rtr_solicitation_interval_ms",
    module_name=__name__,
    attr="ICMP6__RTR_SOLICITATION_INTERVAL_MS",
    default=ICMP6__RTR_SOLICITATION_INTERVAL_MS["default"],
    validator=_rtr_solicitation_interval_ms_validator,
    interface_scope=True,
    description=(
        "RFC 7559 §2 IRT (initial retransmission timeout) for " "the RS exponential-backoff loop; default 4000 ms."
    ),
)
register(
    key="icmp6.rtr_solicitation_max_rt_ms",
    module_name=__name__,
    attr="ICMP6__RTR_SOLICITATION_MAX_RT_MS",
    default=ICMP6__RTR_SOLICITATION_MAX_RT_MS["default"],
    validator=_rtr_solicitation_max_rt_ms_validator,
    interface_scope=True,
    description=(
        "RFC 7559 §2 MRT (maximum retransmission timeout) cap "
        "for the RS exponential-backoff loop; default 3600000 ms."
    ),
)
register(
    key="icmp6.max_rtr_solicitations",
    module_name=__name__,
    attr="ICMP6__MAX_RTR_SOLICITATIONS",
    default=ICMP6__MAX_RTR_SOLICITATIONS["default"],
    validator=_max_rtr_solicitations_validator,
    interface_scope=True,
    description=("RFC 4861 §6.3.7 MAX_RTR_SOLICITATIONS; default 3. " "0 disables RS entirely (kill switch)."),
)
register(
    key="icmp6.enhanced_dad",
    module_name=__name__,
    attr="ICMP6__ENHANCED_DAD",
    default=ICMP6__ENHANCED_DAD["default"],
    validator=_enhanced_dad_validator,
    interface_scope=True,
    description=(
        "RFC 7527 Enhanced DAD with Nonce option (Linux 'enhanced_dad'); "
        "default 1. 0 falls back to RFC 4861 plain DAD semantics."
    ),
)
register(
    key="icmp6.regen_advance_s",
    module_name=__name__,
    attr="ICMP6__REGEN_ADVANCE_S",
    default=ICMP6__REGEN_ADVANCE_S["default"],
    validator=_regen_advance_s_validator,
    interface_scope=True,
    description=(
        "RFC 8981 §3.8 REGEN_ADVANCE — seconds before "
        "preferred_lifetime expiry that a fresh temp address "
        "is regenerated; default 5. 0 disables advance regen."
    ),
)
register(
    key="icmp6.temp_addr_sweep_interval_s",
    module_name=__name__,
    attr="ICMP6__TEMP_ADDR_SWEEP_INTERVAL_S",
    default=ICMP6__TEMP_ADDR_SWEEP_INTERVAL_S["default"],
    validator=_temp_addr_sweep_interval_s_validator,
    interface_scope=True,
    description=(
        "Interval (seconds) between RFC 8981 temporary-address "
        "sweeps; default 60. Removes entries past 'valid_until' "
        "from both the temp-address table and '_ip6_ifaddr'."
    ),
)
register(
    key="icmp6.idgen_retries",
    module_name=__name__,
    attr="ICMP6__IDGEN_RETRIES",
    default=ICMP6__IDGEN_RETRIES["default"],
    validator=_idgen_retries_validator,
    interface_scope=True,
    description=(
        "RFC 7217 §6 IDGEN_RETRIES — number of times the host "
        "re-derives the IID and retries DAD on collision; "
        "default 3. 0 disables retry (give up on first failure)."
    ),
)
register(
    key="icmp6.accept_dad",
    module_name=__name__,
    attr="ICMP6__ACCEPT_DAD",
    default=ICMP6__ACCEPT_DAD["default"],
    validator=_accept_dad_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.accept_dad' tristate "
        "{0,1,2}; 0=skip DAD, 1=normal (default), 2=fail-hard "
        "(disable IPv6 on DAD failure)."
    ),
)
register(
    key="icmp6.max_rtr_solicitation_delay_ms",
    module_name=__name__,
    attr="ICMP6__MAX_RTR_SOLICITATION_DELAY_MS",
    default=ICMP6__MAX_RTR_SOLICITATION_DELAY_MS["default"],
    validator=_max_rtr_solicitation_delay_ms_validator,
    interface_scope=True,
    description=(
        "RFC 4861 §10 MAX_RTR_SOLICITATION_DELAY — random "
        "initial delay ceiling for the first DAD probe (RFC "
        "4862 §5.4.2) and first RS (RFC 4861 §6.3.7); default "
        "1000 ms. 0 disables the delay (kill switch)."
    ),
)
register(
    key="icmp6.use_tempaddr",
    module_name=__name__,
    attr="ICMP6__USE_TEMPADDR",
    default=ICMP6__USE_TEMPADDR["default"],
    validator=_use_tempaddr_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.use_tempaddr' (RFC 8981); "
        "tristate 0/1/2. 0=off, 1=generate without preference, "
        "2=generate and prefer (RFC 6724 rule 7)."
    ),
)
register(
    key="icmp6.temp_valid_lifetime_s",
    module_name=__name__,
    attr="ICMP6__TEMP_VALID_LIFETIME_S",
    default=ICMP6__TEMP_VALID_LIFETIME_S["default"],
    validator=_temp_valid_lifetime_s_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.temp_valid_lft' " "(RFC 8981 §3.8 TEMP_VALID_LIFETIME); default 604800 (7d)."
    ),
)
register(
    key="icmp6.temp_preferred_lifetime_s",
    module_name=__name__,
    attr="ICMP6__TEMP_PREFERRED_LIFETIME_S",
    default=ICMP6__TEMP_PREFERRED_LIFETIME_S["default"],
    validator=_temp_preferred_lifetime_s_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.temp_prefered_lft' "
        "(RFC 8981 §3.8 TEMP_PREFERRED_LIFETIME); default 86400 (1d)."
    ),
)
register(
    key="icmp6.max_desync_factor_s",
    module_name=__name__,
    attr="ICMP6__MAX_DESYNC_FACTOR_S",
    default=ICMP6__MAX_DESYNC_FACTOR_S["default"],
    validator=_max_desync_factor_s_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.max_desync_factor' " "(RFC 8981 §3.8 MAX_DESYNC_FACTOR); default 600 (10m)."
    ),
)
register(
    key="icmp6.optimistic_dad",
    module_name=__name__,
    attr="ICMP6__OPTIMISTIC_DAD",
    default=ICMP6__OPTIMISTIC_DAD["default"],
    validator=_optimistic_dad_validator,
    interface_scope=True,
    description=(
        "Linux 'net.ipv6.conf.<iface>.optimistic_dad' (RFC 4429 §3.1); " "default 0. 1 enables Optimistic DAD."
    ),
)
register(
    key="icmp6.use_rfc7217",
    module_name=__name__,
    attr="ICMP6__USE_RFC7217",
    default=ICMP6__USE_RFC7217["default"],
    validator=_use_rfc7217_validator,
    interface_scope=True,
    description=(
        "RFC 7217 stable opaque IIDs (Linux 'addr_gen_mode = 2'); " "default 1. 0 falls back to legacy EUI-64 IIDs."
    ),
)
