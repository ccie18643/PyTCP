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
This module contains the DHCPv4 client runtime-tunable policy
constants governing RFC 2131 §4.1 retransmission backoff and the
RFC 2131 §3.1 step 4 bounded NAK-restart loop. Every constant
below is registered as a 'pytcp.stack.sysctl' knob so operators
can tune it via 'stack.init(sysctls={...})' at boot or
'pytcp.stack.sysctl["dhcp...."]' at runtime.

pytcp/protocols/dhcp4/dhcp4__constants.py

ver 3.0.10
"""

# RFC 2131 §4.1 — DHCPv4 retransmission backoff. The first
# retransmit fires 4 seconds after the initial DISCOVER /
# REQUEST; each successive retransmit doubles the delay up to
# 64 seconds. Each delay is randomised by ±1 second so a fleet
# of hosts powered on simultaneously does not all retransmit
# at the same instant.
DHCP4__RETRANS_INITIAL_MS = 4000
DHCP4__RETRANS_MAX_MS = 64000
DHCP4__RETRANS_JITTER_MS = 1000

# Total retransmit attempts (recv waits) per
# '_discover_request_once' round-trip. With the doubling
# sequence 4 / 8 / 16 / 32 / 64 seconds, 5 attempts yields
# the ~124-second budget the RFC's §3.1 step 5 worked example
# describes.
DHCP4__RETRANS_MAX_ATTEMPTS = 5

# RFC 2131 §3.1 step 4 — on DHCPNAK the client returns to
# INIT and restarts from DHCPDISCOVER. Bound the restart loop
# so a server that keeps NAK'ing cannot pin the client in an
# infinite cycle. Default 3 = up to 4 total
# DISCOVER/REQUEST attempts (initial + 3 restarts).
DHCP4__NAK_MAX_RESTARTS = 3

# RFC 2131 §4.4.1 startup desynchronisation delay — "the
# client SHOULD wait a random time between one and ten
# seconds to desynchronize the use of DHCP at startup". The
# delay is drawn uniformly from
# '[init_delay_min_ms, init_delay_max_ms]' (milliseconds);
# setting both to 0 disables the wait (useful for tests
# and for short-lived containerised hosts where startup
# desync is unnecessary).
DHCP4__INIT_DELAY_MIN_MS = 1000
DHCP4__INIT_DELAY_MAX_MS = 10000

# RFC 2131 §3.1 step 5 post-DHCPDECLINE wait — "The client
# SHOULD wait a minimum of ten seconds before restarting
# the configuration process to avoid excessive network
# traffic in case of looping." 10 000 ms matches the SHOULD
# floor; setting 0 disables the wait for deterministic
# tests.
DHCP4__DECLINE_BACKOFF_MS = 10000

# RFC 4361 §6.1 operator-overridable DUID. Empty string =
# "auto-derive DUID-LL from the host MAC". Non-empty value
# = hex bytes (compact "0003000102..." or colon-separated
# "00:03:00:01:02:..."), used verbatim as the DUID
# embedded into the Client Identifier emitted in every
# DHCPv4 message. Consumed by 'pytcp.protocols.dhcp4.dhcp4__uid.get_duid'.
DHCP4__DUID: str = ""

# Phase 4 commit B — boot-blocking wait. 'stack.start()' calls
# 'Dhcp4Client.start_and_wait_for_bind(timeout=boot_wait_ms/1000)'
# to block until the FSM reaches BOUND or the timeout elapses.
# Default 30 000 ms matches Linux 'dhcpcd -t30' one-shot default.
# On timeout, the lifecycle keeps trying in the background; boot
# proceeds without IPv4 in the interim. Set 0 for "do not wait;
# return immediately" (the FSM still runs in the background).
DHCP4__BOOT_WAIT_MS = 30000

# Phase 4 commit C — RFC 2131 §4.4.5 lease-lifecycle timer
# defaults. T1 is the elapsed-since-acquired fraction at which
# the client begins RENEWING (unicast REQUEST to the server
# that issued the lease); T2 is the fraction at which the
# client escalates to REBINDING (broadcast REQUEST). Server
# options 58 / 59 (when present in the ACK) override these
# factor-based defaults — not yet honoured in commit C; planned
# for a follow-up.
DHCP4__T1_FACTOR: float = 0.5
DHCP4__T2_FACTOR: float = 0.875

# Phase 4 commit D — TCP-session abort policy on
# AddressApi-mediated address change (cross-IP RENEW/REBIND,
# lease expiry, DHCPRELEASE-on-shutdown). Default 1 = active
# abort per RFC 5227 §2.4-final SHOULD (deliberate deviation
# from Linux's silent-rot kernel behaviour). Set 0 for
# Linux-parity behaviour where the kernel silently lets TCP
# sessions on a removed address rot until application-level
# timeouts fire.
DHCP4__ABORT_SESSIONS_ON_LEASE_CHANGE = 1

# Phase 5 — RFC 2131 §3.2 / §4.4.2 cached-lease persistence.
# When set to a non-empty filesystem path, 'Dhcp4Client'
# serialises every BOUND lease to this file (JSON, atomic
# rename) and consults it on startup; if the cached lease is
# still within its 'lease_time' the client begins in
# INIT-REBOOT and broadcasts a single REQUEST that asks the
# server to re-confirm the prior IP. Empty string = "in-memory
# only; never persist". The canonical Linux default would be
# '/var/lib/pytcp/dhcp4_lease', but PyTCP defaults to empty
# so out-of-the-box behaviour does not silently touch disk.
DHCP4__LEASE_CACHE_PATH: str = ""

# Phase 5 — RFC 2131 §4.4.2 "If the client receives neither a
# DHCPACK nor a DHCPNAK message after 60 seconds / 4 tries,
# the client MAY choose to use the previously allocated
# network address and configuration parameters for the
# remainder of the unexpired lease." PyTCP reuses the Phase 1
# retransmission backoff for the recv loop and bounds it to
# this many attempts; on exhaustion the cached lease is
# adopted as-is and the FSM transitions to BOUND.
DHCP4__REBOOT_MAX_ATTEMPTS = 4

# Phase 6 — RFC 4436 DNAv4 (Detecting Network Attachment in
# IPv4). When non-zero and a cached lease records the
# gateway's MAC, the INIT-REBOOT entry path first sends a
# unicast ARP Request to the cached gateway and waits up to
# 'dhcp.dnav4_timeout_ms' for a reply. If the reply arrives,
# the host is on the same L2 segment as before, the cached
# lease is adopted as-is, and the DHCP exchange is skipped
# entirely (RFC 4436 §4). On miss / disabled, the FSM falls
# through to the standard RFC 2131 §4.4.2 INIT-REBOOT
# REQUEST. Default 1 = enabled; set 0 to force the standard
# path for testing.
DHCP4__DNAV4 = 1
DHCP4__DNAV4_TIMEOUT_MS = 1000

# Phase 8.1 — RFC 2132 §9.10 Maximum DHCP Message Size
# option. The client advertises this value in DISCOVER /
# REQUEST so the server may emit replies larger than the
# RFC 2131 §2 baseline 576-byte minimum. Default 1500 ≈ the
# standard Ethernet interface MTU; minimum 576 per RFC.
DHCP4__MAX_MSG_SIZE = 1500

# Phase 8.2 — RFC 2131 §3.5 / §4.4.1 lease-time hint. When
# non-zero, the client emits a Lease Time option in DISCOVER
# suggesting how long it would like the lease to be. The
# server is free to honour or ignore the hint; the actual
# lease length on the ACK wins. Default 86400 = 1 day,
# matching Linux 'dhclient' / 'dhcpcd' out-of-the-box.
DHCP4__REQUESTED_LEASE_TIME__SEC = 86400

# Phase 8.x — RFC 2131 §4.4.1 multi-OFFER collection window.
# After the first valid DHCPOFFER, the client keeps listening
# for additional OFFERs for this many milliseconds before
# selecting one and proceeding to REQUEST. The selection
# policy is "first received within the window" — the same
# selection a 0-ms window would make, but with all competing
# OFFERs logged for operator visibility. This matches dhcpcd's
# 'OFFER_TIMEOUT' and ISC dhclient's behaviour around the
# 'INITIAL_INTERVAL' window. Default 3000 ms is a middle
# ground between dhcpcd's typical ~5 s and a tight-boot 0.
# Setting 0 disables the collection window — the RFC 2131
# §4.4.1 "e.g. the first DHCPOFFER message" example is
# strictly RFC-compliant in that mode.
DHCP4__OFFER_COLLECTION_MS = 3000

from typing import Callable  # noqa: E402

from pytcp.stack.sysctl import (  # noqa: E402
    get,
    is_float_in_range,
    is_non_negative_int,
    is_positive_int,
    register,
    register_finalize_validator,
)

register(
    key="dhcp.retrans_initial_ms",
    module_name=__name__,
    attr="DHCP4__RETRANS_INITIAL_MS",
    default=DHCP4__RETRANS_INITIAL_MS,
    validator=is_positive_int("dhcp.retrans_initial_ms"),
    description="RFC 2131 §4.1 — initial retransmit delay in milliseconds (first retransmit at 4 s).",
)
register(
    key="dhcp.retrans_max_ms",
    module_name=__name__,
    attr="DHCP4__RETRANS_MAX_MS",
    default=DHCP4__RETRANS_MAX_MS,
    validator=is_positive_int("dhcp.retrans_max_ms"),
    description="RFC 2131 §4.1 — maximum retransmit delay in milliseconds (delays doubled up to 64 s).",
)
register(
    key="dhcp.retrans_max_attempts",
    module_name=__name__,
    attr="DHCP4__RETRANS_MAX_ATTEMPTS",
    default=DHCP4__RETRANS_MAX_ATTEMPTS,
    validator=is_positive_int("dhcp.retrans_max_attempts"),
    description="Phase 1 retransmit budget — total recv attempts before giving up (default 5 = ~124 s).",
)
register(
    key="dhcp.retrans_jitter_ms",
    module_name=__name__,
    attr="DHCP4__RETRANS_JITTER_MS",
    default=DHCP4__RETRANS_JITTER_MS,
    validator=is_non_negative_int("dhcp.retrans_jitter_ms"),
    description=(
        "RFC 2131 §4.1 — uniform ±jitter window around each " "retransmit delay (set 0 for deterministic backoff)."
    ),
)
register(
    key="dhcp.nak_max_restarts",
    module_name=__name__,
    attr="DHCP4__NAK_MAX_RESTARTS",
    default=DHCP4__NAK_MAX_RESTARTS,
    validator=is_non_negative_int("dhcp.nak_max_restarts"),
    description="RFC 2131 §3.1 step 4 — NAK-driven restart budget per fetch() (default 3 = up to 4 attempts).",
)
register(
    key="dhcp.init_delay_min_ms",
    module_name=__name__,
    attr="DHCP4__INIT_DELAY_MIN_MS",
    default=DHCP4__INIT_DELAY_MIN_MS,
    validator=is_non_negative_int("dhcp.init_delay_min_ms"),
    description=(
        "RFC 2131 §4.4.1 — lower bound of the startup "
        "desynchronisation delay in milliseconds (set 0 with "
        "max=0 to disable for tests)."
    ),
)
register(
    key="dhcp.init_delay_max_ms",
    module_name=__name__,
    attr="DHCP4__INIT_DELAY_MAX_MS",
    default=DHCP4__INIT_DELAY_MAX_MS,
    validator=is_non_negative_int("dhcp.init_delay_max_ms"),
    description=(
        "RFC 2131 §4.4.1 — upper bound of the startup "
        "desynchronisation delay in milliseconds (set 0 with "
        "min=0 to disable for tests)."
    ),
)
register(
    key="dhcp.decline_backoff_ms",
    module_name=__name__,
    attr="DHCP4__DECLINE_BACKOFF_MS",
    default=DHCP4__DECLINE_BACKOFF_MS,
    validator=is_non_negative_int("dhcp.decline_backoff_ms"),
    description=(
        "RFC 2131 §3.1 step 5 — post-DHCPDECLINE wait in "
        "milliseconds before restarting from DISCOVER "
        "(SHOULD ≥ 10 s; set 0 to disable for tests)."
    ),
)


def _is_duid_hex_or_empty(name: str) -> Callable[[object], None]:
    """
    Build a validator that accepts the empty string ('auto-derive
    from MAC' signal) or a hex string with optional colon
    separators ("0003000102..." / "00:03:00:01:02:..."). Rejects
    non-string types, odd-length hex, and non-hex characters.
    """

    def validator(value: object) -> None:
        if not isinstance(value, str):
            raise ValueError(f"sysctl {name!r} must be a string; got {type(value).__name__}")
        if value == "":
            return
        normalised = value.replace(":", "")
        if len(normalised) % 2 != 0:
            raise ValueError(f"sysctl {name!r} hex value must have an even number of digits; " f"got {value!r}")
        try:
            bytes.fromhex(normalised)
        except ValueError as error:
            raise ValueError(
                f"sysctl {name!r} must be valid hex (optionally colon-separated); " f"got {value!r}"
            ) from error

    return validator


register(
    key="dhcp.duid",
    module_name=__name__,
    attr="DHCP4__DUID",
    default=DHCP4__DUID,
    validator=_is_duid_hex_or_empty("dhcp.duid"),
    description=(
        "RFC 4361 §6.1 DUID override — hex bytes (compact or "
        "colon-separated) used as the DUID portion of the "
        "Client Identifier; empty = auto-derive DUID-LL from "
        "the host MAC."
    ),
)
register(
    key="dhcp.boot_wait_ms",
    module_name=__name__,
    attr="DHCP4__BOOT_WAIT_MS",
    default=DHCP4__BOOT_WAIT_MS,
    validator=is_non_negative_int("dhcp.boot_wait_ms"),
    description=(
        "Boot-time wait (milliseconds) for the DHCPv4 lifecycle "
        "to reach BOUND before proceeding without IPv4 "
        "(default 30 000 = Linux 'dhcpcd -t30'; set 0 to skip "
        "the boot wait entirely)."
    ),
)
register(
    key="dhcp.t1_factor",
    module_name=__name__,
    attr="DHCP4__T1_FACTOR",
    default=DHCP4__T1_FACTOR,
    validator=is_float_in_range("dhcp.t1_factor", low=0.0, high=1.0),
    description=(
        "RFC 2131 §4.4.5 — fraction of the lease duration at which "
        "the client begins RENEWING (unicast REQUEST). Default 0.5; "
        "must be ≤ 'dhcp.t2_factor'."
    ),
)
register(
    key="dhcp.t2_factor",
    module_name=__name__,
    attr="DHCP4__T2_FACTOR",
    default=DHCP4__T2_FACTOR,
    validator=is_float_in_range("dhcp.t2_factor", low=0.0, high=1.0),
    description=(
        "RFC 2131 §4.4.5 — fraction of the lease duration at which "
        "the client escalates to REBINDING (broadcast REQUEST). "
        "Default 0.875; must be ≥ 'dhcp.t1_factor'."
    ),
)


def _is_string(name: str) -> Callable[[object], None]:
    """
    Build a validator that accepts any string (including empty).
    Reserved for sysctls whose value is a filesystem path or
    other opaque text consumed by their reader; no further
    structural check is appropriate here because the consumer
    surfaces a clearer error on first use.
    """

    def validator(value: object) -> None:
        if not isinstance(value, str):
            raise ValueError(f"sysctl {name!r} must be a string; got {type(value).__name__}")

    return validator


register(
    key="dhcp.lease_cache_path",
    module_name=__name__,
    attr="DHCP4__LEASE_CACHE_PATH",
    default=DHCP4__LEASE_CACHE_PATH,
    validator=_is_string("dhcp.lease_cache_path"),
    description=(
        "RFC 2131 §3.2 / §4.4.2 — filesystem path for the cached "
        "DHCPv4 lease (JSON, atomic rename). Empty = in-memory only; "
        "never persist."
    ),
)
register(
    key="dhcp.reboot_max_attempts",
    module_name=__name__,
    attr="DHCP4__REBOOT_MAX_ATTEMPTS",
    default=DHCP4__REBOOT_MAX_ATTEMPTS,
    validator=is_positive_int("dhcp.reboot_max_attempts"),
    description=(
        "RFC 2131 §4.4.2 — recv attempts for the INIT-REBOOT REQUEST "
        "before adopting the cached lease as-is (default 4 ≈ 60 s "
        "via the Phase 1 backoff)."
    ),
)


def _is_zero_or_one(name: str) -> Callable[[object], None]:
    """
    Build a validator that accepts only {0, 1}. Booleans are
    rejected because 'isinstance(True, int)' is True; the
    sysctl is an integer-valued operator switch, not a bool.
    """

    def validator(value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1):
            raise ValueError(f"sysctl {name!r} must be 0 or 1; got {value!r}")

    return validator


register(
    key="dhcp.dnav4",
    module_name=__name__,
    attr="DHCP4__DNAV4",
    default=DHCP4__DNAV4,
    validator=_is_zero_or_one("dhcp.dnav4"),
    description=(
        "RFC 4436 DNAv4 enable bit (0/1; default 1). When set, "
        "the INIT-REBOOT path first sends a unicast ARP Request "
        "to the cached gateway and short-circuits DHCP entirely "
        "if it answers within 'dhcp.dnav4_timeout_ms'."
    ),
)
register(
    key="dhcp.dnav4_timeout_ms",
    module_name=__name__,
    attr="DHCP4__DNAV4_TIMEOUT_MS",
    default=DHCP4__DNAV4_TIMEOUT_MS,
    validator=is_positive_int("dhcp.dnav4_timeout_ms"),
    description=(
        "RFC 4436 §4 — DNAv4 unicast-ARP probe timeout in "
        "milliseconds (default 1000 = the RFC's recommended "
        "1-second window)."
    ),
)


def _is_max_msg_size(name: str) -> Callable[[object], None]:
    """
    Build a validator that accepts a uint16 ≥ 576 per RFC 2132
    §9.10 (the RFC 2131 §2 baseline minimum every client MUST
    accept). Rejects non-integers and out-of-range values
    explicitly so a misconfiguration cannot silently emit a
    smaller advertised size than the spec floor.
    """

    def validator(value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"sysctl {name!r} must be an int; got {type(value).__name__}")
        if not (576 <= value <= 0xFFFF):
            raise ValueError(
                f"sysctl {name!r} must be in [576, 65535] per RFC 2132 §9.10; got {value!r}",
            )

    return validator


register(
    key="dhcp.max_msg_size",
    module_name=__name__,
    attr="DHCP4__MAX_MSG_SIZE",
    default=DHCP4__MAX_MSG_SIZE,
    validator=_is_max_msg_size("dhcp.max_msg_size"),
    description=(
        "RFC 2132 §9.10 Maximum DHCP Message Size advertised "
        "in DISCOVER / REQUEST (default 1500 ≈ Ethernet MTU; "
        "minimum 576 per RFC)."
    ),
)
register(
    key="dhcp.requested_lease_time__sec",
    module_name=__name__,
    attr="DHCP4__REQUESTED_LEASE_TIME__SEC",
    default=DHCP4__REQUESTED_LEASE_TIME__SEC,
    validator=is_non_negative_int("dhcp.requested_lease_time__sec"),
    description=(
        "RFC 2131 §3.5 — desired lease-time hint emitted in "
        "DISCOVER (default 86400 = 1 day; set 0 to omit the "
        "hint entirely)."
    ),
)
register(
    key="dhcp.offer_collection_ms",
    module_name=__name__,
    attr="DHCP4__OFFER_COLLECTION_MS",
    default=DHCP4__OFFER_COLLECTION_MS,
    validator=is_non_negative_int("dhcp.offer_collection_ms"),
    description=(
        "RFC 2131 §4.4.1 multi-OFFER collection window in "
        "milliseconds (default 3000 = dhcpcd-alike). After "
        "the first valid OFFER, wait this long for "
        "additional OFFERs before selecting the first one "
        "and proceeding to REQUEST. Set 0 to disable "
        "(strictly RFC-compliant 'first DHCPOFFER message' "
        "behaviour)."
    ),
)


def _abort_sessions_validator(value: object) -> None:
    """
    Reject values outside {0, 1}. Booleans rejected because
    'isinstance(True, int)' is True and the sysctl is an
    integer-valued operator switch, not a bool. The explicit
    'isinstance(value, int)' check also rejects '1.0' (float)
    so the operator surface is strict-int.
    """

    if isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1):
        raise ValueError(
            f"sysctl 'dhcp.abort_sessions_on_lease_change' must be 0 or 1; got {value!r}",
        )


register(
    key="dhcp.abort_sessions_on_lease_change",
    module_name=__name__,
    attr="DHCP4__ABORT_SESSIONS_ON_LEASE_CHANGE",
    default=DHCP4__ABORT_SESSIONS_ON_LEASE_CHANGE,
    validator=_abort_sessions_validator,
    description=(
        "TCP-session abort policy on DHCP-driven address change "
        "(0/1; default 1 = active abort per RFC 5227 §2.4-final "
        "SHOULD; 0 = Linux-parity silent-rot)."
    ),
)


def _finalize__retrans_initial_le_max() -> None:
    """
    Cross-knob constraint — 'dhcp.retrans_initial_ms' must be
    no greater than 'dhcp.retrans_max_ms'. A doubled-and-capped
    backoff with 'initial > max' would never actually double.
    """

    if get("dhcp.retrans_initial_ms") > get("dhcp.retrans_max_ms"):
        raise ValueError(
            f"sysctl 'dhcp.retrans_initial_ms' ({get('dhcp.retrans_initial_ms')}) must be "
            f"≤ 'dhcp.retrans_max_ms' ({get('dhcp.retrans_max_ms')}); the doubled-and-capped "
            f"backoff would otherwise never advance.",
        )


def _finalize__init_delay_min_le_max() -> None:
    """
    Cross-knob constraint — 'dhcp.init_delay_min_ms' must be
    no greater than 'dhcp.init_delay_max_ms'. The
    'random.uniform(min, max)' draw is undefined when
    'min > max'.
    """

    if get("dhcp.init_delay_min_ms") > get("dhcp.init_delay_max_ms"):
        raise ValueError(
            f"sysctl 'dhcp.init_delay_min_ms' ({get('dhcp.init_delay_min_ms')}) must be "
            f"≤ 'dhcp.init_delay_max_ms' ({get('dhcp.init_delay_max_ms')}); the "
            f"'random.uniform(min, max)' draw is undefined otherwise.",
        )


def _finalize__t1_le_t2() -> None:
    """
    Cross-knob constraint — 'dhcp.t1_factor' must be no greater
    than 'dhcp.t2_factor'. Otherwise T1 fires AFTER T2, which
    makes the RENEWING-before-REBINDING ordering meaningless.
    """

    if get("dhcp.t1_factor") > get("dhcp.t2_factor"):
        raise ValueError(
            f"sysctl 'dhcp.t1_factor' ({get('dhcp.t1_factor')}) must be "
            f"≤ 'dhcp.t2_factor' ({get('dhcp.t2_factor')}); RENEWING must precede REBINDING.",
        )


register_finalize_validator(_finalize__retrans_initial_le_max)
register_finalize_validator(_finalize__init_delay_min_le_max)
register_finalize_validator(_finalize__t1_le_t2)
