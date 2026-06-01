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
This module contains the TCP runtime configuration constants — RTO /
retransmit budget, TIME-WAIT delay, delayed-ACK / challenge-ACK rate
limits, persist-timer ceiling, keep-alive timing, and the RFC 7323 §5.5
TS.Recent outdated-timestamps threshold. Every constant is exposed as a
policy sysctl ('tcp.*') so operators can tune the stack at boot via
'stack.init(sysctls={...})' or at runtime via
'pytcp.stack.sysctl["tcp...."] = N'. Runtime callers MUST read the
values via qualified module access (e.g.
'tcp__constants.TCP__RTO__INITIAL_MS') so each read re-resolves through
the backing module attribute the registry writes.

Extracted to a dedicated module so per-state FSM handler modules
('tcp__fsm__<state>.py') and the 'session/' subpackage can import these
constants without creating a circular import with 'tcp__session.py'.

pytcp/protocols/tcp/tcp__constants.py

ver 3.0.8
"""

# RFC 6298 §2.1 initial RTO. The first transmission of a fresh segment
# starts the retransmit timer at this value; subsequent retransmits
# back off exponentially, capped by the loss-recovery state machine.
TCP__RTO__INITIAL_MS = 1000

# RFC 1122 §4.2.3.5 R2 (incorporated by RFC 9293 §3.8.3) mandates that
# the connection-abort timeout be at least 100 s. With the exponential-
# backoff cadence of 1, 2, 4, 8, 16, 32, 64 s per retransmit, six
# retries reach t = 2**7 - 1 = 127 s before abort, just past the R2
# floor and matching the Linux 'tcp_syn_retries = 6' default. A lower
# count (e.g. 3 -> ~15 s) would violate the R2 floor and abort
# connections far sooner than the spec allows.
TCP__RETRANSMIT__MAX_COUNT = 6

# RFC 9293 §3.10.1 TIME-WAIT delay (2*MSL). The default of 30 s assumes
# an MSL of 15 s; Linux's 'tcp_fin_timeout' default is 60 s for a more
# conservative 30 s MSL.
TCP__TIME_WAIT__DELAY_MS = 30000

# RFC 1122 §4.2.3.2 / RFC 9293 §3.8.6.3 delayed-ACK delay. The
# receiver SHOULD coalesce ACKs to amortize the wire cost; the
# coalescing window MUST NOT exceed 500 ms.
TCP__DELAYED_ACK__DELAY_MS = 100

# RFC 5961 §3 / §4 challenge-ACK rate limit. The receiver SHOULD NOT
# emit more than one challenge ACK per sliding 1-second window, so a
# burst of unacceptable segments cannot amplify into an outbound ACK
# flood. Linux's default value matches.
TCP__CHALLENGE_ACK__RATE_LIMIT_MS = 1000

# RFC 9293 §3.8.6.1 / RFC 1122 §4.2.2.17 zero-window persist timer.
# The first probe fires after the current RTO (initial =
# TCP__RTO__INITIAL_MS), subsequent probes back off exponentially up to
# TCP__PERSIST__TIMEOUT_MAX_MS (60 s); RFC 1122 §4.2.2.17 requires
# probes to continue indefinitely while the peer's window stays at
# zero, so the timer never gives up — only the connection's R2 timeout
# (handled by '_retransmit_packet_timeout') tears the session down.
TCP__PERSIST__TIMEOUT_MAX_MS = 60_000

# RFC 1122 §4.2.3.6 TCP keep-alive. Optional mechanism to detect a peer
# that has silently gone away on an otherwise idle connection. RFC 1122
# requires:
#   - The mechanism MUST default to OFF; the application MUST be able
#     to enable / disable it per-connection (in PyTCP, via the
#     'KeepaliveState.enabled' flag).
#   - The keep-alive idle timer MUST default to no less than 2 hours.
# After the idle timer expires the session emits a probe ('ACK' with
# 'SEG.SEQ = SND.NXT - 1' so peer's TCP responds with a current-window
# ACK without the application observing any data); on probe-ack the
# idle timer is reset, on lack of response the probe is retransmitted
# every TCP__KEEPALIVE__PROBE_INTERVAL_MS up to
# TCP__KEEPALIVE__PROBE_MAX_COUNT times, at which point the connection
# is declared dead and torn down.
# Defaults match Linux: 7200 s idle, 75 s probe interval, 9 probes.
TCP__KEEPALIVE__IDLE_TIME_MS = 7_200_000
TCP__KEEPALIVE__PROBE_INTERVAL_MS = 75_000
TCP__KEEPALIVE__PROBE_MAX_COUNT = 9

# RFC 7323 §5.5 outdated-timestamps mitigation threshold.
# When the connection has been idle longer than this without updating
# TS.Recent, the next inbound segment whose TSval would otherwise fail
# strict PAWS is accepted instead — TS.Recent is treated as
# 'invalidated' per §5.5 to avoid permanently freezing a connection
# past the 24-day mark. 24 days at 1 ms granularity is roughly 2**31
# ms, the RFC's chosen worst-case TSval-clock sign-bit-wrap window; an
# exact integer of 24 * 86400 * 1000 ms is conservative and
# arithmetic-friendly.
TCP__TS_RECENT__OUTDATED_THRESHOLD_MS = 24 * 86_400 * 1_000

# Per-interface conf-plane policy storage. 'dict[str, int]' keyed by
# interface name with a mandatory '"default"' template slot — the
# operator addresses a specific interface ('tcp.<ifname>.<field>') or
# the template ('tcp.default.<field>'); the runtime read path
# ('TcpSession.__init__' / '_mss_ceiling' when active PLPMTUD probing
# is enabled) goes through 'sysctl_iface.get_for_iface(...)' which
# falls back from 'storage[<ifname>]' to 'storage["default"]'.
#
# Linux 'net.ipv4.tcp_base_mss' — the cold-start 'snd_mss' seed used
# when 'tcp.mtu_probing' enables active PLPMTUD probing on a session.
# Without this seed 'snd_mss' would saturate at 'interface_mtu -
# overhead' and the engine's 'candidate_mtu > snd_mss' probe-emit gate
# would never trip — making the RFC 4821 §3 'Probing without ICMP'
# scenario unreachable on the TCP transport. The default of 1024 (576
# IP datagram minus IP+TCP overhead, rounded up) matches Linux. The
# validator's '≥ 88' floor matches Linux's 'TCP_MIN_MSS' in
# 'include/net/tcp.h' and stays comfortably above the RFC 791 §3.1
# minimum-MTU arithmetic safety margin.
TCP__BASE_MSS: dict[str, int] = {"default": 1024}

# Linux 'net.ipv4.tcp_mtu_probing' tristate — the operator-facing
# enable for active PLPMTUD probing.
#   0 (default) = probing OFF. Cold-start seed in 'TcpSession.__init__'
#                 is skipped; behaviour identical to the pre-Phase-2
#                 baseline (snd_mss capped at 'interface_mtu - overhead'
#                 by the handshake clamp, classical PMTUD via ICMP PTB).
#   2           = probing ON ("always-on aggressive"). Session init
#                 seeds 'snd_mss' from 'tcp.base_mss - overhead' so the
#                 engine's 'candidate_mtu > snd_mss' gate trips on the
#                 first data send; handshake clamp consults the same
#                 ceiling so peer-advertised MSS does NOT raise
#                 snd_mss past the base.
# Linux's mode 1 ("enable after RTO loss suspected to be black-hole")
# needs heuristics PyTCP does not have today — it is rejected by the
# validator with a message naming the deferred-mode rationale. See
# 'docs/refactor/plpmtud_closeout.md' §2 for the deferred-with-rationale
# block.
TCP__MTU_PROBING: dict[str, int] = {"default": 0}


# Sysctl registration. Every constant above is a policy knob,
# operator-tunable at boot via 'stack.init(sysctls={"tcp....": ...})'
# or at runtime via 'pytcp.stack.sysctl["tcp...."] = N'. Per the
# framework's per-package-atomic rule, all ten land together — see
# 'docs/refactor/sysctl_migration_remaining.md' §4.
from typing import Any  # noqa: E402

from pytcp.stack.sysctl import (  # noqa: E402
    get,
    is_positive_int,
    register,
    register_finalize_validator,
)


def _is_positive_int_with_cap(name: str, *, high: int) -> Any:
    """
    Build a validator that requires a positive integer ≤ 'high'.
    Used for knobs with both a positive-int floor and an RFC-pinned
    inclusive ceiling (e.g. delayed-ACK's 500 ms cap).
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is a positive int ≤ high.
        """

        # 'isinstance(True, int)' is True in Python so booleans
        # would otherwise pass — reject them explicitly.
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > high:
            raise ValueError(
                f"sysctl {name!r} must be a positive int ≤ {high}; got {value!r}",
            )

    return validator


def _is_int_at_least(name: str, *, low: int) -> Any:
    """
    Build a validator that requires an integer ≥ 'low' — used for
    RFC-pinned floor knobs (e.g. keep-alive idle ≥ 2 h).
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is an int ≥ low.
        """

        if isinstance(value, bool) or not isinstance(value, int) or value < low:
            raise ValueError(
                f"sysctl {name!r} must be an int ≥ {low}; got {value!r}",
            )

    return validator


register(
    key="tcp.rto.initial_ms",
    module_name=__name__,
    attr="TCP__RTO__INITIAL_MS",
    default=TCP__RTO__INITIAL_MS,
    validator=is_positive_int("tcp.rto.initial_ms"),
    description="RFC 6298 §2.1 initial RTO in milliseconds.",
)
register(
    key="tcp.retransmit.max_count",
    module_name=__name__,
    attr="TCP__RETRANSMIT__MAX_COUNT",
    default=TCP__RETRANSMIT__MAX_COUNT,
    validator=is_positive_int("tcp.retransmit.max_count"),
    description="RFC 1122 §4.2.3.5 R2 budget — max retransmit count before connection abort.",
)
register(
    key="tcp.time_wait.delay_ms",
    module_name=__name__,
    attr="TCP__TIME_WAIT__DELAY_MS",
    default=TCP__TIME_WAIT__DELAY_MS,
    validator=is_positive_int("tcp.time_wait.delay_ms"),
    description="RFC 9293 §3.10.1 TIME-WAIT delay (2*MSL) in milliseconds.",
)
register(
    key="tcp.delayed_ack.delay_ms",
    module_name=__name__,
    attr="TCP__DELAYED_ACK__DELAY_MS",
    default=TCP__DELAYED_ACK__DELAY_MS,
    validator=_is_positive_int_with_cap("tcp.delayed_ack.delay_ms", high=500),
    description="RFC 1122 §4.2.3.2 delayed-ACK delay in milliseconds (RFC cap 500 ms).",
)
register(
    key="tcp.challenge_ack.rate_limit_ms",
    module_name=__name__,
    attr="TCP__CHALLENGE_ACK__RATE_LIMIT_MS",
    default=TCP__CHALLENGE_ACK__RATE_LIMIT_MS,
    validator=is_positive_int("tcp.challenge_ack.rate_limit_ms"),
    description="RFC 5961 §3 challenge-ACK rate-limit window in milliseconds.",
)
register(
    key="tcp.persist.timeout_max_ms",
    module_name=__name__,
    attr="TCP__PERSIST__TIMEOUT_MAX_MS",
    default=TCP__PERSIST__TIMEOUT_MAX_MS,
    validator=is_positive_int("tcp.persist.timeout_max_ms"),
    description="RFC 9293 §3.8.6.1 zero-window persist-timer ceiling in milliseconds.",
)
register(
    key="tcp.keepalive.idle_time_ms",
    module_name=__name__,
    attr="TCP__KEEPALIVE__IDLE_TIME_MS",
    default=TCP__KEEPALIVE__IDLE_TIME_MS,
    validator=_is_int_at_least("tcp.keepalive.idle_time_ms", low=7_200_000),
    description="RFC 1122 §4.2.3.6 keep-alive idle timer (ms); MUST be ≥ 2 hours (7200000 ms).",
)
register(
    key="tcp.keepalive.probe_interval_ms",
    module_name=__name__,
    attr="TCP__KEEPALIVE__PROBE_INTERVAL_MS",
    default=TCP__KEEPALIVE__PROBE_INTERVAL_MS,
    validator=is_positive_int("tcp.keepalive.probe_interval_ms"),
    description="RFC 1122 §4.2.3.6 keep-alive inter-probe interval in milliseconds.",
)
register(
    key="tcp.keepalive.probe_max_count",
    module_name=__name__,
    attr="TCP__KEEPALIVE__PROBE_MAX_COUNT",
    default=TCP__KEEPALIVE__PROBE_MAX_COUNT,
    validator=is_positive_int("tcp.keepalive.probe_max_count"),
    description="RFC 1122 §4.2.3.6 keep-alive unanswered-probe ceiling.",
)
register(
    key="tcp.ts_recent.outdated_threshold_ms",
    module_name=__name__,
    attr="TCP__TS_RECENT__OUTDATED_THRESHOLD_MS",
    default=TCP__TS_RECENT__OUTDATED_THRESHOLD_MS,
    validator=is_positive_int("tcp.ts_recent.outdated_threshold_ms"),
    description="RFC 7323 §5.5 outdated-timestamps threshold in milliseconds (~24 days).",
)
register(
    key="tcp.base_mss",
    module_name=__name__,
    attr="TCP__BASE_MSS",
    default=TCP__BASE_MSS["default"],
    validator=_is_int_at_least("tcp.base_mss", low=88),
    description=(
        "Linux 'net.ipv4.tcp_base_mss' — cold-start 'snd_mss' seed "
        "when 'tcp.mtu_probing' enables active PLPMTUD probing on "
        "a session (default 1024; floor 88 = Linux TCP_MIN_MSS)."
    ),
    interface_scope=True,
)


def _tcp_mtu_probing_validator(value: object) -> None:
    """
    Reject values outside {0, 2}.

    Mode 1 (Linux's "enable after RTO loss suspected to be a black-
    hole") needs heuristics PyTCP does not have today — it depends
    on observing a configurable burst of consecutive RTO timeouts
    with no successful ACK in between. Mode 2 ("always-on
    aggressive") is the simpler always-on alternative and is
    sufficient for the RFC 4821 §3 conformance case the PLPMTUD
    close-out targets. The rejection message names the
    deferred-mode rationale so an operator who chose mode 1 from
    Linux muscle memory sees actionable feedback.
    """

    if isinstance(value, bool) or value not in (0, 2):
        raise ValueError(
            f"sysctl 'tcp.mtu_probing' must be 0 (off) or 2 (always-on); "
            f"got {value!r}. Mode 1 (enable after RTO black-hole suspected) "
            f"is deferred — see docs/refactor/plpmtud_closeout.md."
        )


register(
    key="tcp.mtu_probing",
    module_name=__name__,
    attr="TCP__MTU_PROBING",
    default=TCP__MTU_PROBING["default"],
    validator=_tcp_mtu_probing_validator,
    description=(
        "Linux 'net.ipv4.tcp_mtu_probing' tristate — 0=off (default), "
        "2=always-on. Mode 1 is deferred (needs RTO-black-hole heuristic)."
    ),
    interface_scope=True,
)


def _finalize__persist_max_ge_rto_initial() -> None:
    """
    Cross-knob constraint — 'tcp.persist.timeout_max_ms' must be
    ≥ 'tcp.rto.initial_ms'. The persist back-off starts at the
    initial RTO and doubles until it hits the ceiling; a ceiling
    below the floor would make the back-off arithmetic invert.
    """

    if get("tcp.persist.timeout_max_ms") < get("tcp.rto.initial_ms"):
        raise ValueError(
            f"sysctl 'tcp.persist.timeout_max_ms' ({get('tcp.persist.timeout_max_ms')}) must be "
            f">= 'tcp.rto.initial_ms' ({get('tcp.rto.initial_ms')}); the persist back-off "
            f"starts at the initial RTO and doubles until it hits the ceiling.",
        )


register_finalize_validator(_finalize__persist_max_ge_rto_initial)
