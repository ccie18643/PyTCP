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
This module contains the DHCPv6 (RFC 8415) client constants. The
RFC-pinned wire values (UDP ports, the All_DHCP multicast group,
the §15 randomization factor) are protocol invariants; the
INFORMATION-REQUEST retransmission timers (§7.6) and the PyTCP
recv-budget bound are registered as 'pytcp.stack.sysctl' policy
knobs so operators can tune them via 'stack.init(sysctls={...})'
at boot or 'pytcp.stack.sysctl["dhcp6...."]' at runtime.

pytcp/protocols/dhcp6/dhcp6__constants.py

ver 3.0.10
"""

from net_addr import Ip6Address

# --- Protocol invariants (RFC-pinned; not operator-tunable) ---

# RFC 8415 §7.2 — DHCPv6 uses UDP. Clients listen on and send from
# port 546; servers (and relays) listen on port 547.
DHCP6__CLIENT_PORT = 546
DHCP6__SERVER_PORT = 547

# RFC 8415 §7.1 — All_DHCP_Relay_Agents_and_Servers, the link-scoped
# multicast group a client sends to when it has no configured server
# unicast address.
DHCP6__ALL_DHCP_RELAY_AGENTS_AND_SERVERS = Ip6Address("ff02::1:2")

# RFC 8415 §15 — the retransmission randomization factor RAND is drawn
# uniformly from the range [-0.1, +0.1]; this is the magnitude of that
# symmetric window.
DHCP6__RAND_FACTOR = 0.1


# --- Policy knobs (sysctl-backed) ---

# RFC 8415 §7.6 — INF_TIMEOUT, the initial Information-request timeout
# (IRT) feeding the §15 retransmission algorithm.
DHCP6__INF_TIMEOUT_MS = 1000

# RFC 8415 §7.6 — INF_MAX_RT, the maximum Information-request timeout
# (MRT) the doubled-and-capped backoff converges to (1 hour).
DHCP6__INF_MAX_RT_MS = 3600000

# RFC 8415 §7.6 / §18.2.6 — INF_MAX_DELAY, the upper bound of the
# random delay before the very first INFORMATION-REQUEST so a fleet of
# hosts powered on simultaneously does not all transmit at once. Drawn
# uniformly from [0, INF_MAX_DELAY]; set 0 to transmit immediately
# (useful for tests and short-lived containerised hosts).
DHCP6__INF_MAX_DELAY_MS = 1000

# PyTCP recv-budget bound. RFC 8415 §7.6 sets the Information-request
# MRC (max retransmission count) and MRD (max retransmission duration)
# to 0 — "no maximum" — i.e. a conformant client retransmits forever.
# PyTCP bounds the stateless recv loop to this many attempts so a
# missing server does not pin the client thread indefinitely; on
# exhaustion the stateless fetch returns no configuration and the
# caller may retry later.
DHCP6__RETRANS_MAX_ATTEMPTS = 5

# RFC 8415 §7.6 — SOL_TIMEOUT / SOL_MAX_RT, the initial (IRT) and
# maximum (MRT) Solicit retransmit timeouts. A Solicit has no MRC/MRD
# bound either; PyTCP reuses 'dhcp6.retrans_max_attempts' as the
# SOLICIT recv budget.
DHCP6__SOL_TIMEOUT_MS = 1000
DHCP6__SOL_MAX_RT_MS = 3600000

# RFC 8415 §7.6 / §18.2.1 — SOL_MAX_DELAY, the upper bound of the random
# delay before the very first SOLICIT so a fleet of hosts powered on
# simultaneously (or seeing the Managed RA flag at the same instant) does
# not all solicit at once. Drawn uniformly from [0, SOL_MAX_DELAY]; set 0
# to transmit immediately (useful for tests and short-lived containers).
DHCP6__SOL_MAX_DELAY_MS = 1000

# RFC 8415 §7.6 — REQ_TIMEOUT / REQ_MAX_RT / REQ_MAX_RC, the initial
# (IRT) and maximum (MRT) Request retransmit timeouts and the Request
# max retransmission count. Unlike Solicit, a Request is bounded by
# REQ_MAX_RC = 10; on exhaustion the client returns to Solicit.
DHCP6__REQ_TIMEOUT_MS = 1000
DHCP6__REQ_MAX_RT_MS = 30000
DHCP6__REQ_MAX_RC = 10

# RFC 8415 §7.6 — REN_TIMEOUT / REN_MAX_RT, the initial (IRT) and
# maximum (MRT) Renew retransmit timeouts. A Renew has no MRC; it is
# bounded by a max retransmission duration (MRD) equal to the time
# remaining until T2, after which the client gives up renewing and
# escalates to REBIND.
DHCP6__REN_TIMEOUT_MS = 10000
DHCP6__REN_MAX_RT_MS = 600000

# RFC 8415 §7.6 — REB_TIMEOUT / REB_MAX_RT, the initial (IRT) and
# maximum (MRT) Rebind retransmit timeouts. A Rebind has no MRC; it is
# bounded by an MRD equal to the time remaining until the leased
# address's valid lifetime expires, after which the client discards
# the lease and restarts from SOLICIT.
DHCP6__REB_TIMEOUT_MS = 10000
DHCP6__REB_MAX_RT_MS = 600000

# RFC 8415 §7.6 — REL_TIMEOUT / REL_MAX_RC, the initial Release
# retransmit timeout (IRT) and the Release max retransmission count.
# A Release is a best-effort teardown; on exhaustion the client stops
# regardless (the binding ages out server-side).
DHCP6__REL_TIMEOUT_MS = 1000
DHCP6__REL_MAX_RC = 5

# RFC 8415 §7.6 — DEC_TIMEOUT / DEC_MAX_RC, the initial Decline
# retransmit timeout (IRT) and the Decline max retransmission count
# (sent when a leased address fails Duplicate Address Detection).
DHCP6__DEC_TIMEOUT_MS = 1000
DHCP6__DEC_MAX_RC = 5

# RFC 8415 §18.2.1 / §21.14 — Rapid Commit opt-in. When set the client
# adds a Rapid Commit option to its SOLICIT and accepts a two-message
# SOLICIT / REPLY exchange (skipping ADVERTISE / REQUEST). It is a client
# MAY, so PyTCP defaults it off (0); set 1 to enable.
DHCP6__RAPID_COMMIT = 0

# RFC 8415 §14.2 / §18.2.4 — when the server returns T1 / T2 = 0 it
# leaves the renewal timers to the client's discretion. PyTCP derives
# them as fractions of the shortest IA_NA preferred lifetime: T1 (when
# RENEW begins) at 0.5 and T2 (when REBIND begins) at 0.8, the values
# Linux (systemd-networkd / dhclient -6) use.
DHCP6__T1_FACTOR: float = 0.5
DHCP6__T2_FACTOR: float = 0.8


from pytcp.stack.sysctl import (  # noqa: E402
    get,
    is_float_in_range,
    is_int_in_range,
    is_non_negative_int,
    is_positive_int,
    register,
    register_finalize_validator,
)

register(
    key="dhcp6.inf_timeout_ms",
    module_name=__name__,
    attr="DHCP6__INF_TIMEOUT_MS",
    default=DHCP6__INF_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.inf_timeout_ms"),
    description="RFC 8415 §7.6 — INF_TIMEOUT, initial INFORMATION-REQUEST retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.inf_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__INF_MAX_RT_MS",
    default=DHCP6__INF_MAX_RT_MS,
    validator=is_positive_int("dhcp6.inf_max_rt_ms"),
    description="RFC 8415 §7.6 — INF_MAX_RT, maximum INFORMATION-REQUEST retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.inf_max_delay_ms",
    module_name=__name__,
    attr="DHCP6__INF_MAX_DELAY_MS",
    default=DHCP6__INF_MAX_DELAY_MS,
    validator=is_non_negative_int("dhcp6.inf_max_delay_ms"),
    description=(
        "RFC 8415 §18.2.6 — INF_MAX_DELAY, upper bound of the random delay before the first "
        "INFORMATION-REQUEST in milliseconds (set 0 to transmit immediately)."
    ),
)
register(
    key="dhcp6.retrans_max_attempts",
    module_name=__name__,
    attr="DHCP6__RETRANS_MAX_ATTEMPTS",
    default=DHCP6__RETRANS_MAX_ATTEMPTS,
    validator=is_positive_int("dhcp6.retrans_max_attempts"),
    description=(
        "PyTCP recv budget — total INFORMATION-REQUEST / SOLICIT recv attempts before the "
        "fetch gives up (RFC 8415 §7.6 sets INF/SOL MRC/MRD to 0 = retransmit forever)."
    ),
)
register(
    key="dhcp6.sol_timeout_ms",
    module_name=__name__,
    attr="DHCP6__SOL_TIMEOUT_MS",
    default=DHCP6__SOL_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.sol_timeout_ms"),
    description="RFC 8415 §7.6 — SOL_TIMEOUT, initial SOLICIT retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.sol_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__SOL_MAX_RT_MS",
    default=DHCP6__SOL_MAX_RT_MS,
    validator=is_positive_int("dhcp6.sol_max_rt_ms"),
    description="RFC 8415 §7.6 — SOL_MAX_RT, maximum SOLICIT retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.rapid_commit",
    module_name=__name__,
    attr="DHCP6__RAPID_COMMIT",
    default=DHCP6__RAPID_COMMIT,
    validator=is_int_in_range("dhcp6.rapid_commit", low=0, high=1),
    description=(
        "RFC 8415 §18.2.1 / §21.14 — request the Rapid Commit two-message SOLICIT/REPLY "
        "exchange (1 = on, 0 = off / four-message)."
    ),
)
register(
    key="dhcp6.sol_max_delay_ms",
    module_name=__name__,
    attr="DHCP6__SOL_MAX_DELAY_MS",
    default=DHCP6__SOL_MAX_DELAY_MS,
    validator=is_non_negative_int("dhcp6.sol_max_delay_ms"),
    description=(
        "RFC 8415 §18.2.1 — SOL_MAX_DELAY, upper bound of the random delay before the first "
        "SOLICIT in milliseconds (set 0 to transmit immediately)."
    ),
)
register(
    key="dhcp6.req_timeout_ms",
    module_name=__name__,
    attr="DHCP6__REQ_TIMEOUT_MS",
    default=DHCP6__REQ_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.req_timeout_ms"),
    description="RFC 8415 §7.6 — REQ_TIMEOUT, initial REQUEST retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.req_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__REQ_MAX_RT_MS",
    default=DHCP6__REQ_MAX_RT_MS,
    validator=is_positive_int("dhcp6.req_max_rt_ms"),
    description="RFC 8415 §7.6 — REQ_MAX_RT, maximum REQUEST retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.req_max_rc",
    module_name=__name__,
    attr="DHCP6__REQ_MAX_RC",
    default=DHCP6__REQ_MAX_RC,
    validator=is_positive_int("dhcp6.req_max_rc"),
    description="RFC 8415 §7.6 — REQ_MAX_RC, REQUEST max retransmission count before returning to SOLICIT.",
)
register(
    key="dhcp6.ren_timeout_ms",
    module_name=__name__,
    attr="DHCP6__REN_TIMEOUT_MS",
    default=DHCP6__REN_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.ren_timeout_ms"),
    description="RFC 8415 §7.6 — REN_TIMEOUT, initial RENEW retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.ren_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__REN_MAX_RT_MS",
    default=DHCP6__REN_MAX_RT_MS,
    validator=is_positive_int("dhcp6.ren_max_rt_ms"),
    description="RFC 8415 §7.6 — REN_MAX_RT, maximum RENEW retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.reb_timeout_ms",
    module_name=__name__,
    attr="DHCP6__REB_TIMEOUT_MS",
    default=DHCP6__REB_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.reb_timeout_ms"),
    description="RFC 8415 §7.6 — REB_TIMEOUT, initial REBIND retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.reb_max_rt_ms",
    module_name=__name__,
    attr="DHCP6__REB_MAX_RT_MS",
    default=DHCP6__REB_MAX_RT_MS,
    validator=is_positive_int("dhcp6.reb_max_rt_ms"),
    description="RFC 8415 §7.6 — REB_MAX_RT, maximum REBIND retransmit timeout (MRT), ms.",
)
register(
    key="dhcp6.rel_timeout_ms",
    module_name=__name__,
    attr="DHCP6__REL_TIMEOUT_MS",
    default=DHCP6__REL_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.rel_timeout_ms"),
    description="RFC 8415 §7.6 — REL_TIMEOUT, initial RELEASE retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.rel_max_rc",
    module_name=__name__,
    attr="DHCP6__REL_MAX_RC",
    default=DHCP6__REL_MAX_RC,
    validator=is_positive_int("dhcp6.rel_max_rc"),
    description="RFC 8415 §7.6 — REL_MAX_RC, RELEASE max retransmission count.",
)
register(
    key="dhcp6.dec_timeout_ms",
    module_name=__name__,
    attr="DHCP6__DEC_TIMEOUT_MS",
    default=DHCP6__DEC_TIMEOUT_MS,
    validator=is_positive_int("dhcp6.dec_timeout_ms"),
    description="RFC 8415 §7.6 — DEC_TIMEOUT, initial DECLINE retransmit timeout (IRT), ms.",
)
register(
    key="dhcp6.dec_max_rc",
    module_name=__name__,
    attr="DHCP6__DEC_MAX_RC",
    default=DHCP6__DEC_MAX_RC,
    validator=is_positive_int("dhcp6.dec_max_rc"),
    description="RFC 8415 §7.6 — DEC_MAX_RC, DECLINE max retransmission count.",
)
register(
    key="dhcp6.t1_factor",
    module_name=__name__,
    attr="DHCP6__T1_FACTOR",
    default=DHCP6__T1_FACTOR,
    validator=is_float_in_range("dhcp6.t1_factor", low=0.0, high=1.0),
    description=(
        "RFC 8415 §14.2 — fraction of the shortest IA_NA preferred lifetime at which the "
        "client begins RENEW when the server returns T1=0. Default 0.5; must be ≤ 'dhcp6.t2_factor'."
    ),
)
register(
    key="dhcp6.t2_factor",
    module_name=__name__,
    attr="DHCP6__T2_FACTOR",
    default=DHCP6__T2_FACTOR,
    validator=is_float_in_range("dhcp6.t2_factor", low=0.0, high=1.0),
    description=(
        "RFC 8415 §14.2 — fraction of the shortest IA_NA preferred lifetime at which the "
        "client begins REBIND when the server returns T2=0. Default 0.8; must be ≥ 'dhcp6.t1_factor'."
    ),
)


def _finalize__irt_le_mrt(irt_key: str, mrt_key: str) -> None:
    """
    Cross-knob constraint — the IRT knob must be no greater than its
    paired MRT knob. The RFC 8415 §15 doubled-and-capped backoff with
    IRT > MRT would never actually double.
    """

    if get(irt_key) > get(mrt_key):
        raise ValueError(
            f"sysctl {irt_key!r} ({get(irt_key)}) must be ≤ {mrt_key!r} ({get(mrt_key)}); "
            f"the doubled-and-capped backoff would otherwise never advance.",
        )


def _finalize__t1_le_t2() -> None:
    """
    Cross-knob constraint — 'dhcp6.t1_factor' must be no greater than
    'dhcp6.t2_factor'. Otherwise T1 (RENEW) would fire after T2
    (REBIND), making the RENEW-before-REBIND ordering meaningless.
    """

    if get("dhcp6.t1_factor") > get("dhcp6.t2_factor"):
        raise ValueError(
            f"sysctl 'dhcp6.t1_factor' ({get('dhcp6.t1_factor')}) must be "
            f"≤ 'dhcp6.t2_factor' ({get('dhcp6.t2_factor')}); RENEW must precede REBIND.",
        )


register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.inf_timeout_ms", "dhcp6.inf_max_rt_ms"))
register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.sol_timeout_ms", "dhcp6.sol_max_rt_ms"))
register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.req_timeout_ms", "dhcp6.req_max_rt_ms"))
register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.ren_timeout_ms", "dhcp6.ren_max_rt_ms"))
register_finalize_validator(lambda: _finalize__irt_le_mrt("dhcp6.reb_timeout_ms", "dhcp6.reb_max_rt_ms"))
register_finalize_validator(_finalize__t1_le_t2)
