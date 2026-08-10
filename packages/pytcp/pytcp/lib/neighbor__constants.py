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
This module contains the runtime configuration constants for
the generic Neighbour Unreachability Detection (NUD) state
machine at 'pytcp/lib/neighbor.py'. The NUD timing knobs apply
to both the IPv4 ARP cache and the IPv6 ND cache (per Linux's
'net/core/neighbour.c' factoring) and are exposed as sysctls
under the 'neighbor.*' namespace.

PyTCP uses seconds rather than Linux's milliseconds for every
timing knob — consistent with the existing ARP timing sysctls
and the 'time.monotonic()' arithmetic in the cache loop.

pytcp/lib/neighbor__constants.py

ver 3.0.10
"""

from typing import Any, Callable

from pytcp.stack.sysctl import get, is_positive_int, register, register_finalize_validator

# RFC 4861 §10 / Linux net.ipv4.neigh.<iface>.* defaults,
# scaled to seconds. The six per-interface knobs below
# (REACHABLE_TIME, DELAY_FIRST_PROBE_TIME, RETRANS_TIMER,
# MAX_UNICAST_SOLICIT, MAX_MULTICAST_SOLICIT, UNRES_QLEN)
# carry per-iface storage so a multi-homed host can express
# different NUD policies on different interfaces; the GC
# thresholds remain flat (table-wide).
#
# Storage shape: 'dict[str, int]' keyed by interface name
# with a mandatory '"default"' template slot. Operator
# addresses a specific iface ('neighbor.<ifname>.<field>')
# or the template ('neighbor.default.<field>'); the runtime
# read path (NeighborCache._subsystem_loop /
# _enqueue_pending) goes through
# 'sysctl_iface.get_for_iface(...)' with the cache's bound
# '_iface_name'. Plan: docs/refactor/sysctl_per_interface.md.

# Time a confirmed-reachable entry stays in NUD_REACHABLE
# before transitioning to NUD_STALE. Linux randomises this
# in [0.5, 1.5] × base_reachable_time per neighbour to avoid
# synchronised aging; PyTCP uses the base value directly for
# now (deterministic; refine when synchronised-aging surfaces
# as a real problem).
NEIGHBOR__REACHABLE_TIME: dict[str, int] = {"default": 30}

# Time a STALE entry stays in NUD_DELAY before promoting to
# NUD_PROBE in the absence of an upper-layer reachability
# confirmation. Window during which TCP's confirm_reachability
# hook can short-circuit the unicast probe.
NEIGHBOR__DELAY_FIRST_PROBE_TIME: dict[str, int] = {"default": 5}

# Time between successive solicits while in NUD_INCOMPLETE
# (multicast/broadcast) or NUD_PROBE (unicast). Linux uses
# 1 s by default for both code paths.
NEIGHBOR__RETRANS_TIMER: dict[str, int] = {"default": 1}

# Number of unicast solicits the cache attempts in NUD_PROBE
# before giving up and transitioning to NUD_FAILED.
NEIGHBOR__MAX_UNICAST_SOLICIT: dict[str, int] = {"default": 3}

# Number of multicast/broadcast solicits the cache attempts
# in NUD_INCOMPLETE before giving up and transitioning to
# NUD_FAILED.
NEIGHBOR__MAX_MULTICAST_SOLICIT: dict[str, int] = {"default": 3}

# Linux GC thresholds (Phase 5 of the NUD migration plan).
# Below thresh1: never GC. Above thresh2: GC after
# stale_time. Above thresh3: hard cap; eviction MUST run.
NEIGHBOR__GC_THRESH1 = 128
NEIGHBOR__GC_THRESH2 = 512
NEIGHBOR__GC_THRESH3 = 1024

# Time a STALE entry must persist before becoming
# GC-eligible at gc_thresh2 (Linux 'net.ipv4.neigh.default.
# gc_stale_time'; default 60 seconds). Distinct from
# 'reachable_time' (which gates REACHABLE → STALE) — this
# gates STALE → eviction once cache pressure crosses
# gc_thresh2.
NEIGHBOR__GC_STALE_TIME = 60

# Maximum number of outbound packets queued against a single
# unresolved neighbour while ARP/ND resolution is in flight
# (Linux 'net.ipv4.neigh.<iface>.unres_qlen'). On overflow the
# oldest queued packet is dropped. Linux moved from a 3-packet
# 'unres_qlen' to a byte-based 'unres_qlen_bytes' precisely so a
# fragmented datagram fits the queue; PyTCP keeps a packet-count
# knob and defaults it high enough to hold every fragment of a
# maximum-size IPv4 datagram at a 1500-byte MTU (~45 fragments).
NEIGHBOR__UNRES_QLEN: dict[str, int] = {"default": 64}


def _is_non_negative_int(name: str) -> Callable[[Any], None]:
    """
    Build a validator that requires a non-negative integer
    (>= 0) — used for GC thresholds where 0 means "never GC."
    """

    def validator(value: Any) -> None:
        """
        Raise 'ValueError' unless 'value' is a non-negative int.
        """

        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"sysctl {name!r} must be a non-negative int; got {value!r}")

    return validator


register(
    key="neighbor.reachable_time",
    module_name=__name__,
    attr="NEIGHBOR__REACHABLE_TIME",
    default=NEIGHBOR__REACHABLE_TIME["default"],
    validator=is_positive_int("neighbor.reachable_time"),
    description="NUD_REACHABLE lifetime, seconds (Linux base_reachable_time).",
    interface_scope=True,
)
register(
    key="neighbor.delay_first_probe_time",
    module_name=__name__,
    attr="NEIGHBOR__DELAY_FIRST_PROBE_TIME",
    default=NEIGHBOR__DELAY_FIRST_PROBE_TIME["default"],
    validator=is_positive_int("neighbor.delay_first_probe_time"),
    description="NUD_DELAY → NUD_PROBE timer, seconds.",
    interface_scope=True,
)
register(
    key="neighbor.retrans_timer",
    module_name=__name__,
    attr="NEIGHBOR__RETRANS_TIMER",
    default=NEIGHBOR__RETRANS_TIMER["default"],
    validator=is_positive_int("neighbor.retrans_timer"),
    description="Inter-solicit retransmit timer, seconds.",
    interface_scope=True,
)
register(
    key="neighbor.max_unicast_solicit",
    module_name=__name__,
    attr="NEIGHBOR__MAX_UNICAST_SOLICIT",
    default=NEIGHBOR__MAX_UNICAST_SOLICIT["default"],
    validator=is_positive_int("neighbor.max_unicast_solicit"),
    description="Max unicast probes in NUD_PROBE before NUD_FAILED.",
    interface_scope=True,
)
register(
    key="neighbor.max_multicast_solicit",
    module_name=__name__,
    attr="NEIGHBOR__MAX_MULTICAST_SOLICIT",
    default=NEIGHBOR__MAX_MULTICAST_SOLICIT["default"],
    validator=is_positive_int("neighbor.max_multicast_solicit"),
    description="Max multicast/broadcast probes in NUD_INCOMPLETE before NUD_FAILED.",
    interface_scope=True,
)
register(
    key="neighbor.gc_thresh1",
    module_name=__name__,
    attr="NEIGHBOR__GC_THRESH1",
    default=NEIGHBOR__GC_THRESH1,
    validator=_is_non_negative_int("neighbor.gc_thresh1"),
    description="GC threshold below which the cache never collects (default 128).",
)
register(
    key="neighbor.gc_thresh2",
    module_name=__name__,
    attr="NEIGHBOR__GC_THRESH2",
    default=NEIGHBOR__GC_THRESH2,
    validator=_is_non_negative_int("neighbor.gc_thresh2"),
    description="GC threshold above which stale entries are collected (default 512).",
)
register(
    key="neighbor.gc_thresh3",
    module_name=__name__,
    attr="NEIGHBOR__GC_THRESH3",
    default=NEIGHBOR__GC_THRESH3,
    validator=_is_non_negative_int("neighbor.gc_thresh3"),
    description="GC hard cap; eviction MUST run above this size (default 1024).",
)
register(
    key="neighbor.gc_stale_time",
    module_name=__name__,
    attr="NEIGHBOR__GC_STALE_TIME",
    default=NEIGHBOR__GC_STALE_TIME,
    validator=is_positive_int("neighbor.gc_stale_time"),
    description="Time STALE entries must age before GC-eligible above gc_thresh2, seconds.",
)
register(
    key="neighbor.unres_qlen",
    module_name=__name__,
    attr="NEIGHBOR__UNRES_QLEN",
    default=NEIGHBOR__UNRES_QLEN["default"],
    validator=is_positive_int("neighbor.unres_qlen"),
    description="Max packets queued per unresolved neighbour; drop-oldest on overflow.",
    interface_scope=True,
)


def _finalize__gc_thresh_ordering() -> None:
    """
    Cross-knob constraint — gc_thresh1 <= gc_thresh2 <=
    gc_thresh3. The eviction priority logic in the (Phase 5)
    GC pass relies on this ordering to decide which entries
    are GC-eligible at the current cache size.
    """

    t1 = get("neighbor.gc_thresh1")
    t2 = get("neighbor.gc_thresh2")
    t3 = get("neighbor.gc_thresh3")
    if not (t1 <= t2 <= t3):
        raise ValueError(
            f"sysctl 'neighbor.gc_thresh1/2/3' must satisfy "
            f"gc_thresh1 <= gc_thresh2 <= gc_thresh3; got "
            f"({t1}, {t2}, {t3})"
        )


register_finalize_validator(_finalize__gc_thresh_ordering)
