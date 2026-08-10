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
This package contains the per-state TCP finite-state-machine
handlers and the four event-kind dispatchers
('dispatch_packet', 'dispatch_syscall', 'dispatch_timer',
'dispatch_icmp') that route inbound events to the correct
per-state handler.

The 'fsm/' subpackage is an encapsulated unit: the four
dispatch functions are the sole public API. The dispatch-
table module ('tcp__fsm') and the eleven per-state handler
modules ('tcp__fsm__<state>') are PRIVATE to this subpackage.
Production code outside 'fsm/' MUST import only the
dispatchers and MUST do so via this '__init__' shim:

    from pytcp.protocols.tcp.fsm import (
        dispatch_packet,
        dispatch_syscall,
        dispatch_timer,
        dispatch_icmp,
    )

NEVER:

    from pytcp.protocols.tcp.fsm.tcp__fsm import dispatch_packet
    from pytcp.protocols.tcp.fsm.tcp__fsm__established import (
        fsm__established__packet,
    )

(The first deep form is reserved for the FSM unit test in
'tests/unit/protocols/tcp/fsm/test__tcp__fsm.py' which
exercises the dispatch-table dicts 'FSM_PACKET_HANDLERS' /
'FSM_SYSCALL_HANDLERS' / 'FSM_TIMER_HANDLERS' /
'FSM_ICMP_HANDLERS' directly. Production code does not need
that.)

The carve-out granting this '__init__' module non-empty
content is documented in '.claude/rules/source_files.md'
§2.4.1.

pytcp/protocols/tcp/fsm/__init__.py

ver 3.0.10
"""

from pytcp.protocols.tcp.fsm.tcp__fsm import (
    dispatch_icmp,
    dispatch_packet,
    dispatch_syscall,
    dispatch_timer,
)

__all__ = [
    "dispatch_icmp",
    "dispatch_packet",
    "dispatch_syscall",
    "dispatch_timer",
]
