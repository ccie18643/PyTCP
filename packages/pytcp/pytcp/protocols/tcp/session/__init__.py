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
This package contains the per-session TCP machinery.

The 'session/' subpackage is an encapsulated unit: 'TcpSession'
and the read-only 'TcpInfoSnapshot' it returns from
'TcpSession.tcp_info()' are the public API. The five
collaborator modules ('tcp__session__timers' / '_tx' / '_ack' /
'_validate' / '_retransmit'), the 'tcp__session__info' snapshot
module, and the 'tcp__session' module that holds the class are
otherwise PRIVATE to this subpackage. Production code outside
'session/' MUST import only 'TcpSession' / 'TcpInfoSnapshot' and
MUST do so via this '__init__' shim:

    from pytcp.protocols.tcp.session import TcpSession, TcpInfoSnapshot

NEVER:

    from pytcp.protocols.tcp.session.tcp__session import TcpSession
    from pytcp.protocols.tcp.session.tcp__session__timers import TcpTimerService

(The second form is reserved for the collaborator-seam tests
in 'tests/integration/protocols/tcp/' which exercise each
collaborator class directly. Production code does not need it.)

The carve-out granting this '__init__' module non-empty
content is documented in '.claude/rules/source_files.md' §2.4
— it is a deliberate exception to the otherwise-uniform
"every non-top-level '__init__.py' is empty" rule, justified
by the encapsulation contract above.

pytcp/protocols/tcp/session/__init__.py

ver 3.0.9
"""

from pytcp.protocols.tcp.session.tcp__session import TcpSession
from pytcp.protocols.tcp.session.tcp__session__info import TcpInfoSnapshot

__all__ = ["TcpInfoSnapshot", "TcpSession"]
