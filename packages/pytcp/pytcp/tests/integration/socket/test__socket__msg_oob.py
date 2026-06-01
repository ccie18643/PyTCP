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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Tests for the M3 row of the socket-layer Linux parity audit
('docs/refactor/socket_linux_parity_audit.md' §M3) — the
'MSG_OOB' / 'SO_OOBINLINE' Linux constants are exposed on
'pytcp.socket' so applications looking them up by name don't
hit ImportError, and 'SO_OOBINLINE' setsockopt enforces
PyTCP's RFC 6093 §6 universal-inline design constraint.

PyTCP's RFC 6093 adherence record
('docs/rfc/tcp/rfc6093__urgent_mechanism/adherence.md' §6)
documents that PyTCP delivers ALL inbound data inline
regardless of URG flag — the universalised
'SO_OOBINLINE=1' posture RFC 6093 §6 recommends. Apps that
attempt 'setsockopt(SO_OOBINLINE, 0)' are explicitly
opting INTO out-of-band delivery, which PyTCP does not
implement and which RFC 6093 §6 advises against; the
setsockopt rejects with 'OSError(EINVAL)' rather than
silently failing.

pytcp/tests/integration/socket/test__socket__msg_oob.py

ver 3.0.8
"""

import errno
from unittest import TestCase

from pytcp import stack
from pytcp.socket import (
    MSG_OOB,
    SO_OOBINLINE,
    SOL_SOCKET,
    AddressFamily,
)
from pytcp.socket.udp__socket import UdpSocket

_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


class TestSocketMsgOobConstants(TestCase):
    """
    Linux 'MSG_OOB' / 'SO_OOBINLINE' constant values are
    exposed at the canonical Linux integers so apps written
    against stdlib socket find them at the expected values.
    """

    def test__socket__msg_oob_constant_value(self) -> None:
        """
        Ensure 'MSG_OOB' exposes the Linux integer 1 — apps
        that test 'flags & MSG_OOB' or compare to the stdlib
        value see exact parity.

        Reference: Linux include/uapi/asm-generic/socket.h MSG_OOB=1.
        """

        self.assertEqual(
            int(MSG_OOB),
            1,
            msg="MSG_OOB must equal the Linux integer 1.",
        )

    def test__socket__so_oobinline_constant_value(self) -> None:
        """
        Ensure 'SO_OOBINLINE' exposes the Linux integer 10 —
        matches stdlib 'socket.SO_OOBINLINE'.

        Reference: Linux include/uapi/asm-generic/socket.h SO_OOBINLINE=10.
        """

        self.assertEqual(
            int(SO_OOBINLINE),
            10,
            msg="SO_OOBINLINE must equal the Linux integer 10.",
        )


class TestSocketSoOobinlineUniversalInline(TestCase):
    """
    'SO_OOBINLINE' surface — PyTCP enforces RFC 6093 §6's
    universal-inline recommendation, so getsockopt always
    returns 1 and setsockopt(0) is rejected.
    """

    def test__socket__so_oobinline_getsockopt_default_one(self) -> None:
        """
        Ensure 'getsockopt(SOL_SOCKET, SO_OOBINLINE)' returns
        1 on a freshly-constructed socket — PyTCP's universal-
        inline mode is the SO_OOBINLINE=1 posture the RFC
        recommends.

        Reference: RFC 6093 §6 (SO_OOBINLINE recommended for urgent).
        """

        sock = UdpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            sock.getsockopt(SOL_SOCKET, SO_OOBINLINE),
            1,
            msg="SO_OOBINLINE getsockopt must return 1 (PyTCP is universally inline).",
        )

    def test__socket__so_oobinline_setsockopt_one_accepted(self) -> None:
        """
        Ensure 'setsockopt(SOL_SOCKET, SO_OOBINLINE, 1)'
        succeeds as a no-op — the socket is already in the
        SO_OOBINLINE=1 state; explicitly setting it to 1
        confirms the intent without changing state.

        Reference: RFC 6093 §6 (SO_OOBINLINE=1 recommended posture).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.setsockopt(SOL_SOCKET, SO_OOBINLINE, 1)

        self.assertEqual(
            sock.getsockopt(SOL_SOCKET, SO_OOBINLINE),
            1,
            msg="SO_OOBINLINE=1 setsockopt must leave getsockopt returning 1.",
        )

    def test__socket__so_oobinline_setsockopt_zero_raises_einval(self) -> None:
        """
        Ensure 'setsockopt(SOL_SOCKET, SO_OOBINLINE, 0)'
        raises 'OSError(EINVAL)' — disabling SO_OOBINLINE
        would opt into out-of-band urgent-byte delivery,
        which PyTCP does not implement and which the RFC
        recommends against. The error message names the
        rationale so apps see actionable feedback.

        Reference: RFC 6093 §6 (avoid out-of-band urgent delivery).
        """

        sock = UdpSocket(family=AddressFamily.INET4)

        with self.assertRaises(OSError) as ctx:
            sock.setsockopt(SOL_SOCKET, SO_OOBINLINE, 0)
        self.assertEqual(
            ctx.exception.errno,
            errno.EINVAL,
            msg="setsockopt(SO_OOBINLINE, 0) must raise OSError(EINVAL).",
        )
