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
This module contains tests for the NetProto package stack error classes.

net_proto/tests/unit/lib/test__lib__errors.py

ver 3.0.8
"""

from unittest import TestCase

from net_proto.lib.errors import (
    PacketIntegrityError,
    PacketSanityError,
    PacketValidationError,
    PyTcpError,
)


class TestNetProtoLibErrorsHierarchy(TestCase):
    """
    The NetProto lib errors class hierarchy tests.
    """

    def test__net_proto__lib__errors__pytcp_error__is_exception(self) -> None:
        """
        Ensure 'PyTcpError' subclasses 'Exception'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(PyTcpError, Exception),
            msg="PyTcpError must derive from Exception.",
        )

    def test__net_proto__lib__errors__packet_validation_error__is_pytcp_error(self) -> None:
        """
        Ensure 'PacketValidationError' subclasses 'PyTcpError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(PacketValidationError, PyTcpError),
            msg="PacketValidationError must derive from PyTcpError.",
        )

    def test__net_proto__lib__errors__packet_integrity_error__is_packet_validation_error(
        self,
    ) -> None:
        """
        Ensure 'PacketIntegrityError' subclasses 'PacketValidationError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(PacketIntegrityError, PacketValidationError),
            msg="PacketIntegrityError must derive from PacketValidationError.",
        )

    def test__net_proto__lib__errors__packet_sanity_error__is_packet_validation_error(
        self,
    ) -> None:
        """
        Ensure 'PacketSanityError' subclasses 'PacketValidationError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            issubclass(PacketSanityError, PacketValidationError),
            msg="PacketSanityError must derive from PacketValidationError.",
        )


class TestNetProtoLibErrorsPyTcpError(TestCase):
    """
    The NetProto lib errors PyTcpError tests.
    """

    def test__net_proto__lib__errors__pytcp_error__raising(self) -> None:
        """
        Ensure 'PyTcpError' can be raised and carry its message unchanged.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PyTcpError) as error:
            raise PyTcpError("root failure")

        self.assertEqual(str(error.exception), "root failure")

    def test__net_proto__lib__errors__pytcp_error__empty_message(self) -> None:
        """
        Ensure 'PyTcpError' can be raised without a message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PyTcpError) as error:
            raise PyTcpError()

        self.assertEqual(str(error.exception), "")


class TestNetProtoLibErrorsPacketValidationError(TestCase):
    """
    The NetProto lib errors PacketValidationError tests.
    """

    def test__net_proto__lib__errors__packet_validation_error__raising(self) -> None:
        """
        Ensure 'PacketValidationError' can be raised and carry its message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketValidationError) as error:
            raise PacketValidationError("validation failed")

        self.assertEqual(str(error.exception), "validation failed")

    def test__net_proto__lib__errors__packet_validation_error__catchable_as_pytcp_error(
        self,
    ) -> None:
        """
        Ensure 'PacketValidationError' is caught by 'PyTcpError' handlers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PyTcpError):
            raise PacketValidationError("validation failed")


class TestNetProtoLibErrorsPacketIntegrityError(TestCase):
    """
    The NetProto lib errors PacketIntegrityError tests.
    """

    def test__net_proto__lib__errors__packet_integrity_error__message_prefix(
        self,
    ) -> None:
        """
        Ensure 'PacketIntegrityError' prefixes the message with '[INTEGRITY ERROR]'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketIntegrityError) as error:
            raise PacketIntegrityError(" underlying failure")

        self.assertEqual(str(error.exception), "[INTEGRITY ERROR] underlying failure")

    def test__net_proto__lib__errors__packet_integrity_error__empty_message(
        self,
    ) -> None:
        """
        Ensure 'PacketIntegrityError' still emits the prefix for an empty message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketIntegrityError) as error:
            raise PacketIntegrityError("")

        self.assertEqual(str(error.exception), "[INTEGRITY ERROR]")

    def test__net_proto__lib__errors__packet_integrity_error__catchable_as_packet_validation_error(
        self,
    ) -> None:
        """
        Ensure 'PacketIntegrityError' is caught by 'PacketValidationError' handlers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketValidationError):
            raise PacketIntegrityError(" sample")

    def test__net_proto__lib__errors__packet_integrity_error__positional_only(
        self,
    ) -> None:
        """
        Ensure 'PacketIntegrityError' requires the message positionally.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            PacketIntegrityError(message=" sample")  # type: ignore[call-arg]


class TestNetProtoLibErrorsPacketSanityError(TestCase):
    """
    The NetProto lib errors PacketSanityError tests.
    """

    def test__net_proto__lib__errors__packet_sanity_error__message_prefix(
        self,
    ) -> None:
        """
        Ensure 'PacketSanityError' prefixes the message with '[SANITY ERROR]'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketSanityError) as error:
            raise PacketSanityError(" logical failure")

        self.assertEqual(str(error.exception), "[SANITY ERROR] logical failure")

    def test__net_proto__lib__errors__packet_sanity_error__empty_message(
        self,
    ) -> None:
        """
        Ensure 'PacketSanityError' still emits the prefix for an empty message.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketSanityError) as error:
            raise PacketSanityError("")

        self.assertEqual(str(error.exception), "[SANITY ERROR]")

    def test__net_proto__lib__errors__packet_sanity_error__catchable_as_packet_validation_error(
        self,
    ) -> None:
        """
        Ensure 'PacketSanityError' is caught by 'PacketValidationError' handlers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketValidationError):
            raise PacketSanityError(" sample")

    def test__net_proto__lib__errors__packet_sanity_error__positional_only(
        self,
    ) -> None:
        """
        Ensure 'PacketSanityError' requires the message positionally.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            PacketSanityError(message=" sample")  # type: ignore[call-arg]


class TestNetProtoLibErrorsDistinction(TestCase):
    """
    The NetProto lib errors distinction tests.
    """

    def test__net_proto__lib__errors__integrity_and_sanity_are_distinct(
        self,
    ) -> None:
        """
        Ensure integrity and sanity errors are not catchable as the opposite type.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(PacketIntegrityError):
            try:
                raise PacketIntegrityError(" boom")
            except PacketSanityError:  # pragma: no cover - defensive check
                self.fail("PacketIntegrityError must not be caught as PacketSanityError.")

        with self.assertRaises(PacketSanityError):
            try:
                raise PacketSanityError(" boom")
            except PacketIntegrityError:  # pragma: no cover - defensive check
                self.fail("PacketSanityError must not be caught as PacketIntegrityError.")
