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
This module contains the DHCPv6 packet options class.

net_proto/protocols/dhcp6/options/dhcp6__options.py

ver 3.0.8
"""

from abc import ABC
from typing import Self, override

from net_addr import Buffer, Ip6Address
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.dhcp6.dhcp6__errors import Dhcp6IntegrityError
from net_proto.protocols.dhcp6.dhcp6__header import DHCP6__HEADER__LEN
from net_proto.protocols.dhcp6.options.dhcp6__option import (
    DHCP6__OPTION__LEN,
    Dhcp6Option,
    Dhcp6OptionType,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__client_id import (
    Dhcp6OptionClientId,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__dns_servers import (
    Dhcp6OptionDnsServers,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__elapsed_time import (
    Dhcp6OptionElapsedTime,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__ia_addr import (
    Dhcp6OptionIaAddr,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__ia_na import (
    Dhcp6OptionIaNa,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__oro import (
    Dhcp6OptionOro,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__preference import (
    Dhcp6OptionPreference,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__rapid_commit import (
    Dhcp6OptionRapidCommit,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__server_id import (
    Dhcp6OptionServerId,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__status_code import (
    Dhcp6OptionStatusCode,
)
from net_proto.protocols.dhcp6.options.dhcp6__option__unknown import (
    Dhcp6OptionUnknown,
)


class Dhcp6Options(ProtoOptions):
    """
    The DHCPv6 packet options.
    """

    @property
    def client_id(self) -> bytes | None:
        """
        Get the DHCPv6 'client_id' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionClientId):
                return option.duid

        return None

    @property
    def server_id(self) -> bytes | None:
        """
        Get the DHCPv6 'server_id' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionServerId):
                return option.duid

        return None

    @property
    def ia_na(self) -> Dhcp6OptionIaNa | None:
        """
        Get the DHCPv6 'ia_na' option.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionIaNa):
                return option

        return None

    @property
    def ia_addr(self) -> Dhcp6OptionIaAddr | None:
        """
        Get the DHCPv6 'ia_addr' option.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionIaAddr):
                return option

        return None

    @property
    def oro(self) -> list[Dhcp6OptionType] | None:
        """
        Get the DHCPv6 'oro' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionOro):
                return option.requested_options

        return None

    @property
    def elapsed_time(self) -> int | None:
        """
        Get the DHCPv6 'elapsed_time' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionElapsedTime):
                return option.elapsed_time

        return None

    @property
    def preference(self) -> int | None:
        """
        Get the DHCPv6 'preference' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionPreference):
                return option.preference

        return None

    @property
    def status_code(self) -> Dhcp6OptionStatusCode | None:
        """
        Get the DHCPv6 'status_code' option.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionStatusCode):
                return option

        return None

    @property
    def rapid_commit(self) -> bool:
        """
        Get the DHCPv6 'rapid_commit' option value.

        Returns True when the zero-length Rapid Commit option is present
        (RFC 8415 §21.14); the option carries no data, so its presence
        is its value.
        """

        return any(isinstance(option, Dhcp6OptionRapidCommit) for option in self._options)

    @property
    def dns_servers(self) -> list[Ip6Address] | None:
        """
        Get the DHCPv6 'dns_servers' option value.
        """

        for option in self._options:
            if isinstance(option, Dhcp6OptionDnsServers):
                return option.dns_servers

        return None

    @staticmethod
    def validate_integrity(
        *,
        frame: Buffer,
        hlen: int,
        offset: int = DHCP6__HEADER__LEN,
    ) -> None:
        """
        Run the DHCPv6 options integrity checks before parsing options.

        The default 'offset' (DHCP6__HEADER__LEN = 4) walks the option
        block of a full DHCPv6 message; nested option blocks (e.g. the
        IA_NA / IA Address sub-options) call this with 'offset=0' against
        the re-extracted sub-block so a hostile nested option (length
        field extending past the slice end, truncated header, etc.) is
        rejected with a typed Dhcp6IntegrityError before
        'Dhcp6Options.from_buffer' dispatches.
        """

        while offset < hlen:
            # RFC 8415 §21.1 — every option carries a 4-byte
            # option-code + option-len header; a trailing fragment
            # shorter than that is a truncated option.
            if offset + DHCP6__OPTION__LEN > hlen:
                raise Dhcp6IntegrityError(
                    f"The DHCPv6 option is missing its 4-byte code+len header. Got: {offset=}, {hlen=}",
                )

            offset += DHCP6__OPTION__LEN + int.from_bytes(frame[offset + 2 : offset + 4])
            if offset > hlen:
                raise Dhcp6IntegrityError(
                    f"The DHCPv6 option length must not extend past the message length. Got: {offset=}, {hlen=}",
                )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the DHCPv6 options from buffer.
        """

        offset = 0
        options: list[Dhcp6Option] = []

        while offset < len(buffer):
            match Dhcp6OptionType.from_bytes(buffer[offset : offset + 2]):
                case Dhcp6OptionType.CLIENT_ID:
                    options.append(Dhcp6OptionClientId.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.SERVER_ID:
                    options.append(Dhcp6OptionServerId.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.IA_NA:
                    options.append(Dhcp6OptionIaNa.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.IA_ADDR:
                    options.append(Dhcp6OptionIaAddr.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.ORO:
                    options.append(Dhcp6OptionOro.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.PREFERENCE:
                    options.append(Dhcp6OptionPreference.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.ELAPSED_TIME:
                    options.append(Dhcp6OptionElapsedTime.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.STATUS_CODE:
                    options.append(Dhcp6OptionStatusCode.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.RAPID_COMMIT:
                    options.append(Dhcp6OptionRapidCommit.from_buffer(buffer[offset:]))
                case Dhcp6OptionType.DNS_SERVERS:
                    options.append(Dhcp6OptionDnsServers.from_buffer(buffer[offset:]))
                case _:
                    options.append(Dhcp6OptionUnknown.from_buffer(buffer[offset:]))

            offset += options[-1].len

        return cls(*options)


class Dhcp6OptionsProperties(ABC):
    """
    The DHCPv6 options properties mixin class.
    """

    _options: Dhcp6Options

    @property
    def client_id(self) -> bytes | None:
        """
        Get the DHCPv6 'client_id' option value.
        """

        return self._options.client_id

    @property
    def server_id(self) -> bytes | None:
        """
        Get the DHCPv6 'server_id' option value.
        """

        return self._options.server_id

    @property
    def ia_na(self) -> Dhcp6OptionIaNa | None:
        """
        Get the DHCPv6 'ia_na' option.
        """

        return self._options.ia_na

    @property
    def ia_addr(self) -> Dhcp6OptionIaAddr | None:
        """
        Get the DHCPv6 'ia_addr' option.
        """

        return self._options.ia_addr

    @property
    def oro(self) -> list[Dhcp6OptionType] | None:
        """
        Get the DHCPv6 'oro' option value.
        """

        return self._options.oro

    @property
    def elapsed_time(self) -> int | None:
        """
        Get the DHCPv6 'elapsed_time' option value.
        """

        return self._options.elapsed_time

    @property
    def preference(self) -> int | None:
        """
        Get the DHCPv6 'preference' option value.
        """

        return self._options.preference

    @property
    def status_code(self) -> Dhcp6OptionStatusCode | None:
        """
        Get the DHCPv6 'status_code' option.
        """

        return self._options.status_code

    @property
    def rapid_commit(self) -> bool:
        """
        Get the DHCPv6 'rapid_commit' option value.
        """

        return self._options.rapid_commit

    @property
    def dns_servers(self) -> list[Ip6Address] | None:
        """
        Get the DHCPv6 'dns_servers' option value.
        """

        return self._options.dns_servers
