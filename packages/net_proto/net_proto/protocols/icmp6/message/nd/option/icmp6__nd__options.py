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
This module contains the ICMPv6 Neighbor Discovery option support classes.

net_proto/protocols/icmp6/message/nd/option/icmp6__nd__options.py

ver 3.0.8
"""

from typing import Self, override

from net_addr import Buffer, MacAddress
from net_proto.lib.proto_option import ProtoOptions
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option import (
    Icmp6NdOption,
    Icmp6NdOptionType,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__dnssl import (
    Icmp6NdOptionDnssl,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__mtu import (
    Icmp6NdOptionMtu,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__nonce import (
    Icmp6NdOptionNonce,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__pi import (
    Icmp6NdOptionPi,
    NdPrefixInfo,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__ra_flags import (
    Icmp6NdOptionRaFlags,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__rdnss import (
    Icmp6NdOptionRdnss,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__redirected_header import (
    Icmp6NdOptionRedirectedHeader,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__route_info import (
    Icmp6NdOptionRouteInfo,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__slla import (
    Icmp6NdOptionSlla,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__tlla import (
    Icmp6NdOptionTlla,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__unknown import (
    Icmp6NdOptionUnknown,
)


class Icmp6NdOptions(ProtoOptions):
    """
    The ICMPv6 ND message options.
    """

    @property
    def slla(self) -> MacAddress | None:
        """
        Get the ICMPv6 ND 'slla' option value.
        """

        for option in self._options:
            if isinstance(option, Icmp6NdOptionSlla):
                return option.slla

        return None

    @property
    def tlla(self) -> MacAddress | None:
        """
        Get the ICMPv6 ND 'tlla' option value.
        """

        for option in self._options:
            if isinstance(option, Icmp6NdOptionTlla):
                return option.tlla

        return None

    @property
    def nonce(self) -> bytes | None:
        """
        Get the ICMPv6 ND 'nonce' option value (RFC 3971 §5.3.2 / RFC 7527 §4.1).
        """

        for option in self._options:
            if isinstance(option, Icmp6NdOptionNonce):
                return option.nonce

        return None

    @property
    def pi(self) -> list[NdPrefixInfo]:
        """
        Get the ICMPv6 ND 'pi' option value (concatenated across all
        Prefix Info options present; empty list if none are present).
        """

        prefix_info_list: list[NdPrefixInfo] = []

        for option in self._options:
            if isinstance(option, Icmp6NdOptionPi):
                prefix_info_list.append(
                    NdPrefixInfo(
                        flag_l=option.flag_l,
                        flag_a=option.flag_a,
                        flag_r=option.flag_r,
                        valid_lifetime=option.valid_lifetime,
                        preferred_lifetime=option.preferred_lifetime,
                        prefix=option.prefix,
                    )
                )

        return prefix_info_list

    @staticmethod
    def validate_integrity(
        *,
        frame: Buffer,
        offset: int,
    ) -> None:
        """
        Run the ICMPv6 ND options integrity checks before parsing options.
        """

        plen = len(frame)

        while offset < plen:
            if (value := frame[offset + 1] << 3) < 8:
                raise Icmp6IntegrityError(
                    f"The ICMPv6 ND option length must be greater than or equal to 8. Got: {value!r}.",
                )

            offset += frame[offset + 1] << 3
            if offset > plen:
                raise Icmp6IntegrityError(
                    f"The ICMPv6 ND option length must not extend past the header length. Got: {offset=}, {plen=}",
                )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Read the ICMPv6 ND options from buffer.
        """

        offset = 0
        options: list[Icmp6NdOption] = []

        while offset < len(buffer):
            match Icmp6NdOptionType.from_bytes(buffer[offset : offset + 1]):
                case Icmp6NdOptionType.SLLA:
                    options.append(Icmp6NdOptionSlla.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.TLLA:
                    options.append(Icmp6NdOptionTlla.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.PI:
                    options.append(Icmp6NdOptionPi.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.REDIRECTED_HEADER:
                    options.append(Icmp6NdOptionRedirectedHeader.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.MTU:
                    options.append(Icmp6NdOptionMtu.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.NONCE:
                    options.append(Icmp6NdOptionNonce.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.ROUTE_INFO:
                    options.append(Icmp6NdOptionRouteInfo.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.RDNSS:
                    options.append(Icmp6NdOptionRdnss.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.RA_FLAGS_EXTENSION:
                    options.append(Icmp6NdOptionRaFlags.from_buffer(buffer[offset:]))
                case Icmp6NdOptionType.DNSSL:
                    options.append(Icmp6NdOptionDnssl.from_buffer(buffer[offset:]))
                case _:
                    options.append(Icmp6NdOptionUnknown.from_buffer(buffer[offset:]))

            offset += options[-1].len

        return cls(*options)
