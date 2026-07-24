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
This module contains the DHCPv4 packet assembler class.

net_proto/protocols/dhcp4/dhcp4__assembler.py

ver 3.0.9
"""

from typing import override

from net_addr import Buffer, Ip4Address, MacAddress
from net_proto.lib.proto_assembler import ProtoAssembler
from net_proto.protocols.dhcp4.dhcp4__base import Dhcp4
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__header import Dhcp4Header
from net_proto.protocols.dhcp4.options.dhcp4__option__end import Dhcp4OptionEnd
from net_proto.protocols.dhcp4.options.dhcp4__option__message_type import (
    Dhcp4OptionMessageType,
)
from net_proto.protocols.dhcp4.options.dhcp4__option__param_req_list import (
    Dhcp4OptionParamReqList,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options


class Dhcp4Assembler(Dhcp4, ProtoAssembler):
    """
    The DHCPv4 packet assembler.
    """

    def __init__(
        self,
        *,
        dhcp4__operation: Dhcp4Operation,
        dhcp4__hops: int = 0,
        dhcp4__xid: int,
        dhcp4__secs: int = 0,
        dhcp4__flag_b: bool = False,
        dhcp4__ciaddr: Ip4Address = Ip4Address(),
        dhcp4__yiaddr: Ip4Address = Ip4Address(),
        dhcp4__siaddr: Ip4Address = Ip4Address(),
        dhcp4__giaddr: Ip4Address = Ip4Address(),
        dhcp4__chaddr: MacAddress,
        dhcp4__sname: str | None = None,
        dhcp4__file: str | None = None,
        dhcp4__options: Dhcp4Options = Dhcp4Options(),
    ) -> None:
        """
        Initialize the DHCPv4 packet assembler.
        """

        # RFC 2132 §3 — "The last option must always be the 'end'
        # option." Empty options are permitted (the magic cookie
        # alone marks the DHCP options field); a non-empty options
        # block whose last entry is not Dhcp4OptionEnd would emit
        # a wire frame without the terminator, which a strict
        # receiver may interpret as a truncation or simply leave
        # the option list unbounded.
        assert not dhcp4__options or isinstance(dhcp4__options[-1], Dhcp4OptionEnd), (
            "RFC 2132 §3: the last DHCPv4 option must be Dhcp4OptionEnd. " f"Got: {dhcp4__options!r}"
        )

        # RFC 2131 §2 — 'sname' and 'file' are null-terminated ASCII
        # strings. The wire serialization path uses
        # `bytes(value, encoding="ascii")` which raises
        # UnicodeEncodeError on non-ASCII input. Catch it here at
        # the TX boundary so the failure surfaces at construction
        # time rather than deep inside `__buffer__`. The Dhcp4Header
        # dataclass itself tolerates non-ASCII because the parser
        # uses `errors="replace"` to absorb RFC 2132 §9.3 Option
        # Overload binary payloads — that tolerance lives on RX,
        # not TX.
        sname_normalized = dhcp4__sname or ""
        assert sname_normalized.isascii(), f"The 'dhcp4__sname' field must be ASCII. Got: {sname_normalized!r}"

        file_normalized = dhcp4__file or ""
        assert file_normalized.isascii(), f"The 'dhcp4__file' field must be ASCII. Got: {file_normalized!r}"

        # RFC 2131 §2 / RFC 2132 — protocol enums (Dhcp4Operation
        # 'op' field, Dhcp4MessageType in Message Type option,
        # Dhcp4OptionType inside Parameter Request List) are
        # extensible at parse time via ProtoEnum '_missing_' so the
        # RX path can materialise unknown wire codepoints for
        # `_validate_sanity` to reject. The TX path is strict: a
        # programmer who synthesised `Dhcp4Operation.from_int(99)`
        # or `Dhcp4MessageType.from_int(99)` would otherwise emit a
        # frame with an unknown codepoint that strict receivers
        # cannot interpret. Refuse such constructions here.
        assert not dhcp4__operation.is_unknown, (
            "The 'dhcp4__operation' field must be a known Dhcp4Operation "
            f"member (BOOTREQUEST/BOOTREPLY). Got: {dhcp4__operation!r}"
        )

        for option in dhcp4__options:
            if isinstance(option, Dhcp4OptionMessageType):
                assert not option.message_type.is_unknown, (
                    "The DHCPv4 Message Type option carries an unknown "
                    f"Dhcp4MessageType member. Got: {option.message_type!r}"
                )
            if isinstance(option, Dhcp4OptionParamReqList):
                for element in option.param_req_list:
                    assert not element.is_unknown, (
                        "The DHCPv4 Parameter Request List option carries an "
                        f"unknown Dhcp4OptionType member. Got: {element!r}"
                    )

        self._header = Dhcp4Header(
            operation=dhcp4__operation,
            hops=dhcp4__hops,
            xid=dhcp4__xid,
            secs=dhcp4__secs,
            flag_b=dhcp4__flag_b,
            ciaddr=dhcp4__ciaddr,
            yiaddr=dhcp4__yiaddr,
            siaddr=dhcp4__siaddr,
            giaddr=dhcp4__giaddr,
            chaddr=dhcp4__chaddr,
            sname=dhcp4__sname or "",
            file=dhcp4__file or "",
        )

        self._options = dhcp4__options

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the DHCPv4 packet into list of buffers.
        """

        raise NotImplementedError("The 'assemble()' method is not implemented for L7 protocols. Use Sockets instead.")
