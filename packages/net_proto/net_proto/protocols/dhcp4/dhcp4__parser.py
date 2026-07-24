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
This module contains the DHCPv4 packet parser class.

net_proto/protocols/dhcp4/dhcp4__parser.py

ver 3.0.9
"""

from typing import override

from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.dhcp4.dhcp4__base import Dhcp4
from net_proto.protocols.dhcp4.dhcp4__enums import (
    Dhcp4MessageType,
    Dhcp4Operation,
)
from net_proto.protocols.dhcp4.dhcp4__errors import (
    Dhcp4IntegrityError,
    Dhcp4SanityError,
)
from net_proto.protocols.dhcp4.dhcp4__header import (
    DHCP4__HEADER__FILE__MAX_LEN,
    DHCP4__HEADER__LEN,
    DHCP4__HEADER__SNAME__MAX_LEN,
    Dhcp4Header,
)
from net_proto.protocols.dhcp4.options.dhcp4__options import Dhcp4Options

# Offsets of the BOOTP 'sname' and 'file' fields inside the
# fixed 240-byte DHCPv4 header, computed against the layout
# string '! BBBB L HH L L L L 16s 64s 128s 4s'. Used by the
# RFC 2132 §9.3 Option Overload re-extraction below.
_DHCP4__HEADER__SNAME__OFFSET: int = 44
_DHCP4__HEADER__FILE__OFFSET: int = _DHCP4__HEADER__SNAME__OFFSET + DHCP4__HEADER__SNAME__MAX_LEN


class Dhcp4Parser(Dhcp4, ProtoParser):
    """
    The DHCPv4 packet parser.
    """

    def __init__(self, data_rx: memoryview) -> None:
        """
        Initialize the DHCPv4 packet parser.
        """

        self._frame = data_rx

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the DHCPv4 packet before parsing it.
        """

        # RFC 2131 §2 — fixed BOOTP header (236 B) + 4-byte magic cookie = 240 B floor.
        if len(self._frame) < DHCP4__HEADER__LEN:
            raise Dhcp4IntegrityError(
                f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes. Got: {len(self._frame)} bytes."
            )

        # RFC 2131 §4.1 / RFC 2132 §2 — variable-length options must self-bound (TLV).
        # The header-level integrity invariants (`hrtype == ETHERNET`,
        # `hrlen == 6`, `magic_cookie == 0x63825363`) are raised as
        # typed `Dhcp4IntegrityError` directly from
        # `Dhcp4Header.from_buffer`; per-option wire-shape invariants
        # are enforced by each option's static `_validate_integrity`
        # called from its `from_buffer`.
        Dhcp4Options.validate_integrity(frame=self._frame, hlen=len(self._frame))

    @override
    def _parse(self) -> None:
        """
        Parse the DHCPv4 packet.
        """

        self._header = Dhcp4Header.from_buffer(self._frame)
        self._options = Dhcp4Options.from_buffer(self._frame[len(self._header) :])

        # RFC 2132 §9.3 Option Overload — when option 52 is present
        # the BOOTP 'file' and/or 'sname' fields carry additional
        # DHCP options. Re-extract those raw bytes from the frame
        # (the header's ASCII-decoded view is unusable for non-ASCII
        # option payloads) and merge the parsed options into the main
        # set so 'self._options' presents a unified view to callers.
        self._apply_option_overload()

    def _apply_option_overload(self) -> None:
        """
        Overlay the RFC 2132 §9.3 Option Overload extras onto
        'self._options'. No-op when option 52 is absent. The
        overload values are:

          1 — 'file' field carries additional options.
          2 — 'sname' field carries additional options.
          3 — both fields carry additional options.

        Per the RFC the 'file' field (when overloaded) is parsed
        first, followed by 'sname', so a server can chain the two
        for an option set spanning ~190 bytes of overflow on top of
        the main option block.
        """

        overload = self._options.option_overload
        if overload is None:
            return

        # Parse each overloaded field independently. The RFC 2132
        # §9.3 spec lets each field carry its own END marker, so
        # concatenating the buffers and parsing once would stop at
        # the first END and miss the second field. The slice bounds
        # are constants from the fixed header layout; the
        # 'errors="replace"' decode on the header preserved the raw
        # frame bytes intact for our re-extraction here.
        merged = list(self._options._options)  # pylint: disable=protected-access
        if overload.includes_file:
            file_blob = memoryview(
                bytes(
                    self._frame[
                        _DHCP4__HEADER__FILE__OFFSET : _DHCP4__HEADER__FILE__OFFSET + DHCP4__HEADER__FILE__MAX_LEN
                    ]
                )
            )
            # RFC 2132 §9.3 — the overloaded BOOTP fields carry a
            # full DHCP options sub-block, not bare option bytes.
            # Run the same integrity walker that protects the main
            # options block so a hostile overloaded option (length
            # byte extending past the 128-byte 'file' slice end,
            # missing length byte, etc.) raises a typed
            # Dhcp4IntegrityError before 'from_buffer' dispatches.
            Dhcp4Options.validate_integrity(frame=file_blob, hlen=len(file_blob), offset=0)
            file_options = Dhcp4Options.from_buffer(file_blob)
            merged.extend(file_options._options)  # pylint: disable=protected-access
        if overload.includes_sname:
            sname_blob = memoryview(
                bytes(
                    self._frame[
                        _DHCP4__HEADER__SNAME__OFFSET : _DHCP4__HEADER__SNAME__OFFSET + DHCP4__HEADER__SNAME__MAX_LEN
                    ]
                )
            )
            Dhcp4Options.validate_integrity(frame=sname_blob, hlen=len(sname_blob), offset=0)
            sname_options = Dhcp4Options.from_buffer(sname_blob)
            merged.extend(sname_options._options)  # pylint: disable=protected-access

        if len(merged) == len(self._options._options):  # pylint: disable=protected-access
            return

        self._options = Dhcp4Options(*merged)

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the DHCPv4 packet after parsing it.
        """

        # --- operation (BOOTREQUEST / BOOTREPLY) ---
        # RFC 951 §8 / RFC 2131 §2 define only operation=1 (BOOTREQUEST) and
        # operation=2 (BOOTREPLY); ProtoEnum '_missing_' materialises any other
        # wire value as UNKNOWN_n.
        if self._header.operation.is_unknown:
            raise Dhcp4SanityError(
                f"The 'operation' field value must be one of {Dhcp4Operation.get_known_values()}. "
                f"Got: {int(self._header.operation)}."
            )

        # --- ciaddr / yiaddr / siaddr / giaddr (all host endpoints) ---
        # RFC 1122 §3.2.1.3 — an IPv4 source/destination address that names a
        # host endpoint MUST NOT be loopback (127/8), multicast (224/4), or the
        # limited broadcast (255.255.255.255). All four DHCPv4 header address
        # fields name host endpoints (client current / assigned / next-server /
        # relay-agent).
        for field_name in ("ciaddr", "yiaddr", "siaddr", "giaddr"):
            address = getattr(self._header, field_name)
            if address.is_loopback:
                raise Dhcp4SanityError(f"The '{field_name}' field value {address} must not be a loopback IPv4 address.")
            if address.is_multicast:
                raise Dhcp4SanityError(
                    f"The '{field_name}' field value {address} must not be a multicast IPv4 address."
                )
            if address.is_limited_broadcast:
                raise Dhcp4SanityError(
                    f"The '{field_name}' field value {address} must not be a limited broadcast IPv4 address."
                )

        # --- chaddr (client hardware address) ---
        # RFC 2131 §2 — 'chaddr' is the client's hardware address; for Ethernet
        # (htype=1, hlen=6) IEEE 802.3 forbids the group-bit-set or all-ones MAC
        # as a unicast endpoint identifier. ('chaddr' = all-zeros is tolerated
        # because RFC 4361 deployments may zero it when option 61 carries the
        # client ID instead.)
        if self._header.chaddr.is_multicast:
            raise Dhcp4SanityError(
                f"The 'chaddr' field value {self._header.chaddr} must not be a multicast MAC address."
            )
        if self._header.chaddr.is_broadcast:
            raise Dhcp4SanityError(
                f"The 'chaddr' field value {self._header.chaddr} must not be a broadcast MAC address."
            )

        # --- DHCP Message Type option presence ---
        # RFC 2131 §3 — "DHCP messages MUST contain a 'DHCP message type'
        # option that specifies the type of message". A magic-cookie-bearing
        # BOOTP frame without option 53 is structurally well-formed but
        # cannot be classified as a DHCP message; reject it explicitly here
        # so a caller's typed `except Dhcp4SanityError` does the dropping
        # instead of relying on a downstream `message_type != expected_type`
        # comparison against `None`.
        if (message_type := self._options.message_type) is None:
            raise Dhcp4SanityError(
                "DHCP messages MUST contain a Message Type option (RFC 2131 §3 / RFC 2132 §9.6). "
                "Got: magic-cookie-bearing frame without option 53."
            )

        # --- Required server-response options ---
        # RFC 2131 §3 Table 3 / §4.3.6 — server-emitted DHCPOFFER,
        # DHCPACK, and DHCPNAK MUST carry the Server Identifier
        # option (54); reject responses missing it as malformed so
        # the client's wait loop drops them uniformly via
        # `except Dhcp4SanityError`.
        # 'lease_time' (51) is also MUST on DHCPOFFER and on DHCPACK
        # responses to DHCPREQUEST, but MUST NOT appear on DHCPACK
        # responding to a DHCPINFORM. PyTCP does not emit INFORM so
        # both ACK-paths are equivalent here, and the lease_time MUST
        # is enforced on DHCPOFFER only — keeping the parser usable
        # in hypothetical INFORM-ACK contexts without a stateful
        # request/reply correlation.
        if message_type in (
            Dhcp4MessageType.OFFER,
            Dhcp4MessageType.ACK,
            Dhcp4MessageType.NAK,
        ):
            if self._options.server_id is None:
                raise Dhcp4SanityError(
                    f"DHCPv4 {message_type.name} message MUST carry a Server Identifier option "
                    "(RFC 2131 §3 Table 3 / §4.3.6). Got: option 54 absent."
                )
        if message_type is Dhcp4MessageType.OFFER:
            if self._options.lease_time is None:
                raise Dhcp4SanityError(
                    "DHCPv4 OFFER message MUST carry an IP Address Lease Time option "
                    "(RFC 2131 §3 Table 3 / §4.3.1). Got: option 51 absent."
                )
