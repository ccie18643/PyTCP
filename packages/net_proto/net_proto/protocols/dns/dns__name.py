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
This module contains the DNS domain-name codec (RFC 1035 §4.1.4).

A DNS domain name is a sequence of length-prefixed labels terminated by a
zero-length root label. To save space a name may end in a compression
pointer — a two-octet value whose top two bits are set, carrying a
14-bit offset from the start of the message at which the remainder of the
name is found. 'encode_name' produces the uncompressed wire form (queries
need no compression); 'decode_name' resolves a name at a given offset,
following any pointer chain with a cycle guard, and returns the name plus
the offset of the first octet after the name in the linear stream.

net_proto/protocols/dns/dns__name.py

ver 3.0.10
"""

from net_addr import Buffer
from net_proto.protocols.dns.dns__errors import DnsIntegrityError

# RFC 1035 §2.3.4 — a label is at most 63 octets, a name at most 255.
DNS__LABEL__MAX_LEN = 63
DNS__NAME__MAX_LEN = 255

# RFC 1035 §4.1.4 — a label length octet whose top two bits are set marks
# a compression pointer; the remaining 14 bits give the target offset.
DNS__LABEL__POINTER_MASK = 0xC0
DNS__POINTER__OFFSET_MASK = 0x3FFF


def encode_name(name: str, /) -> bytes:
    """
    Encode a dotted domain name into the uncompressed DNS wire form.
    """

    encoded = bytearray()

    for label in name.rstrip(".").split("."):
        if label == "":
            # An empty label only arises from the root name ("" or ".")
            # or from a malformed name with consecutive dots; the former
            # is legitimate (it produces just the root terminator), the
            # latter is caught by the per-label length assertion below.
            continue
        octets = label.encode("ascii")
        assert (
            1 <= len(octets) <= DNS__LABEL__MAX_LEN
        ), f"A DNS label must be 1..{DNS__LABEL__MAX_LEN} octets. Got: {len(octets)}"
        encoded.append(len(octets))
        encoded += octets

    encoded.append(0)

    assert (
        len(encoded) <= DNS__NAME__MAX_LEN
    ), f"A DNS name must be at most {DNS__NAME__MAX_LEN} octets. Got: {len(encoded)}"

    return bytes(encoded)


def decode_name(frame: Buffer, offset: int, /) -> tuple[str, int]:
    """
    Decode the DNS domain name at 'offset', following any compression
    pointer chain; return the dotted name and the offset of the first
    octet after the name in the linear stream.
    """

    frame = memoryview(frame)
    labels: list[str] = []
    end_offset: int | None = None
    seen: set[int] = set()
    position = offset

    while True:
        if position in seen:
            raise DnsIntegrityError(f"The name compression pointer chain forms a loop at offset {position}.")
        seen.add(position)

        if position >= len(frame):
            raise DnsIntegrityError(f"The name at offset {offset} runs past the end of the message.")

        length = frame[position]

        if length & DNS__LABEL__POINTER_MASK == DNS__LABEL__POINTER_MASK:
            if position + 1 >= len(frame):
                raise DnsIntegrityError(f"The compression pointer at offset {position} is truncated.")
            if end_offset is None:
                end_offset = position + 2
            position = ((length << 8) | frame[position + 1]) & DNS__POINTER__OFFSET_MASK
            continue

        if length & DNS__LABEL__POINTER_MASK != 0:
            raise DnsIntegrityError(
                f"The label length octet {length:#04x} at offset {position} uses reserved top bits."
            )

        if length == 0:
            if end_offset is None:
                end_offset = position + 1
            break

        start = position + 1
        finish = start + length
        if finish > len(frame):
            raise DnsIntegrityError(f"The label at offset {position} runs past the end of the message.")
        labels.append(bytes(frame[start:finish]).decode("ascii", errors="replace"))
        position = finish

    name = ".".join(labels)

    # RFC 1035 §2.3.4 — the on-wire name (labels + length octets + root)
    # must not exceed 255 octets; the dotted form has one separator per
    # label boundary, so 'len(name) + 2' bounds the wire length.
    if len(name) + 2 > DNS__NAME__MAX_LEN:
        raise DnsIntegrityError(f"The decoded name exceeds {DNS__NAME__MAX_LEN} octets. Got: {len(name)} characters.")

    assert end_offset is not None
    return name, end_offset
