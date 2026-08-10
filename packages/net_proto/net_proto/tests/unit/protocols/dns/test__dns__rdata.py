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
This module contains unit tests for the DNS typed-RDATA decoders.

net_proto/tests/unit/protocols/dns/test__dns__rdata.py

ver 3.0.10
"""

from unittest import TestCase

from net_proto.protocols.dns.dns__enums import DnsRecordType
from net_proto.protocols.dns.dns__errors import DnsIntegrityError
from net_proto.protocols.dns.dns__rdata import (
    DnsRdataMx,
    DnsRdataName,
    DnsRdataSoa,
    DnsRdataTxt,
    decode_rdata,
)

# A 13-octet "example.com" name anchored at offset 0, used as the
# compression target for every name-bearing RDATA fixture below:
#   Bytes 0-12 : 0x07 'example' 0x03 'com' 0x00 -> example.com
_ANCHOR = b"\x07example\x03com\x00"


class TestDnsDecodeRdataName(TestCase):
    """
    The single-name (PTR / CNAME / NS) RDATA decoder tests.
    """

    def test__dns__rdata__ptr_decodes_uncompressed_name(self) -> None:
        """
        Ensure a PTR RDATA carrying a self-contained domain name decodes
        to the dotted name.

        Reference: RFC 1035 §3.3.12 (PTR RDATA format).
        """

        # PTR RDATA, name fully inside the RDATA (no compression):
        #   0x04 'host' 0x07 'example' 0x03 'com' 0x00 -> host.example.com
        frame = b"\x04host\x07example\x03com\x00"

        self.assertEqual(
            decode_rdata(rtype=DnsRecordType.PTR, frame=frame, rdata_offset=0, rdlength=len(frame)),
            DnsRdataName(name="host.example.com"),
            msg="A PTR RDATA must decode to its uncompressed domain name.",
        )

    def test__dns__rdata__cname_follows_compression_pointer(self) -> None:
        """
        Ensure a CNAME RDATA whose tail is a compression pointer into the
        wider message resolves against the full frame.

        Reference: RFC 1035 §4.1.4 (Message compression).
        """

        # CNAME RDATA at offset 13: 0x03 'www' 0xC0 0x00 -> www + ptr->0:
        #   Bytes 13-18 : 0x03 'www' 0xc0 0x00 -> www.example.com
        frame = _ANCHOR + b"\x03www\xc0\x00"

        self.assertEqual(
            decode_rdata(rtype=DnsRecordType.CNAME, frame=frame, rdata_offset=13, rdlength=6),
            DnsRdataName(name="www.example.com"),
            msg="A CNAME RDATA must follow a compression pointer into the message.",
        )

    def test__dns__rdata__ns_decodes_name(self) -> None:
        """
        Ensure an NS RDATA decodes to the authoritative server name.

        Reference: RFC 1035 §3.3.11 (NS RDATA format).
        """

        # NS RDATA at offset 13: 0x02 'ns' 0xC0 0x00 -> ns + ptr->0:
        #   Bytes 13-17 : 0x02 'ns' 0xc0 0x00 -> ns.example.com
        frame = _ANCHOR + b"\x02ns\xc0\x00"

        self.assertEqual(
            decode_rdata(rtype=DnsRecordType.NS, frame=frame, rdata_offset=13, rdlength=5),
            DnsRdataName(name="ns.example.com"),
            msg="An NS RDATA must decode to its server name.",
        )


class TestDnsDecodeRdataMx(TestCase):
    """
    The mail-exchange (MX) RDATA decoder tests.
    """

    def test__dns__rdata__mx_decodes_preference_and_exchange(self) -> None:
        """
        Ensure an MX RDATA decodes the 2-octet preference and the
        exchange domain name (compressed against the message).

        Reference: RFC 1035 §3.3.9 (MX RDATA format).
        """

        # MX RDATA at offset 13: 0x000a preference, then 0x04 'mail' 0xC0 0x00:
        #   Bytes 13-14 : 0x000a -> preference=10
        #   Bytes 15-20 : 0x04 'mail' 0xc0 0x00 -> mail.example.com
        frame = _ANCHOR + b"\x00\x0a\x04mail\xc0\x00"

        self.assertEqual(
            decode_rdata(rtype=DnsRecordType.MX, frame=frame, rdata_offset=13, rdlength=8),
            DnsRdataMx(preference=10, exchange="mail.example.com"),
            msg="An MX RDATA must decode its preference and exchange name.",
        )

    def test__dns__rdata__mx_too_short_raises(self) -> None:
        """
        Ensure an MX RDATA shorter than a preference plus a one-octet
        name is rejected as an integrity error.

        Reference: RFC 1035 §3.3.9 (MX RDATA format).
        """

        # MX RDATA carrying only the 2-octet preference, no exchange:
        #   Bytes 0-1 : 0x000a -> preference=10 (integrity violation: no name)
        frame = b"\x00\x0a"

        with self.assertRaises(DnsIntegrityError):
            decode_rdata(rtype=DnsRecordType.MX, frame=frame, rdata_offset=0, rdlength=2)


class TestDnsDecodeRdataSoa(TestCase):
    """
    The start-of-authority (SOA) RDATA decoder tests.
    """

    def test__dns__rdata__soa_decodes_names_and_timers(self) -> None:
        """
        Ensure an SOA RDATA decodes the MNAME / RNAME domain names and
        the five 32-bit timer fields.

        Reference: RFC 1035 §3.3.13 (SOA RDATA format).
        """

        # SOA RDATA at offset 13:
        #   Bytes 13-17 : 0x02 'ns' 0xc0 0x00 -> mname ns.example.com
        #   Bytes 18-30 : 0x0a 'hostmaster' 0xc0 0x00 -> rname hostmaster.example.com
        #   Bytes 31-50 : serial=1, refresh=2, retry=3, expire=4, minimum=5
        rdata = (
            b"\x02ns\xc0\x00"
            b"\x0ahostmaster\xc0\x00"
            b"\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x05"
        )
        frame = _ANCHOR + rdata

        self.assertEqual(
            decode_rdata(rtype=DnsRecordType.SOA, frame=frame, rdata_offset=13, rdlength=len(rdata)),
            DnsRdataSoa(
                mname="ns.example.com",
                rname="hostmaster.example.com",
                serial=1,
                refresh=2,
                retry=3,
                expire=4,
                minimum=5,
            ),
            msg="An SOA RDATA must decode its names and five timer fields.",
        )

    def test__dns__rdata__soa_truncated_tail_raises(self) -> None:
        """
        Ensure an SOA RDATA whose 20-octet timer tail is truncated is
        rejected as an integrity error.

        Reference: RFC 1035 §3.3.13 (SOA RDATA format).
        """

        # SOA RDATA with both names but only 4 of the 20 timer octets:
        #   Bytes 13-17 : 0x02 'ns' 0xc0 0x00 -> mname
        #   Bytes 18-30 : 0x0a 'hostmaster' 0xc0 0x00 -> rname
        #   Bytes 31-34 : 0x00000001 (integrity violation: 16 octets short)
        rdata = b"\x02ns\xc0\x00" b"\x0ahostmaster\xc0\x00" b"\x00\x00\x00\x01"
        frame = _ANCHOR + rdata

        with self.assertRaises(DnsIntegrityError):
            decode_rdata(rtype=DnsRecordType.SOA, frame=frame, rdata_offset=13, rdlength=len(rdata))


class TestDnsDecodeRdataTxt(TestCase):
    """
    The text (TXT) RDATA decoder tests.
    """

    def test__dns__rdata__txt_decodes_character_strings(self) -> None:
        """
        Ensure a TXT RDATA decodes its sequence of length-prefixed
        character-strings.

        Reference: RFC 1035 §3.3.14 (TXT RDATA format).
        """

        # TXT RDATA, two character-strings:
        #   Bytes 0-6  : 0x06 'v=spf1' -> "v=spf1"
        #   Bytes 7-12 : 0x05 'hello' -> "hello"
        frame = b"\x06v=spf1\x05hello"

        self.assertEqual(
            decode_rdata(rtype=DnsRecordType.TXT, frame=frame, rdata_offset=0, rdlength=len(frame)),
            DnsRdataTxt(strings=(b"v=spf1", b"hello")),
            msg="A TXT RDATA must decode each length-prefixed character-string.",
        )

    def test__dns__rdata__txt_string_past_boundary_raises(self) -> None:
        """
        Ensure a TXT character-string whose length runs past the RDATA
        boundary is rejected as an integrity error.

        Reference: RFC 1035 §3.3.14 (TXT RDATA format).
        """

        # TXT RDATA whose declared length exceeds the available octets:
        #   Bytes 0-2 : 0x05 'ab' (integrity violation: claims 5, has 2)
        frame = b"\x05ab"

        with self.assertRaises(DnsIntegrityError):
            decode_rdata(rtype=DnsRecordType.TXT, frame=frame, rdata_offset=0, rdlength=len(frame))


class TestDnsDecodeRdataUndecoded(TestCase):
    """
    The decode-to-None (address and unknown) RDATA decoder tests.
    """

    def test__dns__rdata__a_record_decodes_to_none(self) -> None:
        """
        Ensure an A record returns None so callers fall back to the
        dedicated address accessor.

        Reference: RFC 1035 §3.4.1 (A RDATA format).
        """

        # A RDATA, raw IPv4 address 93.184.216.34:
        #   Bytes 0-3 : 0x5db8d822 -> 93.184.216.34
        frame = b"\x5d\xb8\xd8\x22"

        self.assertIsNone(
            decode_rdata(rtype=DnsRecordType.A, frame=frame, rdata_offset=0, rdlength=len(frame)),
            msg="An A record must decode to None (address comes from the address accessor).",
        )

    def test__dns__rdata__unknown_type_decodes_to_none(self) -> None:
        """
        Ensure an unsupported record type returns None, leaving the raw
        RDATA bytes as the only representation.

        Reference: RFC 1035 §3.2.2 (TYPE values).
        """

        # An arbitrary unsupported TYPE (HINFO = 13) with two octets of RDATA:
        #   Bytes 0-1 : 0x0001 -> opaque RDATA
        frame = b"\x00\x01"

        self.assertIsNone(
            decode_rdata(rtype=DnsRecordType.from_int(13), frame=frame, rdata_offset=0, rdlength=len(frame)),
            msg="An unsupported record type must decode to None.",
        )
