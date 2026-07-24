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
This module contains the DNS protocol enum classes.

net_proto/protocols/dns/dns__enums.py

ver 3.0.8
"""

from typing import override

from net_proto.lib.proto_enum import ProtoEnumByte, ProtoEnumWord


class DnsOpcode(ProtoEnumByte):
    """
    The DNS header 'opcode' field values (RFC 1035 §4.1.1).
    """

    QUERY = 0  # RFC 1035 §4.1.1: Standard query.
    IQUERY = 1  # RFC 1035 §4.1.1: Inverse query (obsoleted by RFC 3425).
    STATUS = 2  # RFC 1035 §4.1.1: Server status request.
    NOTIFY = 4  # RFC 1996: Zone change notification.
    UPDATE = 5  # RFC 2136: Dynamic update.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case DnsOpcode.QUERY:
                name = "Query"
            case DnsOpcode.IQUERY:
                name = "IQuery"
            case DnsOpcode.STATUS:
                name = "Status"
            case DnsOpcode.NOTIFY:
                name = "Notify"
            case DnsOpcode.UPDATE:
                name = "Update"
            case _:
                name = f"{self.value}"

        return name


class DnsResponseCode(ProtoEnumByte):
    """
    The DNS header 'rcode' field values (RFC 1035 §4.1.1).
    """

    NOERROR = 0  # RFC 1035 §4.1.1: No error.
    FORMERR = 1  # RFC 1035 §4.1.1: Format error.
    SERVFAIL = 2  # RFC 1035 §4.1.1: Server failure.
    NXDOMAIN = 3  # RFC 1035 §4.1.1: Non-existent domain.
    NOTIMP = 4  # RFC 1035 §4.1.1: Not implemented.
    REFUSED = 5  # RFC 1035 §4.1.1: Query refused.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case DnsResponseCode.NOERROR:
                name = "NoError"
            case DnsResponseCode.FORMERR:
                name = "FormErr"
            case DnsResponseCode.SERVFAIL:
                name = "ServFail"
            case DnsResponseCode.NXDOMAIN:
                name = "NXDomain"
            case DnsResponseCode.NOTIMP:
                name = "NotImp"
            case DnsResponseCode.REFUSED:
                name = "Refused"
            case _:
                name = f"{self.value}"

        return name


class DnsRecordType(ProtoEnumWord):
    """
    The DNS question / resource-record 'type' field values (RFC 1035 §3.2.2).
    """

    A = 1  # RFC 1035 §3.4.1: A host address (IPv4).
    NS = 2  # RFC 1035 §3.3.11: An authoritative name server.
    CNAME = 5  # RFC 1035 §3.3.1: The canonical name for an alias.
    SOA = 6  # RFC 1035 §3.3.13: Start of a zone of authority.
    PTR = 12  # RFC 1035 §3.3.12: A domain name pointer.
    MX = 15  # RFC 1035 §3.3.9: Mail exchange.
    TXT = 16  # RFC 1035 §3.3.14: Text strings.
    AAAA = 28  # RFC 3596 §2.1: A host address (IPv6).

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case DnsRecordType.A:
                name = "A"
            case DnsRecordType.NS:
                name = "NS"
            case DnsRecordType.CNAME:
                name = "CNAME"
            case DnsRecordType.SOA:
                name = "SOA"
            case DnsRecordType.PTR:
                name = "PTR"
            case DnsRecordType.MX:
                name = "MX"
            case DnsRecordType.TXT:
                name = "TXT"
            case DnsRecordType.AAAA:
                name = "AAAA"
            case _:
                name = f"{self.value}"

        return name


class DnsRecordClass(ProtoEnumWord):
    """
    The DNS question / resource-record 'class' field values (RFC 1035 §3.2.4).
    """

    IN = 1  # RFC 1035 §3.2.4: The Internet.
    CH = 3  # RFC 1035 §3.2.4: The CHAOS class.
    HS = 4  # RFC 1035 §3.2.4: Hesiod.

    @override
    def __str__(self) -> str:
        """
        Get the value as a string.
        """

        match self:
            case DnsRecordClass.IN:
                name = "IN"
            case DnsRecordClass.CH:
                name = "CH"
            case DnsRecordClass.HS:
                name = "HS"
            case _:
                name = f"{self.value}"

        return name
