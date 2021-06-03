#!/usr/bin/env python3

from dataclasses import dataclass

from testslide import TestCase

from misc.ip_helper import inet_cksum, ip_pick_version


class TestMiscIpHelper(TestCase):
    def test_inet_cksum(self):
        @dataclass
        class Sample:
            data: bytes
            init: int
            result: int

        samples = [
            Sample(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" * 80, 0, 0x2D2D),
            Sample(b"\xFF" * 1500, 0, 0x0000),
            Sample(b"\x00" * 1500, 0, 0xFFFF),
            Sample(b"\xF7\x24\x09" * 100 + b"\x35\x67\x0F\x00" * 250, 0, 0xF1E5),
            Sample(b"\x07" * 9999, 0, 0xBEC5),
            Sample(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" * 80, 0x03DF, 0x294E),
            Sample(b"\xFF" * 1500, 0x0015, 0xFFEA),
            Sample(b"\x00" * 1500, 0xF3FF, 0x0C00),
            Sample(b"\xF7\x24\x09" * 100 + b"\x35\x67\x0F\x00" * 250, 0x7314, 0x7ED1),
            Sample(b"\x07" * 9999, 0xA3DC, 0x1AE9),
        ]

        for sample in samples:
            result = inet_cksum(data=sample.data, dptr=0, dlen=len(sample.data), init=sample.init)
            self.assertEqual(result, sample.result)

    def test_ip_pick_version(self):
        from lib.ip6_address import Ip6Address

        self.assertEqual(ip_pick_version("1:2:3:4:5:6:7:8"), Ip6Address("1:2:3:4:5:6:7:8"))
        from lib.ip4_address import Ip4Address

        self.assertEqual(ip_pick_version("1.2.3.4"), Ip4Address("1.2.3.4"))
