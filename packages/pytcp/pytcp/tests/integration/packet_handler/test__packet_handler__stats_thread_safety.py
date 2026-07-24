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
This module contains the packet-statistics thread-safety tests —
pinning that the per-interface 'PacketStatsRx' / 'PacketStatsTx'
counters are sharded per writing thread and summed only on read,
so the per-packet increment path never contends or loses an
update across the RX / TX / Timer threads on a free-threaded
build, while introspection still reports exact totals.

packages/pytcp/pytcp/tests/integration/packet_handler/test__packet_handler__stats_thread_safety.py

ver 3.0.9
"""

import threading

from pytcp.tests.lib.network_testcase import NetworkTestCase


class TestPacketStatsSharding(NetworkTestCase):
    """
    The per-thread sharded packet-statistics counter tests.
    """

    def test__packet_stats__rx_sharded_per_thread_and_summed_on_read(self) -> None:
        """
        Ensure the RX statistics increment target is a distinct
        per-thread shard and that the public snapshot sums the
        shards, so concurrent RX / Timer-thread increments neither
        contend on a shared object nor lose updates on a
        free-threaded build.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        main_shard = handler._packet_stats_rx
        worker_shard_box: list[object] = []

        def worker() -> None:
            worker_shard = handler._packet_stats_rx
            worker_shard_box.append(worker_shard)
            worker_shard.rx_ring__queue_full__drop += 5

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        main_shard.rx_ring__queue_full__drop += 3

        self.assertIsNot(
            worker_shard_box[0],
            main_shard,
            msg="Each writing thread must increment its own RX statistics shard.",
        )
        self.assertEqual(
            handler.packet_stats_rx.rx_ring__queue_full__drop,
            8,
            msg="The public RX snapshot must sum every thread's shard (5 + 3).",
        )

    def test__packet_stats__tx_sharded_per_thread_and_summed_on_read(self) -> None:
        """
        Ensure the TX statistics increment target is a distinct
        per-thread shard and that the public snapshot sums the
        shards, mirroring the RX guarantee for the TX / Timer
        emit paths on a free-threaded build.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler
        main_shard = handler._packet_stats_tx
        worker_shard_box: list[object] = []

        def worker() -> None:
            worker_shard = handler._packet_stats_tx
            worker_shard_box.append(worker_shard)
            worker_shard.tx_ring__queue_full__drop += 7

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        main_shard.tx_ring__queue_full__drop += 2

        self.assertIsNot(
            worker_shard_box[0],
            main_shard,
            msg="Each writing thread must increment its own TX statistics shard.",
        )
        self.assertEqual(
            handler.packet_stats_tx.tx_ring__queue_full__drop,
            9,
            msg="The public TX snapshot must sum every thread's shard (7 + 2).",
        )

    def test__packet_stats__rx_snapshot_is_copy_by_value(self) -> None:
        """
        Ensure the public RX snapshot is a fresh copy-by-value
        object on each read, never a live reference a consumer
        could mutate into stack state (the Phase-3 read-only
        introspection contract).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = self._packet_handler

        self.assertIsNot(
            handler.packet_stats_rx,
            handler.packet_stats_rx,
            msg="Each packet_stats_rx read must return a fresh snapshot, not a live reference.",
        )
