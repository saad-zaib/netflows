#!/usr/bin/env python3

"""
This file belongs to https://github.com/bitkeks/python-netflow-v9-softflowd.

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""
import cProfile
import io
import linecache
import pstats
import tracemalloc
import unittest

from tests.lib import send_recv_packets, generate_packets

NUM_PACKETS_PERFORMANCE = 2000


@unittest.skip("Not necessary in functional tests, used as analysis tool")
class TestNetflowIPFIXPerformance(unittest.TestCase):
    def setUp(self) -> None:
        """
        Before each test run, start tracemalloc profiling.
        :return:
        """
        tracemalloc.start()
        print("\n\n")

    def tearDown(self) -> None:
        """
        After each test run, stop tracemalloc.
        :return:
        """
        tracemalloc.stop()

    def _memory_of_version(self, version, store_packets=500) -> tracemalloc.Snapshot:
        """
        Create memory snapshot of collector run with packets of version :version:
        :param version:
        :return:
        """
        if not tracemalloc.is_tracing():
            raise RuntimeError
        pkts, t1, t2 = send_recv_packets(generate_packets(NUM_PACKETS_PERFORMANCE, version),
                                         store_packets=store_packets)
        self.assertEqual(len(pkts), NUM_PACKETS_PERFORMANCE)
        snapshot = tracemalloc.take_snapshot()
        del pkts
        return snapshot

    @staticmethod
    def _print_memory_statistics(snapshot: tracemalloc.Snapshot, key: str, topx: int = 10):
        """
        Print memory statistics from a tracemalloc.Snapshot in certain formats.
        :param snapshot:
        :param key:
        :param topx:
        :return:
        """
        if key not in ["filename", "lineno", "traceback"]:
            raise KeyError

        stats = snapshot.statistics(key)
        if key == "lineno":
            for idx, stat in enumerate(stats[:topx]):
                frame = stat.traceback[0]
                print("\n{idx:02d}: {filename}:{lineno} {size:.1f} KiB, count {count}".format(
                    idx=idx + 1, filename=frame.filename, lineno=frame.lineno, size=stat.size / 1024, count=stat.count
                ))

                lines = []
                lines_whitespaces = []
                for lineshift in range(-3, 2):
                    stat = linecache.getline(frame.filename, frame.lineno + lineshift)
                    lines_whitespaces.append(len(stat) - len(stat.lstrip(" ")))  # count
                    lines.append(stat.strip())
                lines_whitespaces = [x - min([y for y in lines_whitespaces if y > 0]) for x in lines_whitespaces]
                for lidx, stat in enumerate(lines):
                    print("   {}{}".format("> " if lidx == 3 else "| ", " " * lines_whitespaces.pop(0) + stat))
        elif key == "filename":
            for idx, stat in enumerate(stats[:topx]):
                frame = stat.traceback[0]
                print("{idx:02d}: {filename:80s} {size:6.1f} KiB, count {count:5<d}".format(
                    idx=idx + 1, filename=frame.filename, size=stat.size / 1024, count=stat.count
                ))

    def test_compare_memory(self):
        """
        Test memory usage of two collector runs with IPFIX and NetFlow v9 packets respectively.
        Then compare the two memory snapshots to make sure the libraries do not cross each other.
        TODO: more features could be tested, e.g. too big of a difference if one version is optimized better
        :return:
        """
        pkts, t1, t2 = send_recv_packets(generate_packets(NUM_PACKETS_PERFORMANCE, 10))
        self.assertEqual(len(pkts), NUM_PACKETS_PERFORMANCE)
        snapshot_ipfix = tracemalloc.take_snapshot()
        del pkts
        tracemalloc.clear_traces()

        pkts, t1, t2 = send_recv_packets(generate_packets(NUM_PACKETS_PERFORMANCE, 9))
        self.assertEqual(len(pkts), NUM_PACKETS_PERFORMANCE)
        snapshot_v9 = tracemalloc.take_snapshot()
        del pkts

        stats = snapshot_v9.compare_to(snapshot_ipfix, "lineno")
        for stat in stats:
            if stat.traceback[0].filename.endswith("netflow/ipfix.py"):
                self.assertEqual(stat.count, 0)
                self.assertEqual(stat.size, 0)

        stats = snapshot_ipfix.compare_to(snapshot_v9, "lineno")
        for stat in stats:
            if stat.traceback[0].filename.endswith("netflow/v9.py"):
                self.assertEqual(stat.count, 0)
                self.assertEqual(stat.size, 0)

    def test_memory_ipfix(self):
        """
        Test memory usage of the collector with IPFIX packets.
        Three iterations are done with different amounts of packets to be stored.
        With this approach, increased usage of memory can be captured when the ExportPacket objects are not deleted.
        :return:
        """
        for store_pkts in [0, 500, -1]:  # -1 is compatibility value for "store all"
            snapshot_ipfix = self._memory_of_version(10, store_packets=store_pkts)

            # TODO: this seems misleading, maybe reads the memory of the whole testing process?
            # system_memory = pathlib.Path("/proc/self/statm").read_text()
            # pagesize = resource.getpagesize()
            # print("Total RSS memory used: {:.1f} KiB".format(int(system_memory.split()[1]) * pagesize // 1024.))

            print("\nIPFIX memory usage with {} packets being stored".format(store_pkts))
            self._print_memory_statistics(snapshot_ipfix, "filename")
            if store_pkts == -1:
                # very verbose and most interesting in iteration with all ExportPackets being stored in memory
                print("\nTraceback for run with all packets being stored in memory")
                self._print_memory_statistics(snapshot_ipfix, "lineno")

    def test_memory_v1(self):
        """
        Test memory with NetFlow v1
        :return:
        """
        snapshot_v1 = self._memory_of_version(1)
        print("\nNetFlow v1 memory usage by file")
        self._print_memory_statistics(snapshot_v1, "filename")

    def test_memory_v5(self):
        """
        Test memory with NetFlow v5
        :return:
        """
        snapshot_v5 = self._memory_of_version(5)
        print("\nNetFlow v5 memory usage by file")
        self._print_memory_statistics(snapshot_v5, "filename")

    def test_memory_v9(self):
        """
        Test memory usage of the collector with NetFlow v9 packets.
        :return:
        """
        snapshot_v9 = self._memory_of_version(9)
        print("\nNetFlow v9 memory usage by file")
        self._print_memory_statistics(snapshot_v9, "filename")
        print("\nNetFlow v9 memory usage by line")
        self._print_memory_statistics(snapshot_v9, "lineno")

    @unittest.skip("Does not work as expected due to threading")
    def test_time_ipfix(self):
        """
        Profile function calls and CPU time.
        TODO: this does not work with threading in the collector, yet
        :return:
        """
        profile = cProfile.Profile()
        profile.enable(subcalls=True, builtins=True)
        pkts, t1, t2 = send_recv_packets(generate_packets(NUM_PACKETS_PERFORMANCE, 10), delay=0, store_packets=500)
        self.assertEqual(len(pkts), NUM_PACKETS_PERFORMANCE)
        profile.disable()

        for sort_by in ['cumulative', 'calls']:
            s = io.StringIO()
            ps = pstats.Stats(profile, stream=s)
            ps.sort_stats(sort_by).print_stats("netflow")
            ps.sort_stats(sort_by).print_callees(.5)
            print(s.getvalue())
