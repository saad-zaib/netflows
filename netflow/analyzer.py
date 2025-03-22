#!/usr/bin/env python3
"""
Real-time JSON NetFlow Analyzer

Processes NetFlow data from a JSON file in real-time and outputs analysis as JSON.
Based on the original analyzer.py script.
Enhanced with dnspython for better DNS resolution using Google DNS servers.
"""

import argparse
import contextlib
import dns.resolver
import dns.reversename
import functools
import ipaddress
import json
import logging
import os.path
import socket
import sys
import time
from collections import namedtuple
from datetime import datetime

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}

Pair = namedtuple('Pair', ['src', 'dest'])

logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Configure DNS resolver to use Google DNS
dns_resolver = dns.resolver.Resolver()
dns_resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS servers
dns_resolver.timeout = 1.0  # 1 second timeout for DNS queries
dns_resolver.lifetime = 2.0  # 2 second overall timeout for DNS resolution

@functools.lru_cache(maxsize=1000)  # Limit cache size to prevent memory issues
def resolve_hostname(ip: str) -> str:
    """
    Resolve an IP address to a hostname using dnspython.
    Falls back to the original IP if resolution fails.

    Args:
        ip: IP address to resolve

    Returns:
        Hostname or original IP if resolution fails or is disabled
    """
    if args.no_dns:
        # If no DNS resolution is requested, simply return the IP string
        return ip

    try:
        # Convert IP to reverse pointer
        reverse_name = dns.reversename.from_address(ip)
        # Perform reverse DNS lookup
        dns_answer = dns_resolver.resolve(reverse_name, 'PTR')
        # Return the first PTR record (without trailing dot)
        return str(dns_answer[0]).rstrip('.')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException) as e:
        logger.debug(f"DNS resolution failed for {ip}: {e}")
        return ip
    except Exception as e:
        logger.warning(f"Unexpected error resolving {ip}: {e}")
        return ip


def fallback(d, keys):
    for k in keys:
        if k in d:
            return d[k]
    raise KeyError(", ".join(keys))


def human_size(size_bytes):
    # Calculate a human readable size of the flow
    if size_bytes < 1024:
        return "%dB" % size_bytes
    elif size_bytes / 1024. < 1024:
        return "%.2fK" % (size_bytes / 1024.)
    elif size_bytes / 1024. ** 2 < 1024:
        return "%.2fM" % (size_bytes / 1024. ** 2)
    else:
        return "%.2fG" % (size_bytes / 1024. ** 3)


def human_duration(seconds):
    # Calculate human readable duration times
    if seconds < 60:
        # seconds
        return "%d sec" % seconds
    if seconds / 60 > 60:
        # hours
        return "%d:%02d.%02d hours" % (seconds / 60 ** 2, seconds % 60 ** 2 / 60, seconds % 60)
    # minutes
    return "%02d:%02d min" % (seconds / 60, seconds % 60)


class Connection:
    """Connection model for two flows.
    The direction of the data flow can be seen by looking at the size.

    'src' describes the peer which sends more data towards the other. This
    does NOT have to mean that 'src' was the initiator of the connection.
    """

    def __init__(self, flow1, flow2):
        if not flow1 or not flow2:
            raise Exception("A connection requires two flows")

        # Assume the size that sent the most data is the source
        size1 = fallback(flow1, ['IN_BYTES', 'IN_OCTETS'])
        size2 = fallback(flow2, ['IN_BYTES', 'IN_OCTETS'])
        if size1 >= size2:
            src = flow1
            dest = flow2
        else:
            src = flow2
            dest = flow1

        self.src_flow = src
        self.dest_flow = dest
        ips = self.get_ips(src)
        self.src = ips.src
        self.dest = ips.dest
        self.src_port = fallback(src, ['L4_SRC_PORT', 'SRC_PORT'])
        self.dest_port = fallback(dest, ['L4_DST_PORT', 'DST_PORT'])
        self.size = fallback(src, ['IN_BYTES', 'IN_OCTETS'])

        # Duration is given in milliseconds
        self.duration = src['LAST_SWITCHED'] - src['FIRST_SWITCHED']
        if self.duration < 0:
            # 32 bit int has its limits. Handling overflow here
            self.duration = (2 ** 32 - src['FIRST_SWITCHED']) + src['LAST_SWITCHED']

    @staticmethod
    def get_ips(flow):
        # IPv4
        if flow.get('IP_PROTOCOL_VERSION') == 4 or \
                'IPV4_SRC_ADDR' in flow or 'IPV4_DST_ADDR' in flow:
            return Pair(
                ipaddress.ip_address(flow['IPV4_SRC_ADDR']),
                ipaddress.ip_address(flow['IPV4_DST_ADDR'])
            )

        # IPv6
        return Pair(
            ipaddress.ip_address(flow['IPV6_SRC_ADDR']),
            ipaddress.ip_address(flow['IPV6_DST_ADDR'])
        )

    @property
    def human_size(self):
        return human_size(self.size)

    @property
    def human_duration(self):
        duration = self.duration // 1000  # uptime in milliseconds, floor it
        return human_duration(duration)

    @property
    def hostnames(self):
        # Resolve the IPs of this flows to their hostname
        src_hostname = resolve_hostname(self.src.compressed)
        dest_hostname = resolve_hostname(self.dest.compressed)
        return Pair(src_hostname, dest_hostname)

    @property
    def service(self):
        # Resolve ports to their services, if known
        default = "({} {})".format(self.src_port, self.dest_port)
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.src_port)
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.dest_port)
        return default

    @property
    def total_packets(self):
        return self.src_flow["IN_PKTS"] + self.dest_flow["IN_PKTS"]

    def to_json(self):
        """Return a JSON-serializable representation of the Connection"""
        return {
            "src": {
                "ip": self.src.compressed,
                "hostname": self.hostnames.src,
                "port": self.src_port,
            },
            "dest": {
                "ip": self.dest.compressed,
                "hostname": self.hostnames.dest,
                "port": self.dest_port,
            },
            "service": self.service.upper(),
            "size": {
                "bytes": self.size,
                "human": self.human_size
            },
            "duration": {
                "ms": self.duration,
                "human": self.human_duration
            },
            "packets": self.total_packets,
            "protocol": IP_PROTOCOLS.get(self.src_flow.get("PROTOCOL", 0), "UNKNOWN"),
        }


class NetFlowAnalyzer:
    """Process NetFlow data from a JSON file in real-time."""

    def __init__(self, input_file, match_host=None, packets_threshold=10, no_dns=False, verbose=False):
        self.input_file = input_file
        self.match_host = match_host
        self.packets_threshold = packets_threshold
        self.no_dns = no_dns
        self.verbose = verbose
        self.pending = {}
        self.skipped = 0
        self.processed = 0
        self.file_position = 0

        # Track the last position in the file
        self.last_position = 0

        # For connection tracking
        self.seen_connections = set()

    def printv(self, message, *args_, **kwargs):
        if self.verbose:
            print(message.format(*args_, **kwargs))

    def process_data(self, callback=None):
        """Process all available data from the file and call the callback for each connection.

        Args:
            callback: Function to call for each connection with signature callback(timestamp, connection)
        """
        try:
            with open(self.input_file, 'r') as f:
                # Seek to the last position we read
                f.seek(self.last_position)

                # Read any new data
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON: {e}")
                        continue

                    if 'timestamp' not in entry:
                        logger.warning(f"The line does not have a timestamp key: {entry.keys()}")
                        continue

                    ts = entry['timestamp']  # use the timestamp directly

                    if "header" not in entry:
                        logger.error(f"No header dict in entry")
                        continue

                    if entry["header"]["version"] == 10:
                        logger.warning("Skipped IPFIX entry, because analysis of IPFIX is not yet implemented")
                        continue

                    timestamp = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M.%S")
                    client = entry["client"]
                    flows = entry["flows"]

                    for flow in sorted(flows, key=lambda x: x["FIRST_SWITCHED"]):
                        first_switched = flow["FIRST_SWITCHED"]

                        # Find the peer information
                        if "IPV4_SRC_ADDR" in flow or flow.get("IP_PROTOCOL_VERSION") == 4:
                            local_peer = flow["IPV4_SRC_ADDR"]
                            remote_peer = flow["IPV4_DST_ADDR"]
                        else:
                            local_peer = flow["IPV6_SRC_ADDR"]
                            remote_peer = flow["IPV6_DST_ADDR"]

                        # Match on host filter passed in as argument
                        if self.match_host and not any([local_peer == self.match_host, remote_peer == self.match_host]):
                            # If a match_host is given but neither local_peer nor remote_peer match
                            continue

                        if first_switched not in self.pending:
                            self.pending[first_switched] = {}

                        # Match peers
                        if remote_peer in self.pending[first_switched]:
                            # The destination peer put itself into the pending dict, getting and removing entry
                            peer_flow = self.pending[first_switched].pop(remote_peer)
                            if len(self.pending[first_switched]) == 0:
                                del self.pending[first_switched]
                        else:
                            # Flow did not find a matching, pending peer - inserting itself
                            self.pending[first_switched][local_peer] = flow
                            continue

                        con = Connection(flow, peer_flow)
                        if con.total_packets < self.packets_threshold:
                            self.skipped += 1
                            continue

                        # Generate a unique identifier for this connection
                        con_id = f"{con.src.compressed}:{con.src_port}-{con.dest.compressed}:{con.dest_port}"

                        # Skip if we've already seen this connection
                        if con_id in self.seen_connections:
                            continue

                        # Mark connection as seen
                        self.seen_connections.add(con_id)

                        # Process the connection
                        self.processed += 1

                        # Call the callback if provided
                        if callback:
                            callback(timestamp, con)

                # Remember where we got to for next time
                self.last_position = f.tell()

        except Exception as e:
            logger.error(f"Error processing file: {e}")
            import traceback
            traceback.print_exc()

    def analyze_continuously(self, interval=1.0, output_file=None):
        """
        Continuously analyze the NetFlow data as it comes in.

        Args:
            interval: How often to check for new data (in seconds)
            output_file: Where to write the JSON output (None for stdout)
        """
        def process_connection(timestamp, connection):
            # Create JSON output
            output = {
                "timestamp": timestamp,
                "connection": connection.to_json()
            }

            # Output as JSON
            json_out = json.dumps(output)
            if output_file:
                with open(output_file, 'a') as f:
                    f.write(json_out + '\n')
            else:
                print(json_out)

        print("Starting real-time analysis. Press Ctrl+C to stop.")
        try:
            while True:
                self.process_data(callback=process_connection)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nAnalysis stopped.")
        finally:
            if self.verbose:
                print(f"Processed {self.processed} connections, skipped {self.skipped} connections below threshold.")
            # Print DNS cache statistics
            cache_info = resolve_hostname.cache_info()
            print(f"DNS cache statistics: {cache_info.hits} hits, {cache_info.misses} misses, {cache_info.currsize}/{cache_info.maxsize} size")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-time analysis of NetFlow data from JSON")
    parser.add_argument("-f", "--file", dest="file", type=str, default="netflows.json",
                        help="JSON file to analyze (defaults to netflows.json)")
    parser.add_argument("-o", "--output", dest="output", type=str, default=None,
                        help="Output file for JSON results (defaults to stdout)")
    parser.add_argument("-i", "--interval", dest="interval", type=float, default=1.0,
                        help="Polling interval in seconds (default: 1.0)")
    parser.add_argument("-p", "--packets", dest="packets_threshold", type=int, default=1,
                        help="Number of packets representing the lower bound in connections to be processed")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--match-host", dest="match_host", type=str, default=None,
                        help="Filter output by matching on the given host (matches source or destination)")
    parser.add_argument("-n", "--no-dns", dest="no_dns", action="store_true",
                        help="Disable DNS resolving of IP addresses")
    parser.add_argument("--dns-timeout", dest="dns_timeout", type=float, default=1.0,
                        help="Timeout for DNS queries in seconds (default: 1.0)")
    parser.add_argument("--dns-servers", dest="dns_servers", type=str, default="8.8.8.8,8.8.4.4",
                        help="Comma-separated list of DNS servers to use (default: Google DNS)")
    args = parser.parse_args()

    # Configure logging level
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    # Update DNS resolver with command line arguments
    if hasattr(args, 'dns_timeout'):
        dns_resolver.timeout = args.dns_timeout
        dns_resolver.lifetime = args.dns_timeout * 2

    if hasattr(args, 'dns_servers'):
        try:
            dns_servers = args.dns_servers.split(',')
            if dns_servers:
                dns_resolver.nameservers = dns_servers
                logger.info(f"Using DNS servers: {', '.join(dns_servers)}")
        except Exception as e:
            logger.warning(f"Failed to set DNS servers, using defaults: {e}")

    # Sanity check for IP address
    if args.match_host:
        try:
            match_host = ipaddress.ip_address(args.match_host)
        except ValueError:
            exit("IP address '{}' is neither IPv4 nor IPv6".format(args.match_host))

    # Check if input file exists or can be created
    if not os.path.exists(args.file) and not os.access(os.path.dirname(args.file) or '.', os.W_OK):
        exit(f"File {args.file} does not exist and cannot be created!")

    # Create the analyzer and run continuously
    analyzer = NetFlowAnalyzer(
        input_file=args.file,
        match_host=args.match_host,
        packets_threshold=args.packets_threshold,
        no_dns=args.no_dns,
        verbose=args.verbose
    )
    analyzer.analyze_continuously(interval=args.interval, output_file=args.output)