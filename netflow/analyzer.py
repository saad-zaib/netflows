#!/usr/bin/env python3

"""
Modified analyzer script for NetFlow Python package.
Handles JSON entries in the netflow.json file with multiple top-level keys.
Custom DNS resolution using specified DNS servers.
"""

import argparse
import contextlib
import functools
import json
import logging
import os.path
import socket
import sys
import time
import ipaddress
from collections import namedtuple
from datetime import datetime

# Add the dns.resolver import for custom DNS resolution
try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False
    logging.warning("dnspython module not found. Custom DNS servers will not be used. Install with: pip install dnspython")

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6"
}

Pair = namedtuple('Pair', ['src', 'dest'])

# Set up logging
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


def printv(message, *args_, **kwargs):
    if args.verbose:
        print(message.format(*args_, **kwargs))


@functools.lru_cache(maxsize=None)
def resolve_hostname(ip: str) -> str:
    """Resolve IP address to hostname using custom DNS servers if specified"""
    if args.no_dns:
        # If no DNS resolution is requested, return empty string
        return ""

    # If custom DNS servers are specified and dnspython is available
    if args.dns_servers and HAS_DNSPYTHON:
        try:
            # Create a custom resolver with the specified DNS servers
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = args.dns_servers

            # Convert IP to reverse pointer format for PTR lookup
            reverse_name = dns.reversename.from_address(ip)

            # Set a timeout for DNS resolution
            custom_resolver.timeout = 1.0
            custom_resolver.lifetime = 1.0

            # Perform the lookup
            answers = custom_resolver.resolve(reverse_name, 'PTR')
            if answers:
                # Return the first response, removing the trailing dot
                return str(answers[0]).rstrip('.')
            return args.dns_fallback
        except Exception as e:
            if args.verbose:
                logger.debug(f"DNS resolution failed for {ip}: {str(e)}")
            return args.dns_fallback
    else:
        # Fall back to standard system resolution if custom DNS is not available
        try:
            hostname = socket.getfqdn(ip)
            # If getfqdn returns the same IP, it means resolution failed
            if hostname == ip:
                return args.dns_fallback
            return hostname
        except Exception:
            return args.dns_fallback


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
    """Connection model for two flows."""

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
        self.protocol = src.get('PROTOCOL', 0)

        # Duration is given in milliseconds
        self.duration = src['LAST_SWITCHED'] - src['FIRST_SWITCHED']
        if self.duration < 0:
            # 32 bit int has its limits. Handling overflow here
            self.duration = (2 ** 32 - src['FIRST_SWITCHED']) + src['LAST_SWITCHED']

    def __repr__(self):
        return "<Connection from {} to {}, size {}>".format(
            self.src, self.dest, self.human_size)

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
    def raw_duration(self):
        return self.duration // 1000  # uptime in milliseconds, floor it

    @property
    def hostnames(self):
        # Resolve the IPs of this flows to their hostname
        src_hostname = resolve_hostname(self.src.compressed)
        dest_hostname = resolve_hostname(self.dest.compressed)
        return Pair(src_hostname, dest_hostname)

    @property
    def service(self):
        # Resolve ports to their services, if known
        default = "unknown"
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.src_port)
        with contextlib.suppress(OSError):
            return socket.getservbyport(self.dest_port)
        return default

    @property
    def total_packets(self):
        return self.src_flow["IN_PKTS"] + self.dest_flow["IN_PKTS"]

    def to_dict(self):
        """Convert the connection object to a dictionary for JSON output"""
        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "service": self.service,
            "protocol": IP_PROTOCOLS.get(self.protocol, "UNKNOWN"),
            "size": self.size,
            "human_size": self.human_size,
            "duration_ms": self.duration,
            "duration_sec": self.raw_duration,
            "human_duration": self.human_duration,
            "total_packets": self.total_packets,
            "source": {
                "ip": self.src.compressed,
                "hostname": self.hostnames.src,
                "port": self.src_port
            },
            "destination": {
                "ip": self.dest.compressed,
                "hostname": self.hostnames.dest,
                "port": self.dest_port
            }
        }


def process_file(file_path, processed_lines, match_host=None, packets_threshold=10):
    """Process the JSON file with single-line JSON entries and return new connections"""
    new_connections = []

    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error(f"File {file_path} not found")
        return []

    # The following dict holds flows which are looking for a peer
    pending = {}

    # Process each line in the file
    for line_num, line in enumerate(lines):
        # Skip already processed lines
        if line_num in processed_lines:
            continue

        # Mark as processed
        processed_lines.add(line_num)

        try:
            line = line.strip()
            if not line:  # Skip empty lines
                continue

            entry = json.loads(line)

            # Check if the entry has the expected structure
            if "header" not in entry or "flows" not in entry:
                logger.warning(f"Line {line_num} doesn't have required 'header' and 'flows' fields")
                continue

            # Get header and flows directly from the entry
            data = entry

            if data["header"]["version"] == 10:
                logger.warning("Skipped IPFIX entry, because analysis of IPFIX is not yet implemented")
                continue

            flows = data.get("flows", [])

            for flow in sorted(flows, key=lambda x: x["FIRST_SWITCHED"]):
                first_switched = flow["FIRST_SWITCHED"]

                # Find the peer for this connection
                if "IPV4_SRC_ADDR" in flow or flow.get("IP_PROTOCOL_VERSION") == 4:
                    local_peer = flow["IPV4_SRC_ADDR"]
                    remote_peer = flow["IPV4_DST_ADDR"]
                else:
                    local_peer = flow["IPV6_SRC_ADDR"]
                    remote_peer = flow["IPV6_DST_ADDR"]

                # Match on host filter passed in as argumenthostn
                if match_host and not any([local_peer == match_host, remote_peer == match_host]):
                    # If a match_host is given but neither local_peer nor remote_peer match
                    continue

                if first_switched not in pending:
                    pending[first_switched] = {}

                # Match peers
                if remote_peer in pending[first_switched]:
                    # The destination peer put itself into the pending dict, getting and removing entry
                    peer_flow = pending[first_switched].pop(remote_peer)
                    if len(pending[first_switched]) == 0:
                        del pending[first_switched]

                    # Create connection and check packet threshold
                    con = Connection(flow, peer_flow)
                    if con.total_packets < packets_threshold:
                        continue

                    # Add to new connections
                    new_connections.append(con)
                else:
                    # Flow did not find a matching, pending peer - inserting itself
                    pending[first_switched][local_peer] = flow

        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON at line {line_num}: {line[:50]}...")
        except Exception as e:
            logger.error(f"Error processing line {line_num}: {str(e)}")

    return new_connections


def monitor_file(file_path, interval=1.0, match_host=None, packets_threshold=10, output_file=None):
    """Monitor a file for changes and process new lines"""
    processed_lines = set()
    last_size = 0

    print(json.dumps({"status": "starting", "message": "Starting to monitor file", "file": file_path}))

    while True:
        try:
            # Check if file exists and has changed size
            try:
                current_size = os.path.getsize(file_path)
            except FileNotFoundError:
                # Wait for the file to be created
                time.sleep(interval)
                continue

            if current_size > last_size:
                # Process the file
                new_connections = process_file(
                    file_path,
                    processed_lines,
                    match_host=match_host,
                    packets_threshold=packets_threshold
                )

                # Output connections as JSON
                if new_connections:
                    for conn in new_connections:
                        # Output each connection as a single-line JSON
                        json_output = json.dumps(conn.to_dict(), separators=(',', ':'))

                        if output_file:
                            with open(output_file, 'a') as f:
                                f.write(json_output + "\n")
                        else:
                            print(json_output)

                last_size = current_size

            # Wait before checking again
            time.sleep(interval)

        except KeyboardInterrupt:
            print(json.dumps({"status": "stopped", "message": "Monitoring stopped by user"}))
            break
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor and analyze NetFlow JSON data in real-time")
    parser.add_argument("-f", "--file", dest="file", type=str, default="netflow.json",
                      help="The JSON file to monitor (defaults to netflow.json)")
    parser.add_argument("-o", "--output", dest="output", type=str, default=None,
                      help="Output file for JSON results (defaults to stdout)")
    parser.add_argument("-i", "--interval", dest="interval", type=float, default=1.0,
                      help="Interval in seconds to check for file changes (default: 1.0)")
    parser.add_argument("-p", "--packets", dest="packets_threshold", type=int, default=1,
                      help="Number of packets representing the lower bound in connections to be processed")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                      help="Enable verbose output.")
    parser.add_argument("--match-host", dest="match_host", type=str, default=None,
                      help="Filter output by matching on the given host (matches source or destination)")
    parser.add_argument("-n", "--no-dns", dest="no_dns", action="store_true",
                      help="Disable DNS resolving of IP addresses")

    # Add new arguments for custom DNS resolution
    parser.add_argument("--dns-servers", dest="dns_servers", type=str, nargs="+", default=None,
                      help="Custom DNS servers to use (e.g. 8.8.8.8 1.1.1.1)")
    parser.add_argument("--dns-fallback", dest="dns_fallback", type=str, default="others.com",
                      help="Value to use when DNS resolution fails (default: others.com, use empty string for blank)")

    args = parser.parse_args()

    # Set logging
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    # Sanity check for IP address matching
    if args.match_host:
        try:
            match_host = ipaddress.ip_address(args.match_host)
        except ValueError:
            print(json.dumps({"status": "error", "message": f"IP address '{args.match_host}' is neither IPv4 nor IPv6"}))
            exit(1)

    # Validate DNS servers if provided
    if args.dns_servers:
        # Check if dnspython is available
        if not HAS_DNSPYTHON:
            logger.warning("dnspython module not installed. Custom DNS servers will not be used.")
            logger.warning("Install dnspython with: pip install dnspython")

        # Validate each IP address
        valid_servers = []
        for server in args.dns_servers:
            try:
                ipaddress.ip_address(server)
                valid_servers.append(server)
            except ValueError:
                logger.warning(f"Invalid DNS server IP: {server} - skipping")

        args.dns_servers = valid_servers
        if not valid_servers:
            logger.warning("No valid DNS servers provided, falling back to system DNS")
            args.dns_servers = None

    # Start monitoring
    monitor_file(
        args.file,
        interval=args.interval,
        match_host=args.match_host,
        packets_threshold=args.packets_threshold,
        output_file=args.output
    )
