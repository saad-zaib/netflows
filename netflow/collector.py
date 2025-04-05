#!/usr/bin/env python3

"""
Enhanced NetFlow collector script for production environments.
Based on https://github.com/bitkeks/python-netflow-v9-softflowd.

This version adds production-ready features:
- Monitoring and alerting
- Resource management
- Fault tolerance
- Better packaging for integration
- Log rotation and retention
- Performance metrics collection

Copyright 2016-2020 Dominik Pataky <software+pynetflow@dpataky.eu>
Licensed under MIT License. See LICENSE.
"""
import argparse
import gzip
import json
import logging
import logging.handlers
import os
import queue
import signal
import socket
import socketserver
import threading
import time
import traceback
from collections import namedtuple, defaultdict
from typing import Dict, Any, Optional, Tuple

# Import prometheus client for metrics collection
try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from ipfix import IPFIXTemplateNotRecognized
from utils import UnknownExportVersion, parse_packet
from v9 import V9TemplateNotRecognized

# Type definitions
RawPacket = namedtuple('RawPacket', ['ts', 'client', 'data'])
ParsedPacket = namedtuple('ParsedPacket', ['ts', 'client', 'export'])

# Default configuration
DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 2055,
    "max_queue_size": 100000,
    "packet_timeout": 3600,  # 1 hour
    "log_level": "INFO",
    "log_file": "netflow_collector.log",
    "log_max_size": 10485760,  # 10MB
    "log_backup_count": 5,
    "output_directory": "netflow_data",
    "output_file": "netflows.json",  # Changed from output_prefix
    "clear_interval": 604800,  # 1 week in seconds
    "metrics_enabled": True,
    "metrics_port": 9101,
    "alert_threshold_drop_rate": 0.01,  # 1% drop rate
    "alert_threshold_queue_full": 0.8,  # 80% queue utilization
    "alert_command": None,  # External command to run on alerts
}

# Configure logging
logger = logging.getLogger("netflow-collector")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Metrics (will be initialized if Prometheus is available)
METRICS = {
    "packets_received": None,
    "packets_processed": None,
    "packets_dropped": None,
    "parse_errors": None,
    "queue_size": None,
    "processing_time": None,
    "active_templates": None,
    "flows_processed": None,
    "bytes_written": None,
}


class AlertManager:
    """Manages alerts for the NetFlow collector"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.last_alert_time = defaultdict(lambda: 0)
        self.alert_cooldown = 300  # 5 minutes between repeated alerts

    def check_alert_conditions(self, metrics_data: Dict[str, Any]) -> None:
        """Check for alert conditions and trigger alerts if needed"""
        current_time = time.time()

        # Check drop rate
        if metrics_data.get("drop_rate", 0) > self.config["alert_threshold_drop_rate"]:
            if current_time - self.last_alert_time["drop_rate"] > self.alert_cooldown:
                self.trigger_alert(
                    f"High packet drop rate: {metrics_data['drop_rate']:.2%}",
                    metrics_data
                )
                self.last_alert_time["drop_rate"] = current_time

        # Check queue utilization
        if metrics_data.get("queue_utilization", 0) > self.config["alert_threshold_queue_full"]:
            if current_time - self.last_alert_time["queue_full"] > self.alert_cooldown:
                self.trigger_alert(
                    f"Queue nearly full: {metrics_data['queue_utilization']:.2%} utilization",
                    metrics_data
                )
                self.last_alert_time["queue_full"] = current_time

    def trigger_alert(self, message: str, metrics_data: Dict[str, Any]) -> None:
        """Trigger an alert with the given message and metrics data"""
        logger.warning(f"ALERT: {message}")

        # Run alert command if configured
        if self.config["alert_command"]:
            try:
                alert_data = {
                    "message": message,
                    "timestamp": time.time(),
                    "metrics": metrics_data
                }
                cmd = f"{self.config['alert_command']} '{json.dumps(alert_data)}'"
                os.system(cmd)
            except Exception as e:
                logger.error(f"Failed to run alert command: {e}")


class FileManager:
    """Manages output file and weekly cleanup"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.bytes_written = 0
        self.last_clear_time = time.time()
        self.clear_interval = 7 * 24 * 3600  # 1 week in seconds

        # Create output directory if it doesn't exist
        os.makedirs(self.config["output_directory"], exist_ok=True)

        # Define the fixed output file path
        self.output_file = os.path.join(self.config["output_directory"], "netflows.json")

        # Initialize the file if it doesn't exist
        if not os.path.exists(self.output_file):
            with open(self.output_file, "w") as f:
                f.write("")
            logger.info(f"Created new output file: {self.output_file}")

    def check_and_clear_file(self) -> None:
        """Check if it's time to clear the file and do so if needed"""
        current_time = time.time()

        # Check if a week has passed since last clear
        if current_time - self.last_clear_time > self.clear_interval:
            try:
                with open(self.output_file, "w") as f:
                    f.write("")
                self.last_clear_time = current_time
                self.bytes_written = 0
                logger.info(f"Weekly cleanup: Cleared {self.output_file}")

                # Update metrics
                if PROMETHEUS_AVAILABLE and METRICS["bytes_written"]:
                    METRICS["bytes_written"].set(0)  # Reset the counter

            except Exception as e:
                logger.error(f"Failed to clear file {self.output_file}: {e}")

    def write_flow(self, data: Dict[str, Any]) -> int:
        """Write flow data to the output file"""
        # Check if it's time for weekly clear
        self.check_and_clear_file()

        # Convert to single-line JSON
        line = json.dumps(data) + "\n"  # Each entry on a new line

        try:
            with open(self.output_file, "a") as fh:  # open as append
                fh.write(line)
                self.bytes_written += len(line)

                # Update metrics
                if PROMETHEUS_AVAILABLE and METRICS["bytes_written"]:
                    METRICS["bytes_written"].inc(len(line))

            return len(line)
        except Exception as e:
            logger.error(f"Failed to write to {self.output_file}: {e}")
            return 0


class QueuingRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]  # get content, [1] would be the socket
        client_address = self.client_address

        # Update metrics
        if PROMETHEUS_AVAILABLE and METRICS["packets_received"]:
            METRICS["packets_received"].inc()

        # Check if queue is full
        if self.server.queue.full():
            if PROMETHEUS_AVAILABLE and METRICS["packets_dropped"]:
                METRICS["packets_dropped"].inc()
            logger.warning(f"Input queue full, dropping packet from {client_address}")
            return

        self.server.queue.put(RawPacket(time.time(), client_address, data))
        logger.debug(
            f"Received {len(data)} bytes of data from {client_address}"
        )


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    """A threaded UDP server that adds a (time, data) tuple to a queue for
    every request it sees
    """
    allow_reuse_address = True

    def __init__(self, interface, queue, max_queue_size):
        self.queue = queue
        self._max_queue_size = max_queue_size

        # If IPv6 interface addresses are used, override the default AF_INET family
        if ":" in interface[0]:
            self.address_family = socket.AF_INET6

        super().__init__(interface, QueuingRequestHandler)

    def queue_full(self) -> bool:
        return self.queue.qsize() >= self._max_queue_size


class ThreadedNetFlowListener(threading.Thread):
    """A thread that listens for incoming NetFlow packets, processes them, and
    makes them available to consumers.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        logger.info(f"Starting the NetFlow listener on {config['host']}:{config['port']}")

        # Initialize metrics if available
        if PROMETHEUS_AVAILABLE and config["metrics_enabled"]:
            self._setup_metrics()
            start_http_server(config["metrics_port"])
            logger.info(f"Started metrics server on port {config['metrics_port']}")

        # Create queues with max size
        self.output = queue.Queue(maxsize=config["max_queue_size"])
        self.input = queue.Queue(maxsize=config["max_queue_size"])

        # Create UDP server
        self.server = QueuingUDPListener(
            (config["host"], config["port"]),
            self.input,
            config["max_queue_size"]
        )

        # Create server thread
        self.thread = threading.Thread(target=self.server.serve_forever, name="UDPListener")
        self.thread.daemon = True
        self.thread.start()

        # Create file manager
        self.file_manager = FileManager(config)

        # Create alert manager
        self.alert_manager = AlertManager(config)

        # Setup shutdown event
        self._shutdown = threading.Event()

        # Create health check thread
        self.health_thread = threading.Thread(target=self._health_check, name="HealthCheck")
        self.health_thread.daemon = True

        # Packet stats
        self.stats = {
            "packets_received": 0,
            "packets_processed": 0,
            "packets_dropped": 0,
            "parse_errors": 0,
            "last_check_time": time.time(),
            "bytes_written": 0,
        }

        # Set thread name
        super().__init__(name="NetFlowProcessor")
        self.daemon = True

    def _setup_metrics(self):
        """Setup Prometheus metrics"""
        METRICS["packets_received"] = Counter('netflow_packets_received_total', 'Total number of NetFlow packets received')
        METRICS["packets_processed"] = Counter('netflow_packets_processed_total', 'Total number of NetFlow packets processed')
        METRICS["packets_dropped"] = Counter('netflow_packets_dropped_total', 'Total number of NetFlow packets dropped')
        METRICS["parse_errors"] = Counter('netflow_parse_errors_total', 'Total number of NetFlow packet parse errors')
        METRICS["queue_size"] = Gauge('netflow_queue_size', 'Current size of the packet queue')
        METRICS["processing_time"] = Histogram('netflow_processing_time_seconds', 'Time taken to process a NetFlow packet')
        METRICS["active_templates"] = Gauge('netflow_active_templates', 'Number of active NetFlow templates', ['type'])
        METRICS["flows_processed"] = Counter('netflow_flows_processed_total', 'Total number of flows processed')
        METRICS["bytes_written"] = Counter('netflow_bytes_written_total', 'Total number of bytes written to output files')

    def _health_check(self):
        """Periodically check the health of the system and update metrics"""
        while not self._shutdown.is_set():
            try:
                current_time = time.time()
                elapsed = current_time - self.stats["last_check_time"]

                # Calculate rates
                packets_received = self.stats["packets_received"]
                packets_processed = self.stats["packets_processed"]
                packets_dropped = self.stats["packets_dropped"]
                total_packets = packets_processed + packets_dropped

                drop_rate = packets_dropped / max(total_packets, 1)
                process_rate = packets_processed / max(elapsed, 1)

                # Get queue sizes
                input_queue_size = self.input.qsize()
                output_queue_size = self.output.qsize()
                queue_utilization = input_queue_size / self.config["max_queue_size"]

                # Log health metrics
                logger.info(
                    f"Health check: processed={packets_processed}, "
                    f"dropped={packets_dropped}, "
                    f"drop_rate={drop_rate:.2%}, "
                    f"process_rate={process_rate:.2f}/s, "
                    f"queue_size={input_queue_size}/{self.config['max_queue_size']}"
                )

                # Update metrics in Prometheus
                if PROMETHEUS_AVAILABLE and METRICS["queue_size"]:
                    METRICS["queue_size"].set(input_queue_size)

                # Check for alert conditions
                metrics_data = {
                    "drop_rate": drop_rate,
                    "process_rate": process_rate,
                    "queue_utilization": queue_utilization,
                    "input_queue_size": input_queue_size,
                    "output_queue_size": output_queue_size,
                    "packets_processed": packets_processed,
                    "packets_dropped": packets_dropped,
                }
                self.alert_manager.check_alert_conditions(metrics_data)

                # Reset stats for next interval
                self.stats["last_check_time"] = current_time

                # Sleep for the next check
                self._shutdown.wait(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in health check: {e}")
                logger.debug(traceback.format_exc())
                time.sleep(60)  # Wait and try again

    def get(self, block=True, timeout=None) -> ParsedPacket:
        """Get a processed flow."""
        return self.output.get(block, timeout)

    def run(self):
        # Start health check thread
        self.health_thread.start()

        # Process packets from the queue
        try:
            templates = {"netflow": {}, "ipfix": {}}
            to_retry = []

            while not self._shutdown.is_set():
                try:
                    # Limited delay to check shutdown flag more frequently
                    pkt = self.input.get(block=True, timeout=0.5)  # type: RawPacket
                except queue.Empty:
                    continue

                # Update template metrics
                if PROMETHEUS_AVAILABLE and METRICS["active_templates"]:
                    METRICS["active_templates"].labels(type="netflow").set(len(templates["netflow"]))
                    METRICS["active_templates"].labels(type="ipfix").set(len(templates["ipfix"]))

                # Process the packet with timing
                start_time = time.time()
                try:
                    # Parse the packet
                    export = parse_packet(pkt.data, templates)

                    # Update stats
                    self.stats["packets_processed"] += 1
                    if PROMETHEUS_AVAILABLE and METRICS["packets_processed"]:
                        METRICS["packets_processed"].inc()

                    # Update flow count metric
                    if hasattr(export, "flows") and PROMETHEUS_AVAILABLE and METRICS["flows_processed"]:
                        METRICS["flows_processed"].inc(len(export.flows))

                except UnknownExportVersion as e:
                    logger.error(f"{e}, ignoring the packet from {pkt.client}")
                    self.stats["parse_errors"] += 1
                    if PROMETHEUS_AVAILABLE and METRICS["parse_errors"]:
                        METRICS["parse_errors"].inc()
                    continue
                except (V9TemplateNotRecognized, IPFIXTemplateNotRecognized):
                    # Handle template recognition errors
                    if time.time() - pkt.ts > self.config["packet_timeout"]:
                        logger.warning(f"Dropping an old and undecodable v9/IPFIX ExportPacket from {pkt.client}")
                        self.stats["packets_dropped"] += 1
                        if PROMETHEUS_AVAILABLE and METRICS["packets_dropped"]:
                            METRICS["packets_dropped"].inc()
                    else:
                        to_retry.append(pkt)
                        logger.debug(f"Failed to decode a v9/IPFIX ExportPacket from {pkt.client} - will "
                                     f"re-attempt when a new template is discovered")
                    continue
                except Exception as e:
                    # Handle unexpected errors
                    logger.error(f"Unexpected error processing packet from {pkt.client}: {e}")
                    logger.debug(traceback.format_exc())
                    self.stats["parse_errors"] += 1
                    if PROMETHEUS_AVAILABLE and METRICS["parse_errors"]:
                        METRICS["parse_errors"].inc()
                    continue
                finally:
                    # Record processing time
                    processing_time = time.time() - start_time
                    if PROMETHEUS_AVAILABLE and METRICS["processing_time"]:
                        METRICS["processing_time"].observe(processing_time)

                # Log successful processing
                if export.header.version == 10:
                    logger.debug(f"Processed an IPFIX ExportPacket with length {export.header.length} from {pkt.client}.")
                else:
                    logger.debug(f"Processed a v{export.header.version} ExportPacket with {export.header.count} flows from {pkt.client}.")

                # If any new templates were discovered, try to process old packets
                if export.header.version in [9, 10] and export.contains_new_templates and to_retry:
                    logger.debug(f"Received new template(s) from {pkt.client}")
                    logger.debug(f"Will re-attempt to decode {len(to_retry)} old v9/IPFIX ExportPackets")
                    for p in to_retry:
                        self.input.put(p)
                    to_retry.clear()

                # Add processed packet to output queue
                try:
                    self.output.put_nowait(ParsedPacket(pkt.ts, pkt.client, export))
                except queue.Full:
                    logger.warning("Output queue full, dropping processed packet")
                    self.stats["packets_dropped"] += 1
                    if PROMETHEUS_AVAILABLE and METRICS["packets_dropped"]:
                        METRICS["packets_dropped"].inc()
        except Exception as e:
            logger.error(f"Error in NetFlow processor: {e}")
            logger.debug(traceback.format_exc())
        finally:
            # Only reached when while loop ends
            logger.info("Shutting down the NetFlow processor")
            self.server.shutdown()
            self.server.server_close()

    def stop(self):
        logger.info("Shutting down the NetFlow listener")
        self._shutdown.set()

    def join(self, timeout=None):
        self.thread.join(timeout=timeout)
        super().join(timeout=timeout)


def setup_logging(config):
    """Set up logging with file rotation"""
    logger.setLevel(getattr(logging, config["log_level"]))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler with rotation
    if config["log_file"]:
        file_handler = logging.handlers.RotatingFileHandler(
            config["log_file"],
            maxBytes=config["log_max_size"],
            backupCount=config["log_backup_count"]
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def load_config():
    """Load configuration from command line arguments"""
    parser = argparse.ArgumentParser(description="Production-ready NetFlow collector.")

    # Basic options
    parser.add_argument("--host", type=str, default=DEFAULT_CONFIG["host"],
                        help="collector listening address")
    parser.add_argument("--port", "-p", type=int, default=DEFAULT_CONFIG["port"],
                        help="collector listener port")
    parser.add_argument("--output-dir", "-o", type=str, default=DEFAULT_CONFIG["output_directory"],
                        help="directory for output files")
    parser.add_argument("--output-file", type=str, default=DEFAULT_CONFIG["output_file"],
                        help="filename for output file")
    parser.add_argument("--debug", "-D", action="store_true",
                        help="Enable debug output")

    # Resource management options
    parser.add_argument("--max-queue-size", type=int, default=DEFAULT_CONFIG["max_queue_size"],
                        help="Maximum size of packet queues")
    parser.add_argument("--packet-timeout", type=int, default=DEFAULT_CONFIG["packet_timeout"],
                        help="Timeout in seconds for undecodable packets")

    # Logging options
    parser.add_argument("--log-file", type=str, default=DEFAULT_CONFIG["log_file"],
                        help="Log file path (empty for no file logging)")
    parser.add_argument("--log-max-size", type=int, default=DEFAULT_CONFIG["log_max_size"],
                        help="Maximum log file size in bytes")
    parser.add_argument("--log-backup-count", type=int, default=DEFAULT_CONFIG["log_backup_count"],
                        help="Number of log files to keep")

    # Rotation options
    parser.add_argument("--clear-interval", type=int,
                   default=DEFAULT_CONFIG["clear_interval"],
                   help="Interval in seconds to clear the output file (default: 1 week)")

    # Metrics options
    parser.add_argument("--metrics", action="store_true", default=DEFAULT_CONFIG["metrics_enabled"],
                        help="Enable Prometheus metrics")
    parser.add_argument("--metrics-port", type=int, default=DEFAULT_CONFIG["metrics_port"],
                        help="Port for Prometheus metrics server")

    # Alerting options
    parser.add_argument("--alert-drop-rate", type=float,
                        default=DEFAULT_CONFIG["alert_threshold_drop_rate"],
                        help="Alert threshold for packet drop rate")
    parser.add_argument("--alert-queue-full", type=float,
                        default=DEFAULT_CONFIG["alert_threshold_queue_full"],
                        help="Alert threshold for queue utilization")
    parser.add_argument("--alert-command", type=str, default=DEFAULT_CONFIG["alert_command"],
                        help="Command to run when alert is triggered")

    args = parser.parse_args()

    # Create config dict from args
    config = DEFAULT_CONFIG.copy()
    config.update({
        "host": args.host,
        "port": args.port,
        "output_directory": args.output_dir,
        "output_file": args.output_file,
        "log_level": "DEBUG" if args.debug else "INFO",
        "max_queue_size": args.max_queue_size,
        "packet_timeout": args.packet_timeout,
        "log_file": args.log_file,
        "log_max_size": args.log_max_size,
        "log_backup_count": args.log_backup_count,
        "clear_interval": args.clear_interval,
        "metrics_enabled": args.metrics and PROMETHEUS_AVAILABLE,
        "metrics_port": args.metrics_port,
        "alert_threshold_drop_rate": args.alert_drop_rate,
        "alert_threshold_queue_full": args.alert_queue_full,
        "alert_command": args.alert_command,
    })

    return config


def process_and_store_flows(listener, file_manager):
    """Process flows from the listener and store them to files"""
    try:
        while True:
            try:
                # Get the next processed packet with a timeout
                ts, client, export = listener.get(timeout=0.5)
            except queue.Empty:
                continue

            # Format flow data for storage
            client_str = f"{client[0]}:{client[1]}"
            entry = {
                "timestamp": ts,
                "client": client_str,
                "header": export.header.to_dict(),
                "flows": [flow.data for flow in export.flows]
            }

            # Write to file
            file_manager.write_flow(entry)
    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, stopping...")
    except Exception as e:
        logger.error(f"Error processing flows: {e}")
        logger.debug(traceback.format_exc())


def main():
    """Main function to run the collector"""
    # Load configuration
    config = load_config()

    # Set up logging
    setup_logging(config)

    # Start the listener
    listener = ThreadedNetFlowListener(config)
    listener.start()

    # Start processing flows
    try:
        file_manager = FileManager(config)
        process_and_store_flows(listener, file_manager)
    finally:
        # Cleanup
        logger.info("Stopping NetFlow collector...")
        listener.stop()
        listener.join(timeout=5)
        logger.info("NetFlow collector stopped.")


if __name__ == "__main__":
    main() 
