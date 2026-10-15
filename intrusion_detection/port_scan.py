from collections import defaultdict
from datetime import datetime, timedelta


class PortScanDetector:
    """
    Detects possible port scanning activity by tracking
    the number of unique destination ports contacted by
    each source IP within a time window.
    """

    def __init__(self, port_threshold=10, time_window=10):
        self.port_threshold = port_threshold
        self.time_window = timedelta(seconds=time_window)

        # Stores connection records for each source IP
        self.connections = defaultdict(list)

    def record_connection(self, source_ip, destination_port):
        """
        Record a new connection attempt.

        Args:
            source_ip (str): IP address initiating the connection.
            destination_port (int): Destination port being contacted.

        Returns:
            dict or None: Alert information if a port scan is detected.
        """

        current_time = datetime.now()

        self.connections[source_ip].append(
            (current_time, destination_port)
        )

        self._remove_old_connections(source_ip, current_time)

        unique_ports = {
            port for _, port in self.connections[source_ip]
        }

        if len(unique_ports) >= self.port_threshold:
            return self._create_alert(
                source_ip,
                unique_ports,
                current_time
            )

        return None

    def _remove_old_connections(self, source_ip, current_time):
        """Remove connection records outside the time window."""

        cutoff_time = current_time - self.time_window

        self.connections[source_ip] = [
            (timestamp, port)
            for timestamp, port in self.connections[source_ip]
            if timestamp >= cutoff_time
        ]

    def _create_alert(self, source_ip, ports, timestamp):
        """Create an alert dictionary for a detected port scan."""

        return {
            "alert_type": "PORT_SCAN",
            "source_ip": source_ip,
            "unique_ports": sorted(ports),
            "port_count": len(ports),
            "timestamp": timestamp.isoformat(),
            "severity": "HIGH"
        }