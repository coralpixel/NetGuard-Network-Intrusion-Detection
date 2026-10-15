from collections import defaultdict
from datetime import datetime, timedelta


class TrafficAnomalyDetector:
    """
    Detects unusually high traffic from a source IP
    within a specified time window.
    """

    def __init__(self, traffic_threshold=20, time_window=10):
        self.traffic_threshold = traffic_threshold
        self.time_window = timedelta(seconds=time_window)

        # Stores timestamps of connections for each source IP
        self.connections = defaultdict(list)

        # Keeps track of IPs that already triggered an alert
        self.alerted_ips = set()

    def record_connection(self, source_ip):
        """
        Record a connection from a source IP.

        Args:
            source_ip (str): IP address generating the traffic.

        Returns:
            dict or None: Alert if a new traffic anomaly is detected.
        """

        current_time = datetime.now()

        self.connections[source_ip].append(current_time)

        self._remove_old_connections(source_ip, current_time)

        connection_count = len(self.connections[source_ip])

        # Traffic has returned below the threshold.
        # Allow the IP to trigger a new alert later.
        if connection_count <= self.traffic_threshold:
            self.alerted_ips.discard(source_ip)
            return None

        # Prevent repeated alerts for the same traffic spike.
        if source_ip in self.alerted_ips:
            return None

        # First detection of this traffic anomaly.
        self.alerted_ips.add(source_ip)

        return self._create_alert(
            source_ip,
            connection_count,
            current_time
        )

    def _remove_old_connections(self, source_ip, current_time):
        """Remove connections outside the configured time window."""

        cutoff_time = current_time - self.time_window

        self.connections[source_ip] = [
            timestamp
            for timestamp in self.connections[source_ip]
            if timestamp >= cutoff_time
        ]

    def _create_alert(self, source_ip, connection_count, timestamp):
        """Create an alert for unusually high traffic."""

        return {
            "alert_type": "TRAFFIC_ANOMALY",
            "source_ip": source_ip,
            "connection_count": connection_count,
            "time_window_seconds": self.time_window.total_seconds(),
            "timestamp": timestamp.isoformat(),
            "severity": "MEDIUM"
        }