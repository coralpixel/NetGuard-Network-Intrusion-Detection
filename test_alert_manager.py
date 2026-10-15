from intrusion_detection.alert_manager import AlertManager


alert_manager = AlertManager()


port_scan_alert = {
    "alert_type": "PORT_SCAN",
    "source_ip": "192.168.1.50",
    "port_count": 5,
    "timestamp": "2026-10-15T23:40:00",
    "severity": "HIGH"
}


traffic_alert = {
    "alert_type": "TRAFFIC_ANOMALY",
    "source_ip": "192.168.1.60",
    "connection_count": 25,
    "timestamp": "2026-10-15T23:41:00",
    "severity": "MEDIUM"
}


alert_manager.add_alert(port_scan_alert)
alert_manager.add_alert(traffic_alert)


print(f"Total alerts: {alert_manager.get_alert_count()}")

alert_manager.display_all_alerts()