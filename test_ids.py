from intrusion_detection.ids import NetGuardIDS


ids = NetGuardIDS(
    port_threshold=5,
    traffic_threshold=5,
    time_window=10
)

source_ip = "192.168.1.50"

ports = [21, 22, 23, 25, 80, 443]

for port in ports:
    alerts = ids.process_connection(
        source_ip,
        port
    )

    for alert in alerts:
        print("IDS ALERT DETECTED!")
        print(alert)

print("\nTotal alerts:", ids.get_alert_count())

print("\nAll alerts:")
ids.display_alerts()