from intrusion_detection.port_scan import PortScanDetector


detector = PortScanDetector(
    port_threshold=5,
    time_window=10
)

source_ip = "192.168.1.50"

ports = [21, 22, 23, 25, 80, 443]

for port in ports:
    alert = detector.record_connection(source_ip, port)

    if alert:
        print("ALERT DETECTED!")
        print(alert)
    else:
        print(f"Connection recorded: port {port}")