from intrusion_detection.traffic_detection import TrafficAnomalyDetector


detector = TrafficAnomalyDetector(
    traffic_threshold=5,
    time_window=10
)

source_ip = "192.168.1.50"

for i in range(6):
    alert = detector.record_connection(source_ip)

    if alert:
        print("TRAFFIC ANOMALY DETECTED!")
        print(alert)