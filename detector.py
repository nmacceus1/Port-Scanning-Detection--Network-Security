

from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime
import time

# Port Scanning Detection Project

# Store network activity for each source IP
scan_activity = defaultdict(list)

# Store the time of the last alert
last_alert = {}

# Detection settings
TIME_WINDOW = 10
PORT_THRESHOLD = 10
ALERT_COOLDOWN = 30


def detect_scan(packet):

    # Check for IP and TCP packets
    if IP in packet and TCP in packet:

        # Only monitor TCP SYN packets
        if packet[TCP].flags != 0x02:
            return

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        destination_port = packet[TCP].dport
        current_time = time.time()

        # Track each source and destination pair
        connection = (source_ip, destination_ip)

        # Record the port and time
        scan_activity[connection].append(
            (current_time, destination_port)
        )

        # Remove packets older than 10 seconds
        scan_activity[connection] = [
            (t, p)
            for t, p in scan_activity[connection]
            if current_time - t <= TIME_WINDOW
        ]

        # Count unique destination ports
        unique_ports = {
            p for t, p in scan_activity[connection]
        }

        # Check for suspicious scanning activity
        if len(unique_ports) >= PORT_THRESHOLD:

            previous_alert = last_alert.get(connection, 0)

            # Prevent duplicate alerts
            if current_time - previous_alert >= ALERT_COOLDOWN:

                timestamp = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                # Create suspicious activity warning
                alert = (
                    "\n====================================\n"
                    "[!] SUSPICIOUS ACTIVITY DETECTED!\n"
                    "Possible Port Scanning Attack\n"
                    f"Source IP: {source_ip}\n"
                    f"Destination IP: {destination_ip}\n"
                    f"Unique Ports Scanned: {len(unique_ports)}\n"
                    f"Time Window: {TIME_WINDOW} seconds\n"
                    f"Timestamp: {timestamp}\n"
                    "Status: SUSPICIOUS\n"
                    "===================================="
                )

                # Display alert
                print(alert)

                # Save alert to log file
                with open("scan_alerts.log", "a") as log:
                    log.write(alert + "\n")

                # Update last alert time
                last_alert[connection] = current_time


# Start the detection program
print("====================================")
print("PORT SCANNING DETECTOR STARTED")
print("Monitoring network traffic...")
print("Detection Threshold: 10 unique ports")
print("Time Window: 10 seconds")
print("====================================")

# Capture network packets
sniff(
    iface="lo",
    filter="tcp",
    prn=detect_scan,
    store=False
)
