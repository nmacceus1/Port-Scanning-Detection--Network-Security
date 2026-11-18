

# Port Scanning Detection System
#
# Adapted from the project:
# https://github.com/alexamanpreet/port_scan_detector
#
# Modified to use Python 3 and Scapy.
# Added live port monitoring, traffic classification,
# unique-port tracking, alerts, logging, and summaries.

from scapy.all import IP, TCP, UDP
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
import time

# ---------------------------------------
# DETECTION SETTINGS
# ---------------------------------------

TIME_WINDOW = 10
WARNING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 10
ALERT_COOLDOWN = 30

LOG_FILE = Path(__file__).resolve().parent / "scan_alerts.log"

# Recent activity grouped by source, destination,
# and protocol/scan type.
scan_activity = defaultdict(deque)

# All unique destination ports observed in this session.
port_records = {}

# Track the last alert for each connection.
last_alert = {}

# Session statistics
total_packets = 0
total_alerts = 0

STATUS_LEVELS = {
    "NORMAL": 0,
    "WARNING": 1,
    "SUSPICIOUS": 2
}


# ---------------------------------------
# IDENTIFY PACKET TYPE
# ---------------------------------------

def identify_scan_type(packet):

    if TCP in packet:
        flags = int(packet[TCP].flags)

        if flags == 0x02:
            return "TCP SYN"

        elif flags == 0x01:
            return "TCP FIN"

        elif flags == 0x29:
            return "TCP XMAS"

        elif flags == 0x00:
            return "TCP NULL"

    elif UDP in packet:
        return "UDP"

    return None


# ---------------------------------------
# CLASSIFY ACTIVITY
# ---------------------------------------

def classify_activity(unique_count):

    if unique_count >= SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"

    elif unique_count >= WARNING_THRESHOLD:
        return "WARNING"

    return "NORMAL"


# ---------------------------------------
# DISPLAY INDIVIDUAL PORT
# ---------------------------------------

def display_port(port, protocol, status):

    print(
        f"{str(port):<12}"
        f"{protocol:<16}"
        f"{status:<15}",
        flush=True
    )


# ---------------------------------------
# GENERATE SECURITY ALERT
# ---------------------------------------

def generate_alert(source_ip, destination_ip,
                   scan_type, unique_ports):

    global total_alerts

    total_alerts += 1

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    sorted_ports = sorted(unique_ports)

    alert = (
        "\n========================================\n"
        "[!] SUSPICIOUS ACTIVITY DETECTED!\n"
        "========================================\n"
        f"Scan Type: {scan_type}\n"
        f"Source IP: {source_ip}\n"
        f"Destination IP: {destination_ip}\n"
        f"Unique Ports Scanned: {len(sorted_ports)}\n"
        f"Scanned Ports: {sorted_ports}\n"
        f"Time Window: {TIME_WINDOW} seconds\n"
        f"Timestamp: {timestamp}\n"
        "Status: SUSPICIOUS\n"
        "========================================\n"
    )

    print(alert, flush=True)

    try:
        with open(LOG_FILE, "a") as log:
            log.write(alert + "\n")

    except OSError as error:
        print(f"[LOG ERROR] {error}")


# ---------------------------------------
# MAIN PACKET DETECTION
# ---------------------------------------

def detect_scan(packet):

    global total_packets

    if IP not in packet:
        return

    scan_type = identify_scan_type(packet)

    if scan_type is None:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    if TCP in packet:
        destination_port = int(packet[TCP].dport)

    elif UDP in packet:
        destination_port = int(packet[UDP].dport)

    else:
        return

    total_packets += 1

    # Use the time when the packet is processed.
    current_time = time.time()

    connection = (
        source_ip,
        destination_ip,
        scan_type
    )

    scan_activity[connection].append(
        (current_time, destination_port)
    )

    # Remove packets outside the rolling window.
    recent_packets = scan_activity[connection]

    while (
        recent_packets
        and current_time - recent_packets[0][0]
        > TIME_WINDOW
    ):
        recent_packets.popleft()

    unique_ports = {
        port for _, port in recent_packets
    }

    # Determine current activity status.
    status = classify_activity(len(unique_ports))

    # Update records for every port involved in
    # the current scanning pattern.
    for port in unique_ports:

        record_key = (
            source_ip,
            destination_ip,
            scan_type,
            port
        )

        if record_key not in port_records:
            port_records[record_key] = "NORMAL"

        previous_status = port_records[record_key]

        # Retain the highest risk level observed
        # for each port during this session.
        if (
            STATUS_LEVELS[status]
            > STATUS_LEVELS[previous_status]
        ):
            port_records[record_key] = status

    # Show a port when it first appears.
    current_key = (
        source_ip,
        destination_ip,
        scan_type,
        destination_port
    )

    # Track which ports have already been displayed.
    if current_key not in displayed_ports:

        displayed_ports.add(current_key)

        display_port(
            destination_port,
            scan_type,
            port_records[current_key]
        )

    # Generate alert when threshold is reached.
    if status == "SUSPICIOUS":

        previous_alert = last_alert.get(connection)

        if (
            previous_alert is None
            or current_time - previous_alert
            >= ALERT_COOLDOWN
        ):

            generate_alert(
                source_ip,
                destination_ip,
                scan_type,
                unique_ports
            )

            last_alert[connection] = current_time


# ---------------------------------------
# FINAL SESSION SUMMARY
# ---------------------------------------

def print_summary():

    print("\n")
    print("=" * 65)
    print("PORT SCANNING DETECTION - FINAL REPORT")
    print("=" * 65)

    print(
        f"{'PORT':<10}"
        f"{'PROTOCOL':<14}"
        f"{'STATUS':<15}"
        f"{'DESTINATION IP'}"
    )

    print("-" * 65)

    normal_count = 0
    warning_count = 0
    suspicious_count = 0

    # Print all observed destination ports.
    for record_key in sorted(
        port_records,
        key=lambda item: (
            item[1], item[2], item[3], item[0]
        )
    ):

        source_ip, destination_ip, protocol, port = record_key
        status = port_records[record_key]

        print(
            f"{port:<10}"
            f"{protocol:<14}"
            f"{status:<15}"
            f"{destination_ip}"
        )

        if status == "NORMAL":
            normal_count += 1

        elif status == "WARNING":
            warning_count += 1

        elif status == "SUSPICIOUS":
            suspicious_count += 1

    print("-" * 65)

    total_ports = len(port_records)

    print(f"Total Packets Analyzed: {total_packets}")
    print(f"Total Port Records: {total_ports}")
    print(f"Normal Port Records: {normal_count}")
    print(f"Warning Port Records: {warning_count}")
    print(f"Suspicious Port Records: {suspicious_count}")
    print(f"Total Security Alerts: {total_alerts}")

    print("=" * 65)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    summary = (
        f"\nSESSION SUMMARY - {timestamp}\n"
        f"Packets Analyzed: {total_packets}\n"
        f"Total Port Records: {total_ports}\n"
        f"Normal: {normal_count}\n"
        f"Warning: {warning_count}\n"
        f"Suspicious: {suspicious_count}\n"
        f"Security Alerts: {total_alerts}\n"
    )

    try:
        with open(LOG_FILE, "a") as log:
            log.write(summary)

    except OSError as error:
        print(f"[LOG ERROR] {error}")


# Ports already printed during live monitoring.
displayed_ports = set()
