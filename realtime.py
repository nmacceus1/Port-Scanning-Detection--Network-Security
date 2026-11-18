
# Real-Time Port Scanning Monitor
#
# Adapted from:
# https://github.com/alexamanpreet/port_scan_detector
#
# Uses Scapy instead of tcpdump and dpkt.

from scapy.all import sniff
from parsing import detect_scan, print_summary

print("=" * 65)
print("PORT SCANNING DETECTION SYSTEM")
print("=" * 65)
print("Monitoring live TCP and UDP traffic")
print("Interface: lo")
print("Warning Threshold: 5 unique ports")
print("Suspicious Threshold: 10 unique ports")
print("Time Window: 10 seconds")
print("Alert Cooldown: 30 seconds")
print("Press Ctrl+C to stop and view summary")
print("=" * 65)

print(
    f"{'PORT':<12}"
    f"{'PROTOCOL':<16}"
    f"{'STATUS':<15}"
)

print("-" * 43)

try:
    sniff(
        iface="lo",
        filter="tcp or udp",
        prn=detect_scan,
        store=False
    )

except KeyboardInterrupt:
    print("\nMonitoring stopped by user.")

finally:
    print_summary()

