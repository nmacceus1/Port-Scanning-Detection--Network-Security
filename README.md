Port Scanning Detection System

Project Overview

This project is a Python- based network security application designed to detect potential port scanning activity. It uses Scapy to monitor network packets in real time and identifies unusual patterns based on the number of unique destination port contacted within a specified time window.

The system classifies observed port activity as NORMAL, WARNING, or SUSPICIOUS. It also generates security alerts when the suspicious threshold is reached.

Installation
1. Clone the repository:

git clone https://github.com/YOUR_USERNAME/PortScanningDetection.git
cd PortScanningDetection

2. Install the required packages on Ubuntu:

sudo apt update
sudo apt install python3 python3-pip nmap -y

3. Install Scapy:

python3 -m pip install -r requirements.txt

Running the Program:
1. Open a terminal in the project directory and start the detector:

sudo python3 realtime.py

The detector will beging monitoring network traffic on the loopback interface.

2.Open a second terminal and generate test traffic:

sudo nmap -sS -p 1-100 127.0.0.1

3. View the results:

The detector displays observed ports, scan classifications, and security alerts in real time.

Press Ctrl + C to stop monitoring and display the final summary.

Security alerts and session summaries are saved in scan_alerts.log

Test Results

Complete testing procedures, screenshots, and recorded results ae available in TEST_RESULTS.md

Source Code Attribution

This project was adapted and extended from https://github.com/alexamanpreet/port_scan_detector

The implementation was updated to use Python3 and Scapy for real-time packet monitoring, activity classification, security alerts, and logging
