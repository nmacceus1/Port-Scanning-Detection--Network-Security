# Port Scanning Detection — Test Results

This document contains the testing procedures, screenshots, and results from evaluating the Port Scanning Detection System on an Ubuntu virtual machine.

## Test 1 — Normal Activity

**Command:** `sudo nmap -sS -p 80,443,8080 127.0.0.1`

**Results:**
- Packets Analyzed: 6
- Total Port Records: 3
- Normal Port Records: 3
- Warning Port Records: 0
- Suspicious Port Records: 0
- Total Security Alerts: 0

**Outcome:** PASSED

<img width="818" height="200" alt="normal2" src="https://github.com/user-attachments/assets/fee358e0-acd9-409d-bcdc-01629f901a16" />
<img width="753" height="677" alt="normal" src="https://github.com/user-attachments/assets/40350d91-2917-4cd4-8256-4e65acfefeb1" />


## Test 2 — Warning Activity

**Command:** `sudo nmap -sS -p 20-26 127.0.0.1`

**Results:** 
- Packets Analyzed: 14
- Total Port Records: 7
- Normal Port Records: 0
- Warning Port Records: 7
- Suspicious Port Records: 0
- Total Security Alerts:0

**Outcome:** PASSED

<img width="720" height="269" alt="warning" src="https://github.com/user-attachments/assets/a3310e01-8dfc-4970-94bf-522d43f8b4ef" />

<img width="849" height="591" alt="warning2" src="https://github.com/user-attachments/assets/60893e79-e456-4bcd-9a75-9ca8c00d840f" />



## Test 3 — Suspicious TCP SYN Scan

**Command:** `sudo nmap -sS -p 1-100 127.0.0.1`

**Results:**
- Packets Analyzed: 83
- Total Port Records: 42
- Normal Port Records:0
- Warning Port Records: 0
- Suspicious Port Records:42
- Total Security Alerts: 1

**Outcome:** PASSED

<img width="787" height="201" alt="suspicious" src="https://github.com/user-attachments/assets/a2e991b6-db9f-407e-bf59-66a01e7783d0" />

<img width="603" height="781" alt="suspiciousdetection" src="https://github.com/user-attachments/assets/879c56ae-c4e1-4b6b-9648-a2a73850bceb" />

<img width="448" height="726" alt="suspiciousreport" src="https://github.com/user-attachments/assets/3c9236e1-ce12-4923-af2b-046af4855fb6" />



## Test 4 — TCP FIN Scan

**Command:** `sudo nmap -sF -p 1-30 127.0.0.1`

**Results:** 
- Packets Analyzed: 64
- Total Port Records: 30
- Normal Port Records: 0 
- Warning Port Records: 0
- Suspicious Port Records: 30
- Total Security Alerts: 1

**Outcome:** PASSED

<img width="680" height="232" alt="fin" src="https://github.com/user-attachments/assets/5ff0a99a-1257-43b7-b8e9-70081bedb9c4" />
<img width="545" height="724" alt="findetection" src="https://github.com/user-attachments/assets/9fcb3b9b-baf1-4699-a2d0-973233c574ed" />

<img width="545" height="724" alt="fin" src="https://github.com/user-attachments/assets/a48ef122-4690-4c36-baec-994d1f2537ee" />


## Test 5 — TCP XMAS Scan

**Command:** `sudo nmap -sX -p 1-30 127.0.0.1`

**Results:** 
- Packets Analyzed: 64
- Total Port Records:30
- Normal Port Records: 0
- Warning Port Records: 0
- Suspicious Port Records: 30
- Total Security Alerts: 1

**Outcome:** PASSED

<img width="582" height="732" alt="xmasdetection" src="https://github.com/user-attachments/assets/b7b676f1-c763-4d57-baa6-382c3e16e7b0" />
<img width="721" height="182" alt="xmas" src="https://github.com/user-attachments/assets/9b969012-b986-49ea-bad9-a688a163b5d5" />
<img width="519" height="648" alt="xmasreport" src="https://github.com/user-attachments/assets/cf355bac-d667-421f-8d51-68605949d09a" />


## Test 6 — TCP NULL Scan

**Command:** `sudo nmap -sN -p 1-30 127.0.0.1`

**Results:** 
- Packets Analyzed: 64
- Total Port Records: 30
- Normal Port Records: 0
- Warning Port Records: 0
- Suspicious Port Records: 30
- Total Security Alerts: 1

**Outcome:** PASSED
  
<img width="713" height="183" alt="null" src="https://github.com/user-attachments/assets/f4ee08dd-0c16-4d28-8334-c77fa5bfee11" />
<img width="533" height="725" alt="nulldetection" src="https://github.com/user-attachments/assets/ab0e02ff-3def-4092-8407-5eaebd988729" />
<img width="555" height="658" alt="nullreport" src="https://github.com/user-attachments/assets/eb0fc626-e934-4a3e-bb00-81795ed93e9d" />


## Test 7 — UDP Scan

**Command:** `sudo nmap -sU -p 50-65 127.0.0.1`

**Results:**
- Packets Analyzed: 32
- Total Port Records: 16
- Normal Port Records: 0
- Warning Port Records: 0
- Suspicious Port Records: 16
- Total Security Alerts: 1

  
<img width="786" height="434" alt="udp" src="https://github.com/user-attachments/assets/073e5fe8-b5df-4b00-bee8-b89ca0caa5b5" />
<img width="613" height="670" alt="udpdetection" src="https://github.com/user-attachments/assets/da268764-5eba-451c-8043-44dae55f2682" />
<img width="1213" height="440" alt="udpreport" src="https://github.com/user-attachments/assets/dd73e3ad-87d7-4d75-bad4-89de33c13a59" />


## Test 8 — Alert Logging

**Command:** `cat scan_alerts.log`

**Outcome:** PASSED

<img width="717" height="789" alt="scan_alert" src="https://github.com/user-attachments/assets/0c330dac-f9bb-4a0f-a728-aa5b0ea1f672" />


## Test 9 — Alert Cooldown

**Command:** `sudo nmap -sS -p 1-100 127.0.0.1` (run twice within 30 seconds)

**Outcome:** PASSED

<img width="775" height="370" alt="cooldown" src="https://github.com/user-attachments/assets/5d0e52f0-de06-481d-a3bc-cf15d6c36aa2" />
<img width="402" height="793" alt="cooldowndetection" src="https://github.com/user-attachments/assets/57dccee5-89b9-405d-a2f4-956604279af0" />
<img width="894" height="336" alt="cooldowndetection2" src="https://github.com/user-attachments/assets/fa411840-59bd-457a-afa5-72dbfe66e33b" />
<img width="716" height="781" alt="cooldownreport" src="https://github.com/user-attachments/assets/ae3168ac-3101-412c-8f8c-f010fa705e67" />
<img width="432" height="289" alt="cooldownreport2" src="https://github.com/user-attachments/assets/8809215a-4732-48b4-a248-1910c5186eaf" />
