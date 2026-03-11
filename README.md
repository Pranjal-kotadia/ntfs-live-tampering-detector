# NTFS Tampering Detection & Live Monitoring System

## Overview

This project is a Windows NTFS forensic detection system designed to identify file timestamp tampering, suspicious file activity, and cross-system file origins using NTFS artifacts. It combines two major approaches: live monitoring and dead forensics analysis.

Live monitoring detects suspicious file activity in real time using the NTFS USN Journal, while dead forensics performs post-incident investigation using exported NTFS artifacts such as $MFT, $UsnJrnl, and $LogFile. The overall goal is to detect attacker techniques like timestomping, drop-and-stomp malware delivery, and suspicious file origin changes by correlating multiple NTFS metadata sources.

---

## Real-Time NTFS Monitoring

The live monitor watches the USN Journal and detects suspicious patterns such as metadata-only changes that may indicate timestomping, drop-and-stomp behavior, suspicious rename patterns, file deletion activity, and unusual file copy patterns. When suspicious activity is detected, the system verifies it by comparing NTFS metadata structures.

---

## Dead Forensics Detection

The offline detector analyzes exported NTFS artifacts to detect historical tampering. It works with three primary artifacts: $MFT, $UsnJrnl, and $LogFile. Detection techniques include $SI vs $FN timestamp comparison, Log Sequence Number (LSN) recency analysis, USN event sequence correlation, and metadata inconsistency detection. This allows the system to identify tampering even when it was not caught in real time.

---

## Cross-System Office File Detection

The system also analyzes Microsoft Office files (.docx, .xlsx, .pptx) to detect files that were likely copied from another system. It compares NTFS timestamps, internal Office metadata, author information, and internal creation and modification timestamps. This is particularly useful for identifying suspicious documents introduced from external sources.

---

## Project Architecture

```
               +----------------------+
               |   NTFS File System   |
               +----------+-----------+
                          |
                          v
                +-------------------+
                |   USN Journal     |
                |  (Live Changes)   |
                +---------+---------+
                          |
                          v
                +-------------------+
                |   Live Monitor    |
                | Real-time Alerts  |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Artifact Export   |
                |  MFT / USN / Log  |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Dead Forensics    |
                | detector.py       |
                +-------------------+
```

---

## Detection Logic

### Timestamp Tampering Detection

Timestamp tampering detection works by comparing two NTFS timestamp sets. The $SI attribute (Standard Information) is modifiable by users, while the $FN attribute (File Name) is kernel-controlled. If these timestamps differ significantly, it indicates possible timestamp manipulation.

| Attribute | Description |
|-----------|-------------|
| $SI | Standard Information (modifiable by user) |
| $FN | File Name attribute (kernel controlled) |

### LSN Recency Analysis

LSN recency analysis examines the Log Sequence Number embedded in each MFT record. If a file claims to be old but its LSN reflects recent activity, that suggests recent metadata manipulation.

### USN Journal Correlation

USN Journal correlation tracks file events such as creation, data modification, metadata changes, and deletion. Suspicious sequences of these events can reveal attack patterns like drop-and-stomp malware deployment.

---

## Installation

Requirements: Windows 10 or Windows 11, Python 3.8 or later, and administrator privileges for NTFS artifact extraction.

To install dependencies, run:

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Run Live Monitor

```bash
python live_monitor.py
```

This starts real-time monitoring of the NTFS USN Journal.

### 2. Run Dead Forensics Analysis

First export the NTFS artifacts, then run:

```bash
python detector.py --mft mft.bin --usn usn.bin --logfile logfile.bin
```

To also scan Office files, add the scan directory option:

```bash
python detector.py --mft mft.bin --usn usn.bin --logfile logfile.bin --scan-dir C:\Users
```

Results are saved to `results.json`.

---

## Testing the System

The following PowerShell commands can be used to test the system:

```powershell
# Create a file
New-Item test.txt -ItemType File

# Modify the file
Add-Content test.txt "hello"

# Rename the file
Rename-Item test.txt renamed.txt

# Delete the file
Remove-Item renamed.txt

# Simulate timestamp manipulation
(Get-Item test.txt).LastWriteTime = "01 January 2019 10:00AM"
```

---

## Output Example

```
[CRITICAL] 92%  C:\Temp\backdoor.exe
Timestamp inconsistency detected
MFT record indicates recent modification
Possible timestomping attack
```

---

## Limitations

The USN Journal may be truncated on heavily used systems. $LogFile entries can be overwritten over time. Some legitimate software may produce metadata changes that resemble suspicious patterns.

---

## Future Improvements

Planned improvements include integration with SIEM tools, machine learning based anomaly detection, automated forensic timeline reconstruction, and visualization of NTFS activity.

---

## Educational Purpose

This project was created as part of a cybersecurity research and detection initiative focusing on digital forensics, NTFS internals, file system artifact analysis, and attack detection techniques.

---

## Author

Cybersecurity Project – NTFS Tampering Detection System
