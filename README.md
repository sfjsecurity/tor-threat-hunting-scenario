# Threat Hunting Scenario-based Project

<img width="400" height="400" alt="image" src="https://github.com/user-attachments/assets/8f02e736-84d4-44f1-b405-4389a5220d85" alt="Tor Logo Threat Hunting Project" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/sfjsecurity/tor-threat-hunting-scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

---

## Scenario

Following an internal review, management raised concerns that certain employees might be leveraging TOR browsers to circumvent existing network security controls. This suspicion was prompted by anomalous encrypted traffic patterns observed in network logs, along with detected connections to known TOR entry nodes. There were also internal tips suggesting employees had been discussing methods to reach restricted websites during business hours. The objective of this hunt was to identify any TOR-related activity and investigate associated security events. Management was to be notified upon confirmation of any findings.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any file activity related to `tor.exe` or `firefox.exe`.
- **Check `DeviceProcessEvents`** for evidence of TOR installation or execution.
- **Check `DeviceNetworkEvents`** for outbound connections over ports commonly associated with TOR.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Queried for any filenames containing the string "tor" on the `vm-thunt-sj` device under the account `labusersj`. Results revealed that the user had downloaded a TOR installer, which led to numerous TOR-related files appearing on the desktop. A file named `tor-shopping-list.txt` was also observed being created on the desktop at `2026-03-15T14:24:52.1115663Z`. The earliest related event was recorded at `2026-03-15T13:53:51.8730436Z`.

**Query used to locate events:**
```kql
DeviceFileEvents
| where DeviceName == "vm-thunt-sj"
| where InitiatingProcessAccountName == "labusersj"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1197" height="629" alt="Image" src="https://github.com/user-attachments/assets/d05ebd1c-7ba9-4964-97ba-921faff93b3e" />
---

### 2. Searched the `DeviceProcessEvents` Table

Filtered process events by the TOR installer filename to identify execution activity. At `2026-03-15T14:14:45.7704252Z`, `labusersj` was found to have launched `tor-browser-windows-x86_64-portable-15.0.7.exe` directly from the Downloads folder. The command used included a silent install flag, meaning the installation ran in the background without any visible prompts.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-thunt-sj"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1219" height="175" alt="Image" src="https://github.com/user-attachments/assets/95e2e283-2c1b-486e-9c5b-7e6940d861b0" />
---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Looked for process activity tied to TOR browser executables to determine whether the browser was actually launched. Logs confirmed that `labusersj` opened the TOR browser at `[TIMESTAMP]`, with multiple child processes including `firefox.exe` and `tor.exe` being created shortly after, consistent with a successful browser launch.

**Query used to locate events:**
```kql
DeviceProcessEvents
| where DeviceName == "vm-thunt-sj"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Investigated whether the TOR browser was used to make outbound connections over known TOR ports. At `[TIMESTAMP]`, `labusersj` on `vm-thunt-sj` successfully connected to `[REMOTE IP]` over port `9001` via `tor.exe`, located at `C:\Users\labusersj\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. Several additional outbound connections were also observed over port `443`.

**Query used to locate events:**
```kql
DeviceNetworkEvents
| where DeviceName == "vm-thunt-sj"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

---

## Chronological Event Timeline

### 1. File Download - TOR Installer
- **Timestamp:** `[TIMESTAMP]`
- **Event:** `labusersj` downloaded `tor-browser-windows-x86_64-portable-15.0.7.exe` into the Downloads folder on `vm-thunt-sj`.
- **Action:** File download detected.
- **File Path:** `C:\Users\labusersj\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - Silent TOR Installation
- **Timestamp:** `[TIMESTAMP]`
- **Event:** `labusersj` ran the TOR installer with a silent flag, causing it to install in the background with no user-facing prompts.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\labusersj\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - TOR Browser Launched
- **Timestamp:** `[TIMESTAMP]`
- **Event:** `labusersj` launched the TOR browser. Associated processes `firefox.exe` and `tor.exe` were spawned, confirming a successful launch.
- **Action:** TOR-related process creation detected.
- **File Path:** `C:\Users\labusersj\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Entry Node
- **Timestamp:** `[TIMESTAMP]`
- **Event:** `tor.exe` established an outbound connection to `[REMOTE IP]` on port `9001`, confirming the device was actively communicating over the TOR network.
- **Action:** Successful connection detected.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\labusersj\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - Continued TOR Activity
- **Timestamps:**
  - `[TIMESTAMP]` - Outbound connection to `[REMOTE IP]` on port `443`.
  - `[TIMESTAMP]` - Local loopback connection to `127.0.0.1` on port `9150`.
- **Event:** Further network connections were observed, consistent with continued TOR browsing activity by `labusersj`.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List
- **Timestamp:** `[TIMESTAMP]`
- **Event:** `labusersj` created `tor-shopping-list.txt` on the desktop, suggesting the user may have been documenting intended purchases or activity through TOR.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labusersj\Desktop\tor-shopping-list.txt`

### 7. File Deletion - Shopping List Removed
- **Timestamp:** `[TIMESTAMP]`
- **Event:** `labusersj` deleted `tor-shopping-list.txt` from the desktop shortly after its creation, indicating a deliberate attempt to remove evidence of the activity.
- **Action:** File deletion detected.
- **File Path:** `C:\Users\labusersj\Desktop\tor-shopping-list.txt`

---

## Summary

During this threat hunt, it was determined that `labusersj` on workstation `vm-thunt-sj` deliberately downloaded, silently installed, and launched the TOR browser. The user went on to establish multiple connections through the TOR network, browsed via the anonymized connection, and created a file titled `tor-shopping-list.txt` on their desktop. That file was deleted shortly after, pointing to an effort to remove traces of the activity. The full chain of events from download to network use to file cleanup, strongly suggests intentional and unauthorized use of TOR on a corporate endpoint.

---

## Response Taken

TOR usage was confirmed on endpoint `vm-thunt-sj` by the user `labusersj`. The device was isolated from the network and the user's direct manager was notified of the findings.

---
