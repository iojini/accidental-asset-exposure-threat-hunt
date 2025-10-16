# Threat Hunt Report: Accidental Exposure of Assets to the Internet

<img width="1540" height="1028" alt="TH2_1E_bordered" src="https://github.com/user-attachments/assets/c8935c1f-3220-46d7-a94d-d4a966444260" />

##  Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (e.g., VMs handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have brute-force logged into some of the devices since the older devices do not have account lockout configured for excessive failed login attempts. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

- [Scenario Creation](https://github.com/iojini/accidental-asset-exposure-threat-hunt/blob/main/honeypot-implementation-and-map-appendix.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

## Steps Taken

### 1. Searched the `DeviceInfo` table to identify internet-facing instances of the device

Searched the DeviceInfo table and discovered that the device ("irene-test-vm-m") was internet-facing for several days, with the most recent occurrence at 2025-10-16T17:36:02.4227451Z.

**Query used to locate events:**

```kql
DeviceInfo
| where DeviceName == "irene-test-vm-m"
| where IsInternetFacing == true
| order by Timestamp desc
```
<img width="3292" height="1436" alt="IF1" src="https://github.com/user-attachments/assets/c84a74ea-4f85-4f59-a6d0-99dd2217f316" />

---

### 2. Searched the `DeviceLogonEvents` table to identify remote IP addresses with failed logon attempts

Based on the logs returned, several threat actors have been discovered attempting to log in to the target machine. Multiple failed logon attempts were identified from various remote IPs, with the results grouped and ordered by the number of attempts from each IP address. For example, 185.39.19.56 failed to log in to the target machine 100 times and 45.227.254.130 failed to log in to the target machine 93 times.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="2809" height="1524" alt="IF2_2" src="https://github.com/user-attachments/assets/d93ecb1b-223b-4238-a141-de06a9a28ac1" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-10-04T19:20:39.986612Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "irene-test-vm-m"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
<img width="3154" height="1534" alt="TOR3" src="https://github.com/user-attachments/assets/805a97c7-b644-4400-9c5e-40916cf12531" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-10-04T19:21:06.6841946Z`, an employee on the "irene-test-vm-m" device successfully established a connection to the remote IP address `51.159.186.85` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "irene-test-vm-m"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<img width="3717" height="1465" alt="TOR4" src="https://github.com/user-attachments/assets/2ceeb167-9115-46c7-8b36-26e41da42f92" />

---

## Summary

The user "labuser" on the "irene-test-vm-m" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `irene-test-vm-m` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
