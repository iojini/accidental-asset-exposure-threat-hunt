# Threat Hunt Report: Accidental Exposure of Assets to the Internet

<img width="1540" height="1028" alt="TH2_1E_bordered" src="https://github.com/user-attachments/assets/c8935c1f-3220-46d7-a94d-d4a966444260" />

##  Scenario

During routine maintenance, the security team is tasked with investigating any VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that have mistakenly been exposed to the public internet. During the time the devices were unknowingly exposed to the internet, it’s possible that someone could have brute-force logged into some of the devices since the older devices do not have account lockout configured for excessive failed login attempts. The goal is to identify any misconfigured VMs and check for potential brute-force login attempts/successes from external sources.

- [Scenario Creation](https://github.com/iojini/accidental-asset-exposure-threat-hunt/blob/main/honeypot-implementation-and-map-appendix.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` table to check the IP addresses with the most failed logons

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-10-04T19:49:26.090506Z`. These events began at `2025-10-04T19:16:45.455884Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "irene-test-vm-m"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-04T19:16:45.455884Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="2846" height="1271" alt="TOR1" src="https://github.com/user-attachments/assets/a3653f41-84cf-4409-896f-77f46f9e5b66" />

---

### 2. Searched the `DeviceLogonEvents` table to determine if the most active threat actors were able to successfully logon

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.7.exe". Based on the logs returned, at `2025-10-04T19:16:45.455884Z`, an employee on the "irene-test-vm-m" device ran the file `tor-browser-windows-x86_64-portable-14.5.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "irene-test-vm-m"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="3117" height="398" alt="TOR2" src="https://github.com/user-attachments/assets/94bcf1aa-dc1f-4ccc-89b7-57035c52d433" />

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
