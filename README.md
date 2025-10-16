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

### 3. Searched the `DeviceLogonEvents` Table for successful logons from suspicious IP addresses

Searched for any indication of successful logons from the IP addresses with the most failed login attempts. Based on the logs returned, no successful logons were identified from these IP addresses.

**Query used to locate events:**

```kql
let RemoteIPsInQuestion = dynamic(["185.39.19.56","45.227.254.130", "185.243.96.107", "182.160.114.213", "188.253.1.20"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
---

### 4. Searched the `DeviceLogonEvents` Table for successful network logons

The only successful remote network logons in the last 30 days was for the labuser account (53 total).

**Query used to locate events:**

```kql
//Successful logons
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"

//Number of successful logons by account owner
DeviceLogonEvents
| where DeviceName == "irene-test-vm-m"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```
---

### 5. Searched the `DeviceInfo` table to identify internet-facing instances of the device

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

### 6. Searched the `DeviceInfo` table to identify internet-facing instances of the device

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

### 7. Searched the `DeviceInfo` table to identify internet-facing instances of the device

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

## Summary

The user "labuser" on the "irene-test-vm-m" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `irene-test-vm-m` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
