# Threat Event: Accidental Exposure of Assets to the Internet

<img width="1540" height="1028" alt="HP_SOC_III_bordered" src="https://github.com/user-attachments/assets/b451da10-f342-4ce9-8b44-ef6f21622686" />

## Introduction

[REPLACE THIS WITH YOUR TEXT] In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

---
## Building a SOC + Honeypot in Azure (Live Traffic)

In order to create a honeypot in Azure, you will need to create an Azure subscription. After creating the Azure subscription, you’ll need to create a resource group. You can think of a resource group as a folder for cloud resources (e.g., virtual machine, virtual network, etc). Next, you will need to create a virtual network inside the resource group. To make this a little more tangible, you can think of a virtual network as your home router that allows you to connect to Wi-Fi (this is similar except in the cloud). When setting this up, make sure to add it to the same region as the resource group you created. 

Next, the virtual machine will need to be created and attached to the virtual network. Then you’ll need to log in to the virtual machine and turn off the firewall. This will really make it enticing to attackers on the internet. Then, you’ll need to create a network security group. The network security group can be thought of as a cloud firewall. In our case, this will eventually be opened up completely. At the end, the architecture will consist of a virtual network with a virtual machine that’s wide open to the internet.

At this point, you’ll have an empty Azure tenant with a subscription inside, a resource group, and a virtual network with a subnet inside of that virtual network. Next, you will need to create the virtual machine. The virtual machine is the honeypot which will be exposed to the internet that people will attack. When creating the virtual machine, choose the resource group and virtual network you created. Once you’re done, if you go to your resource group, you should see your virtual machine, the public IP address that was created along with your virtual machine, the network security group (i.e., the cloud firewall for this virtual machine), the network interface (think of this like a virtual ethernet port for the virtual machine), and a disk. 

Next, you will need to open the network security group up to the internet so anyone can access it with any type of traffic. This typically should not be done but we’re doing it here so our honeypot is discovered as soon as possible. 

So, there’s a firewall (network security group) between the virtual machine and the internet and there are inbound rules and outbound rules. The inbound rules control what traffic can enter the virtual network from the public network. By default, Remote Desktop Protocol (RDP) is enabled over the internet from any source. That means anyone from anywhere around the world can attempt to log into the virtual machine from remote desktop. However, if you send any other type of traffic, there are no rules that will allow it, so it will get blocked. Therefore, by default, there’s only remote desktop protocol allowed inbound.

You can delete the default RDP rule and create another inbound security rule that allows everything inbound, not just remote desktop. Next, log in to the virtual machine and disable the internal Windows Firewall for the virtual machine.

Just as a recap, we have our azure tenant, we have our subscription, we have our resource group with everything inside of it. We have a virtual network and we have a subnet. The connected to the subnet, we have a virtual machine. The virtual machine’s network security group, or cloud firewall, is completely opened up to the public internet. The firewall inside the virtual machine is completely opened up to the public internet.

---
## Table:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceLogonEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table|
| **Purpose**| Used to detect failed and successful logons by threat actors. |

---

## Related Queries:
```kql
// Installer name == tor-browser-windows-x86_64-portable-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// TOR Browser being silently installed
// Take note of two spaces before the /S (I don't know why)
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// TOR Browser or service was successfully installed and is present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// TOR Browser or service was launched
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// TOR Browser or service is being used and is actively creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// User shopping list was created and, changed, or deleted
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Irene Ojini
- **Author Contact**: https://www.linkedin.com/in/iojini/
- **Date**: October 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `October 2025`  | `Irene Ojini`   
