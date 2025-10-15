# Threat Event: Accidental Exposure of Assets to the Internet

<img width="1348" height="772" alt="NSG_III_bordered" src="https://github.com/user-attachments/assets/41c222b2-8520-41cf-a7d3-8f3d6740a4d2" />

## Introduction

For this threat hunt, a honeypot was built in Azure by creating a virtual machine and completely opening up the virtual machine’s network security group to the internet. The virtual machine's internal firewall was also disabled.

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
## Appendix: Map Visualization

While the honeypot was created to focus on a specific scenario, the maps included here were generated at the tenant level in a different lab. These maps are visualizations that should give you an idea of the different things that are happening in your environment from a geographic standpoint. You can create maps for anything; it just depends on what’s important to your organization and what you want to see. They also serve as examples of similar detection methods that could apply to the honeypot scenario. In summary, these maps cover different aspects of the tenant's security, such as authentication attempts at the tenant and VM level, resource creation, and malicious flows.

### Entra ID (Azure) Authentication Success

```kql
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]),  Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```
<img width="2571" height="1264" alt="Entra ID (Azure) Authentication Success" src="https://github.com/user-attachments/assets/355e71bf-fd64-4e77-82bd-a0206897dc92" />

[Entra ID Authentication Success Map Visualization JSON Script](https://github.com/iojini/azure-honeypot-soc-threat-hunt/blob/main/scripts/directory-login-successes.json)  

---

### Entra ID (Azure) Authentication Failures

```kql
SigninLogs
| where ResultType != 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]),  Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```

<img width="2340" height="1227" alt="Entra ID (Azure) Authentication Failures II" src="https://github.com/user-attachments/assets/eeaf4a89-b4cb-4ebf-b1e0-7a96b1095ac1" />

[Entra ID Authentication Failure Map Visualization JSON Script](https://github.com/iojini/azure-honeypot-soc-threat-hunt/blob/main/scripts/directory-login-failures.json)  

---

### Azure Resource Creation

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3})\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller,
    CallerPrefix = split(Caller, "@")[0],  // Splits Caller UPN and takes the part before @
    CallerIpAddress,
    ResouceCreationCount,
    Country = countryname,
    Latitude = latitude,
    Longitude = longitude,
    friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```

<img width="2265" height="1248" alt="Azure Resource Creation" src="https://github.com/user-attachments/assets/330091d6-835a-429f-8568-670ef5c369f6" />

[Azure Resource Creation Map Visualization JSON Script](https://github.com/iojini/azure-honeypot-soc-threat-hunt/blob/main/scripts/azure-resource-creation.json)  

---

### VM Authentication Failures

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;
```

<img width="2326" height="1242" alt="VM Authentication Failures" src="https://github.com/user-attachments/assets/04e4506d-70f3-4c3f-872b-12adcbd65090" />

[VM Authentication Failure Map Visualization JSON Script](https://github.com/iojini/azure-honeypot-soc-threat-hunt/blob/main/scripts/vm-authentication-failures.json)  

---

### Malicious Traffic Entering the Network

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow"
//| where SrcIP_s == "10.0.0.5"
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")
```

<img width="2333" height="1244" alt="Malicious Traffic Entering the Network" src="https://github.com/user-attachments/assets/5547c750-d50c-4d55-b320-8cf4b3fb1786" />

[Malicious Traffic Map Visualization JSON Script](https://github.com/iojini/azure-honeypot-soc-threat-hunt/blob/main/scripts/allowed-inbound-malicious-flows.json)  

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
