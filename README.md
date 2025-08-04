# Cloud-Based Home SOC Lab with Microsoft Sentinel

<p align="center">
<img src="/images/hero.png" alt="hero" width=900/>
</p>

## Technology Utilized

* Microsoft Azure Virtual Machine (Windows 10)
    
* Microsoft Defender
    
* Microsoft Sentinel

* Remote Desktop Protocol (RDP)
     
* KQL (Kusto Query Language)

* MITRE ATT&CK Framework

* Network Security Group (NSG)

<hr>

## Purpose

The purpose of this lab is to create a vulnerable honeypot in Microsoft Azure to demonstrate attacker activity and create a visual representation of their location on a map.

<p align="center">
<img src="/images/lab_architecture.png" alt="lab architecture" width=900/>
</p>

## Procedure

I will create a Windows 10 virtual machine and intentionally leave it vulnerable by disabling the firewall and creating a NSG (Network Security Group) rule that allows ANY connection type to the virtual machine and giving it priority over other rules. This will leave the machine vulnerable to attacks from around the world. I will then ping the VM from my ownpersonal device to ensure connectivity because, if I can reach the VM from my person device, then others can as well.

Next, I will intentionally attempt to login to the VM using Remote Desktop Protocol (RDP) in order to generate security logs to view for testing purposes. After verifying that the logs are present in the security logs, I will create a log analytics workspace within Azure to later link to Microsoft Sentinel. This will connect the VM to the log analytics workspace so that all logs from the VM can be sent from the VM to the log analytics workspace, then to Sentinel so that better analysis can be done such as KQL queries.

Then, I will download a created geo location list that associates different IP Addresses to their respective locations (City Name, Country Name). After downloading the geo location file, I will create a new watchlist item and upload the file so that it can later be used in KQL queries for data analysis.

<a href="https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/misc/geoip-summarized.csv">View The File Here</a>

Finally, I will leave the vulnerable device online for **24 HOURS** in order to give time for a good data set to produce good visual results for the heat map. Then, I will list the related MITRE ATT&CK tactics and a potential remediation plan. 

<hr>

## Step 1) Create a virtual machine

This step is the creation of a virtual machine in Azure that is running Windows 10.


<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>

<hr>

## Step 2) Remove RDP (Remote Desktop Protocol) Rule

This step is the removal of the default RDP rule that is created within the NSG (Network Security Group) upon virtual machine creation.


<p align="center">
<img src="/images/remove_rdp_rule.png" alt="remove rdp rule" width=600/>
</p>

<hr>

## Step 3) Create a New Global Rule

This step is creating a global rule that allows any type of connection to the virtual machine and giving it higher priority (lower number value) than the other rules.

<p align="center">
<img src="/images/create_global_rule.png" alt="create global rule" width=600/>
</p>

<hr>

## Step 4) Disable Windows Firewall

The windows firewall is disabled in this step to ensure communication betweeen devices and the virtual machine.

<p align="center">
<img src="/images/disable_firewall.png" alt="disable firewall" width=600/>
</p>

<hr>

## Step 5) Ping The Virtual Machine 

In this step, I ping the virtual machine from another device to test connectivity. If I can connect to the device, then potential attackers can as well, which is the goal.

<p align="center">
<img src="/images/ping_vm.png" alt="ping" width=600/>
</p>

<hr>

## Step 6) Attempt A Login

In this step, I intentionally attempt to login using incorrect credentials to generate security logs so that I can make sure there are no issues.

<p align="center">
<img src="/images/attempt.png" alt="login attempt" width=600/>
</p>


<p align="center">
<img src="/images/attempt2.png" alt="login attempt" width=600/>
</p>

<hr>

## Step 7) Check For Login Attempts

In this step, I check for the login attempts from the previous step by viewing the system's security logs. I can see the two attempts that I made earlier are present, which means everything is working fine thus far.

<p align="center">
<img src="/images/event_viewer.png" alt="event viewer" width=600/>
</p>

<hr>

## Step 8) Create a Log Analytics Workspace

In this step, I create a log analytics workspace in Azure to link Microsoft Sentinel, Microsoft Defender, and Windows Security Events

<p align="center">
<img src="/images/create_law.png" alt="create log analytics workspace" width=600/>
</p>

<hr>

## Step 9) Link Sentinel

In this step, I link Sentinel to the LAW (log analytics workspace) created from the previous step


<p align="center">
<img src="/images/link_sentinel.png" alt="link sentinel" width=600/>
</p>

<hr>

## Step 10) Create a Data Connection

In this step, I go to `Content hub` to install windows security events, add connector, and create a data connection rule so that logs from the virtual machine can be sent to Sentinel

<p align="center">
<img src="/images/install_windows_security_events.png" alt="windows security events" width=600/>
</p>


<p align="center">
<img src="/images/add_connector.png" alt="add connector" width=600/>
</p>


<p align="center">
<img src="/images/create_data_connection_rule.png" alt="create data connection rule" width=600/>
</p>

<hr>

## Step 11) Create a Watchlist

In this step, I create a new watchlist item using the geo location file that I previously downloaded


<p align="center">
<img src="/images/watchlist.png" alt="watchlist" width=600/>
</p>


<hr>

## Step 12) Run KQL Query

In this step, I run the following KQL query to generate all of the IP addresses of attackers on the VM and utilize the geo locations from the uploaded geo file:

```powershell
let geoWatchlist = _GetWatchlist('geoip');
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc 
| evaluate ipv4_lookup(geoWatchlist, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project AttackerIP = IpAddress, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), FailureCount;
```
<hr>

## Step 13) Create Workbook

In this step, I created a new workbook and added a new query, json, to the workbook to generate the heat maps. These heatmaps display the relative areas where attacks on the honeypot originated from.

`JSON`

```powershell
{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}
```

**AFTER 24 HOURS**

<p align="center">
<img src="/images/24hours.png" alt="after 24 hours" width=900/>
</p>


**AFTER 48 HOURS**

<p align="center">
<img src="/images/48hours.png" alt="after 48 hours" width=900/>
</p>

## Discussion


 
## MITRE ATT&CK Tactics Used

`Test`

## Mitigation Plan

* Enable Windows Defender Firewall

* Remove RDP Rule (use Bastion connnection instead)

* Increase lockout duration policy from 60 seconds to 900 seconds to mitigate brute force attempts
