# Microsoft Azure Honeypot Attacker Heatmap Lab

<p align="center">
<img src="/images/hero.png" alt="hero" width=900/>
</p>

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

Finally, I will leave the vulnerable device online for **24 HOURS** in order to give time for a good data set to produce good visual results for the heat map. 

<hr>

`Step 1`

Create a virtual machine

<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>

<hr>

`Step 2`

Remove default Remote Desktop Rule from NSG (Network Security Group)


<p align="center">
<img src="/images/remove_rdp_rule.png" alt="remove rdp rule" width=600/>
</p>

<hr>

`Step 3`

Create new global rule that allows any type of connection the virtual machine

<p align="center">
<img src="/images/create_global_rule.png" alt="create global rule" width=600/>
</p>

<hr>

`Step 4`

Disable windows firewall

<p align="center">
<img src="/images/disable_firewall.png" alt="disable firewall" width=600/>
</p>

<hr>

`Step 5` 

Ping the virtual machine from another device to test connectivity. If you can connect to the device, then potential attackers can as well.

<p align="center">
<img src="/images/ping_vm.png" alt="ping" width=600/>
</p>

<hr>

`Step 6`

Intentionally attempt to login using incorrect credentials to generate security logs

<p align="center">
<img src="/images/attempt.png" alt="login attempt" width=600/>
</p>


<p align="center">
<img src="/images/attempt2.png" alt="login attempt" width=600/>
</p>

<hr>

`Step 7`

Check for the login attempts from the previous step by viewing the system's security logs

<p align="center">
<img src="/images/event_viewer.png" alt="event viewer" width=600/>
</p>

<hr>

`Step 8`

Create a log analytics workspace in Azure to link Microsoft Sentinel and Windows Security Events

<p align="center">
<img src="/images/create_law.png" alt="create log analytics workspace" width=600/>
</p>

<hr>

`Step 9`

Link Sentinel to the LAW (log analytics workspace) created from the previous step


<p align="center">
<img src="/images/link_sentinel.png" alt="link sentinel" width=600/>
</p>

<hr>

`Step 10`

Go to `Content hub` to install windows security events, add connector, and create a data connection rule so that logs from the virtual machine can be sent to Sentinel

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

`Step 11`

Create new watchlist item using the geo location file


<p align="center">
<img src="/images/watchlist.png" alt="watchlist" width=600/>
</p>


<hr>

`Step 12`

Run the following KQL query to generate all of the IP addresses of attackers on the VM and utilize the geo locations from the uploaded geo file

```powershell
let geoWatchlist = _GetWatchlist('geoip');
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc 
| evaluate ipv4_lookup(geoWatchlist, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project AttackerIP = IpAddress, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), FailureCount;
```



<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>


<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>



<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>


<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>

<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>

<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>

<p align="center">
<img src="/images/create_machine.png" alt="create virtual machine" width=600/>
</p>







## Discussion

 

