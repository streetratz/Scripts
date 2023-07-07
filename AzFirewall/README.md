# Powershell Help
Tests which Network [OR] Application Rules match a provided set.

Script: Check-AzFirewallRules.ps1
Version: 1.0
Author: Johnfern

# Examples
## Network Collection:
### From File:
````
> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Network -SourceAddress '10.35.6.42' -DestinationAddress '207.25.253.47' -Object .\testAzFwJSON.json
````
### From Get-AzFirewallObject:
````
> $AzfwObj = Get-AzFirewall -Name 'Play-FW-1' -ResourceGroupName 'AzFw-Playground-1'
> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Network -SourceAddress '10.35.6.42' -DestinationAddress '207.25.253.47' -Object $AzfwObj
````

# Application Collection: 
### From File:
````
> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Application -DestinationUrl 'johnfern.blob.core.windows.net' -Object .\testAzFwJSON.json
````
### From Get-AzFirewallObject:
````
> $AzfwObj = Get-AzFirewall -Name 'Play-FW-1' -ResourceGroupName 'AzFw-Playground-1'
> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Application -DestinationUrl 'johnfern.blob.core.windows.net' -Object $AzfwObj
````
PS> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
PS> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Network -SourceAddress 10.10.10.5 -DestinationAddress 131.107.255.255 -Object .\testAzFwJSON.json

## Example Outputs
### From Firewall Object:
> PS> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
> PS> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Network -SourceAddress 10.10.10.5 -DestinationAddress 131.107.255.255 -Object $Azfw
```
############################################################
Check-AzFirewallRules : Testing which rules match inputed paramets.

Matched Application Collections: 1
Collection Name: ALLOW-To-MSFTNCSI
Priority: 900
Action: Allow

Name                        Description Protocol Source Addresses Destination Addresses Destination Ports
----                        ----------- -------- ---------------- --------------------- -----------------
OUT-MSFTNCSI-050                          Any    10.0.0.0/8       131.107.255.255/32    *
OUT-MSFTNCSI-055                          Any    10.0.0.0/8       131.107.0.0/16        *

############################################################
```
### From File:
> PS> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Application -DestinationUrl 'mystorage.blob.core.windows.net' -Object .\testAzFwJSON.json
```
############################################################
Check-AzFirewallRules : Testing which rules match inputed paramets.

Matched Application Collections: 1
Collection Name: ALLOW-STORAGE-TRAFFIC
Priority: 10000
Action: Allow

Name          Description Protocol Port Source Addresses                                     Target FQDNs
----          ----------- -------- ---- ----------------                                     ------------
Storage-Https              Https   443  {10.1.1.0/24, 10.1.2.0/24, 10.1.3.0/24, 10.1.4.0/24…} *.blob.core.windows.net

############################################################
```

