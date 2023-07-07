[[_TOC_]]

# Network Collection:
From File:
> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Network -SourceAddress '10.35.6.42' -DestinationAddress '207.25.253.47' -Object .\testAzFwJSON.json

From Get-AzFirewallObject:
> $AzfwObj = Get-AzFirewall -Name 'Play-FW-1' -ResourceGroupName 'AzFw-Playground-1'
> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Network -SourceAddress '10.35.6.42' -DestinationAddress '207.25.253.47' -Object $AzfwObj


# Application Collection: 
From File:
> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Application -DestinationUrl 'johnfern.blob.core.windows.net' -Object .\testAzFwJSON.json

From Get-AzFirewallObject:
> $AzfwObj = Get-AzFirewall -Name 'Play-FW-1' -ResourceGroupName 'AzFw-Playground-1'
> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Application -DestinationUrl 'johnfern.blob.core.windows.net' -Object $AzfwObj

.\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Application -DestinationUrl 'johnfern.blob.core.windows.net' -Object .\testAzFwJSON.json
