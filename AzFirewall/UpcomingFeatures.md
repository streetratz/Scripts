# Upcoming Features
* Support for Azure Firewall Policy
* Dump to Report
* _Show nearest Network Rules_

# Notes:

Handling the Azure Firewall Policy Object

* $d : Is the Firewall Policy Object.
* $x : Is the Firewall Policy Rule Collecection
  * _We will need this to be a **FOREACH**_
* $m : Is the Firewall Policy Rule Collection as a PS Object.

```
$d = get-azfirewallPolicy -ResourceGroupName 'NAB-Test' -Name 'FirewallPolicy_NAB-Firewall'
$x = Get-AzFirewallPolicyRuleCollectionGroup -Name DefaultDnatRuleCollectionGroup -AzureFirewallPolicy $d
$m = ($x | ConvertTo-Json -depth 10) | ConvertFrom-Json
$m
```