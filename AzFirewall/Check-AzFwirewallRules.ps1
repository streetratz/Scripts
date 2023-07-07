<#
.SYNOPSIS
Tests which Network [OR] Application Rules match a provided set.

.DESCRIPTION
Script: Check-AzFirewallRules.ps1
Version: 1.0
Author: Johnfern

.INPUTS
From JSON: 
> .\Check-AzFwirewallRules-V2.ps1 -FirewallJson ... -Object .\FirewallJSONFile.json

From Get-AzFirewall: 
> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
> .\Check-AzFwirewallRules-V2.ps1 -Firewall ... -Object $Azfw

.OUTPUTS
Collection Type: NETWORK

Matched Application Collections: 1
Collection Name: ALLOW-To-MSFTNCSI
Priority: 900
Action: Allow

Name                        Description Protocol Source Addresses Destination Addresses Destination Ports
----                        ----------- -------- ---------------- --------------------- -----------------
OUT-MSFTNCSI-050                          Any    10.0.0.0/8       131.107.255.255/32    *
OUT-MSFTNCSI-055                          Any    10.0.0.0/8       131.107.0.0/16        *

Collection Type: APPLICATION

Matched Application Collections: 1
Collection Name: ALLOW-STORAGE-TRAFFIC
Priority: 10000
Action: Allow

Name          Description Protocol Port Source Addresses                                     Target FQDNs
----          ----------- -------- ---- ----------------                                     ------------
Storage-Https              Https   443  {10.1.1.0/24, 10.1.2.0/24, 10.1.3.0/24, 10.1.4.0/24…} *.blob.core.windows.net

.EXAMPLE
From File: 
PS> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
PS> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Network -SourceAddress 10.10.10.5 -DestinationAddress 131.107.255.255 -Object .\testAzFwJSON.json

From Firewall Object:
PS> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Network -SourceAddress 10.10.10.5 -DestinationAddress 131.107.255.255 -Object $Azfw

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

.EXAMPLE
From File:
PS> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
PS> .\Check-AzFwirewallRules.ps1 -FirewallJson -CollectionType Application -DestinationUrl 'mystorage.blob.core.windows.net' -Object .\testAzFwJSON.json

From FirewallObject:
PS> $Azfw = Get-AzFirewall -Name 'AzFw-RG' -ResourceGroupName 'AzFw-Name'
PS> .\Check-AzFwirewallRules.ps1 -Firewall -CollectionType Application -DestinationUrl 'mystorage.blob.core.windows.net' -Object $Azfw
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
#>
[CmdletBinding(DefaultParameterSetName = 'Firewall')]
PARAM (
    [Parameter (Mandatory = $True)]
    [Parameter(ParameterSetName = 'Firewall')]
    [Parameter(ParameterSetName = 'FirewallPolicy')]
    [Parameter(ParameterSetName = 'FirewallJSON')]
    [ValidateSet("Network","Application")]
    [string]$CollectionType,
    [Parameter (Mandatory = $False, ParameterSetName = 'Network')]
    [string]$Protocol = 'Any',
    [Parameter (Mandatory = $False)]
    [string]$SourceAddress = 'Any',
    [Parameter (Mandatory = $False)]
    [string]$DestinationAddress = 'Any',
    [Parameter (Mandatory = $False)]
    [string]$DestinationPort = 'Any',
    [Parameter (Mandatory = $False)]
    [switch]$Firewall,
    [Parameter (Mandatory = $False)]
    [switch]$FirewallPolicy,
    [Parameter (Mandatory = $False, DontShow)]
    [switch]$FirewallJson,
    [Parameter (Mandatory = $False)]
    [Object]$Object,
    [Parameter (Mandatory = $False, ParameterSetName = 'Application')]
    [string]$DestinationUrl = 'Any'
)
# Set StrictMode
Set-StrictMode -Version latest

# Ensure Provided IP is a CIDR
function ensureIpCIDR {
    PARAM($IP)
    try {
        if (!$IP.Contains('/'))
        {
            $IP = "$($IP)/32"
        }
        # Write-Debug("IP: {0}" -f $IP)
        $IP
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
}

# Convert CIDR to NetMask
function convertCidrToSubnetMask {
    PARAM ($CIDR)
    try {
        $CIDR_Bits = ('1' * $CIDR).PadRight(32, '0')
        $Octets = $CIDR_Bits -split '(.{8})' -ne ''
        $Mask = ($Octets | ForEach-Object -Process {[Convert]::ToInt32($_, 2) }) -join '.'
        $Mask
        # Write-Debug ("CIDR: {0}, Mask: {1}" -f $CIDR, $Mask)
    }
    catch {
        Write-Debug ("ConvertCidrToSubnetMask - CIDR: {0}" -f $CIDR)
    }
}

# Get IP Range from CIDR
function getIpAddressRange {
    PARAM ($Range)
    try {
        $ip,$cidr=$Range.Split('/')
        $mask = convertCidrToSubnetMask -CIDR $cidr
        $IPBits = [int[]]$ip.Split('.')
        $MaskBits = [int[]]$Mask.Split('.')
        $NetworkIDBits = 0..3 | Foreach-Object { $IPBits[$_] -band $MaskBits[$_] }
        $BroadcastBits = 0..3 | Foreach-Object { $NetworkIDBits[$_] + ($MaskBits[$_] -bxor 255) }
        $NetworkID = $NetworkIDBits -join '.'
        $Broadcast = $BroadcastBits -join '.'
        $arr = @($NetworkID, $Broadcast)
        
        if($arr.Count -ne 2)
        {
            Write-Debug("Range:{0}" -f $Range)
            Write-Debug("A:{0}, B:{1}" -f $NetworkID, $Broadcast)
        }
        return $arr
    }
    catch {
        Write-Debug("GetIpAddressRange - Range: {0}" -f $Range)
    }
}    
   
# Convert IP to Binary
function convertIpToBinary {
    PARAM ($IpAddress)
    try {
        $bin = [system.net.ipaddress]::Parse($IpAddress).GetAddressBytes()
        [array]::Reverse($bin)
        $bin = [system.BitConverter]::ToUInt32($bin, 0)
        return $bin
    }
    catch {
        Write-Debug("ConvertIpToBinary - IpAddress: {0}" -f $IpAddress)
    }
}

# Check IP in Range
function isAddressInRange {
    PARAM ($CompareTo, $CompareWith)
    try {
        $rhs = ensureIpCIDR -IP $CompareTo
        $lhs = ensureIpCIDR -IP $CompareWith
    
        # Get IP Ranges of Test Cases
        $rhsArr = getIpAddressRange -Range $rhs
        $rhsNetworkID = $rhsArr[0]
        $rhsBroadcast = $rhsArr[1]
    
        $lhsArr = getIpAddressRange -Range $lhs
        $lhsNetworkId = $lhsArr[0]
        $lhsBroadcast = $lhsArr[1]
        # Write-Debug ("IP: From: {0}, To:{1}, CompareFrom:{2}, CompareTo:{3}" -f $rhsNetworkID,$rhsBroadcast,$lhsNetworkId,$lhsBroadcast)

        $rhsFrom = convertIpToBinary -IpAddress $rhsNetworkID
        $rhsTo = convertIpToBinary -IpAddress $rhsBroadcast
        $lhsFrom = convertIpToBinary -IpAddress $lhsNetworkId
        $lhsTo = convertIpToBinary -IpAddress $lhsBroadcast
        # Write-Debug ("Bin: From: {0}, To:{1}, CompareFrom:{2}, CompareTo:{3}" -f $rhsFrom,$rhsTo,$lhsFrom,$lhsTo)
    
        # Test if the LHS in within the RHS
        [bool]$testResults = if($lhsFrom -ge $rhsFrom -and $lhsTo -le $rhsTo){$true}else{$false}
        $testResults        
    }
    catch {
        Write-Debug ("CompareTo: {0}, CompareWith: {1}" -f $CompareTo, $CompareWith)
    }
}

# Expand Array of Ports: Changes 1,2,4-7,9 to 1,2,4,5,6,7,9
function buildArray {
    PARAM ($inputArray)
    try {
        $outputArray = @()
        foreach($prt in $dstPort)
        {
            if($prt -match '-')
            {
                $x = $prt.Split('-') | Sort-Object;
                $i = [int32]$x[0]
                $j = [Int32]$x[1]
                while($i -ne $j)
                {
                    $outputArray += $i
                    $i++
                }
            }
            else{
                $outputArray += [int32]$prt
            }
        }
        # Write-Debug ("Inside: $outputArray")
        return $outputArray    
    }
    catch {
        Write-Debug ("buildArray - InputArray: $inputArray")
    }

}

# Convert Wildcard, 0.0.0.0, 0.0.0.0/0 to Any
function checkWildcard
{
    PARAM ($x)
    switch -regex ($x) {
        '^[*]+$' { $x = 'Any'; }
        '^0.0.0.0$' { $x = 'Any'; }
        '^0.0.0.0/0$' { $x = 'Any'; }
        Default {
            #$x
        }
    }
    # Write-Debug("CheckWildcard: {0}" -f $x)
    return $x
}

#region Network Rules
# Main Network Rules Collection Function
function mainNetwork {
    PARAM($RuleSet)
    #$theSet = $RuleSet | ConvertFrom-Json
    $responseBag = @()
    foreach($s in $RuleSet)
    {
        if($Firewall)
        {
            $ruleCollection = @(matchNetworkRules -ruleBag $s.Rules)
            if($ruleCollection.Count -ge 1){
                $thisCollection = [PSCustomObject]@{
                        collectionName = $s.name
                        id = $s.id
                        priority = $s.priority
                        action = $s.action.type
                        rules = $ruleCollection
                    }
                $responseBag += $thisCollection
            }
        }
        elseif($FirewallJson) {
            foreach($p in $s.properties)
            {
                $ruleCollection = @(matchNetworkRules -ruleBag $p.rules)
            }
            if($ruleCollection.Count -ge 1){
                $thisCollection = [PSCustomObject]@{
                        collectionName = $s.name
                        id = $s.id
                        priority = $p.priority
                        action = $p.action.type
                        rules = $ruleCollection
                    }
                $responseBag += $thisCollection
            }
        }
    }

    if($responseBag.Count -ge 1)
    {
        Write-Host("Matched Collections: {0}`n" -f $responseBag.Count);
        # $matchedRules | Format-Table
        foreach($bag in $responseBag)
        {
            Write-Host ("Collection Name: {0}" -f $bag.collectionName)
            Write-Host ("Priority: {0}" -f $bag.priority)
            Write-Host ("Action: {0}" -f $bag.action)
            $bag.rules | Format-Table @{L='Name';E={$_.name}},@{L='Description';E={$_.description}},@{L='Protocol';E={$_.protocols};A='Center';W=100},@{L='Source Addresses';E={$_.sourceAddresses}},@{L='Destination Addresses';E={$_.destinationAddresses}},@{L='Destination Ports';E={$_.destinationPorts}} #-Wrap
        }
    }
    else {
        Write-Host("No Matched Rules")
    }
}

# Match Network Rules Function
function matchNetworkRules {
    PARAM($ruleBag)
    $matchedRules = @()
    #$ruleBag

    # Change for Wildcard
    $SourceAddress = checkWildcard($SourceAddress)
    $DestinationAddress = checkWildcard($DestinationAddress)
    $Protocol = checkWildcard($Protocol)
    $DestinationPort = checkWildcard($DestinationPort)

    #$firewallJson = Get-Content $RulesSet | ConvertFrom-Json
    foreach ($rule in $ruleBag)
    {
        $protocolTest = $False;
        $srcAddressTest = $False;
        $dstAddressTest = $False;
        $dstPortTest = $False;

        # Check: Does Provided SourceAddress match the SourceAddresses a the Rule?
        foreach($src in $rule.sourceAddresses)
        {
            #$src = $src.replace('*','Any')
            $src = checkWildcard($src)
            if($src -match 'Any' -or $SourceAddress -match 'Any')
            {
                $srcAddressTest = $True;
                break;
            }
            elseif (isAddressInRange -CompareTo $src -CompareWith $SourceAddress)
            {
                $srcAddressTest = $True;
                break;
            }
        }
        # Write-Debug("SRC - CompareTo: {0}, CompareWith: {1}" -f $src, $sourceAddress)

        # Check: Does Provided DestinationAddress match the DestinationAddresses a the Rule?
        foreach($dst in $rule.destinationAddresses)
        {
            #$dst = $dst.replace('*','Any')
            $dst = checkWildcard($dst)
            if ($dst -match 'Any' -or $DestinationAddress -match 'Any')
            {
                $dstAddressTest = $True;
                break;
            }
            elseif(isAddressInRange -CompareTo $dst -CompareWith $DestinationAddress)
            {
                $dstAddressTest = $True;
                break;
            }
        }
        # Write-Debug("DST - CompareTo: {0}, CompareWith: {1}" -f $dst, $destinationAddress)

        # Check: Does Provided Protocol match the Protocol in the Rule?
        foreach($prot in $rule.protocols)
        {
            #$prot = $prot.replace('*','Any')
            $prot = checkWildcard($prot)
            if ($prot -match 'Any' -or $Protocol -match 'Any')
            {
                $protocolTest = $True;
                break;
            }
            elseif($prot -match $Protocol)
                {
                    $protocolTest = $True;
                    break;
                }
            
            # Write-Debug("DST - CompareTo: {0}, CompareWith: {1}" -f $dst, $destinationAddress)
        }

        # Check: Does Provided DestinationPorts match the DestinationPorts in the Rule?
        $dstPort = @($rule.destinationPorts)
        #$dstPort = $dstPort.replace('*','Any')
        $dstPort = checkWildcard($dstPort)
        # Write-Debug("DstPort: {0} - Convert: {1}" -f $dstPort, (checkWildcard($dstPort)))

        if ($dstPort -match 'Any' -or $DestinationPort -match 'Any') {
            $dstPortTest = $True
        }
        elseif($dstPort -ne 'Any')
        {
            $dstPortA = buildArray -inputArray $dstPort
            if($DestinationPort -in $dstPortA){$dstPortTest = $True}
        }

        # Write-Debug ("Src Add: {0}, Dst Add: {1}" -f $src, $dst)
        # Write-Debug ("Src Test: {0}, Dst Test: {1}" -f $srcAddressTest, $dstAddressTest)

        if($srcAddressTest -and $dstAddressTest -and $protocolTest -and $dstPortTest)
        {
            $matchedRules += $rule
        }
    }
    # Return all Matched Rules
    $matchedRules
}

#endregion

#region Application Rules
# Main Application Rules Collection Function
function mainApplication{
    PARAM($RuleSet)
    $responseBag = @()
    foreach($s in $RuleSet)
    {
        if($Firewall) {
            $ruleCollection = @(matchApplicationRules -ruleBag $s.rules)
            if($ruleCollection.Count -ge 1){
                $thisCollection = [PSCustomObject]@{
                        collectionName = $s.name
                        id = $s.id
                        priority = $s.priority
                        action = $s.action.type
                        rules = $ruleCollection
                    }
                $responseBag += $thisCollection
            }

        }
        elseif ($FirewallJson) {
            foreach($p in $s.properties)
            {
                $ruleCollection = @(matchApplicationRules -ruleBag $p.rules)
            }
            if($ruleCollection.Count -ge 1){
                $thisCollection = [PSCustomObject]@{
                        collectionName = $s.name
                        id = $s.id
                        priority = $p.priority
                        action = $p.action.type
                        rules = $ruleCollection
                    }
                $responseBag += $thisCollection
            }
        }
    }

    <##>
    if($responseBag.Count -ge 1)
    {
        Write-Host("Matched Application Collections: {0}`n" -f $responseBag.Count);
        # $matchedRules | Format-Table
        foreach($bag in $responseBag)
        {
            Write-Host ("Collection Name: {0}" -f $bag.collectionName)
            Write-Host ("Priority: {0}" -f $bag.priority)
            Write-Host ("Action: {0}" -f $bag.action)
            $bag.rules | Format-Table @{L='Name';E={$_.name}},@{L='Description';E={$_.description}},@{L='Protocol';E={$_.protocols.protocolType};A='Center';W=100},@{L='Port';E={$_.protocols.port};A='Center';W=100},@{L='Source Addresses';E={$_.sourceAddresses}},@{L='Target FQDNs';E={$_.targetFqdns}} #-Wrap
        }
    }
    else {
        Write-Host("No Matched Rules")
    }
    #>
}

# Match Application Rules Function
function matchApplicationRules {
    PARAM($ruleBag)
    $matchedRules = @()

    # Change for Wildcard
    $SourceAddress = checkWildcard($SourceAddress)
    $Protocol = checkWildcard($Protocol)
    $DestinationPort = checkWildcard($DestinationPort)

    # Write-Debug ("Source: {0}, Destinaton: {1}, Destination Port: {2}, Protocol {3}" -f $SourceAddress, $DestinationUrl, $DestinationPort, $Protocol) 
    foreach ($rule in $ruleBag) {
        $srcAddressTest = $False;
        #$dstAddressTest = $False;
        $protocolTest = $False;
        $dstPortTest = $False;
        $dstFqdnTest = $False;
        # Write-Debug ("Source: {0}, Destinaton: {1}, Destination Port: {2}, Protocol {3}" -f $rule.sourceAddresses, $rule.targetFqdns, $rule.protocols.port, $rule.protocols.protocolType)
        # $rule | Format-Table

        # Check: Does Provided SourceAddress match the SourceAddresses a the Rule?
        foreach($src in $rule.sourceAddresses)
        {
            $src = checkWildcard($src)
            if($src -match 'Any' -or $SourceAddress -match 'Any')
            {
                $srcAddressTest = $True;
                # Write-Debug ("Any: Match Source: {0}, Output: {1}" -f $src, $srcAddressTest)
                break;
            }
            elseif (isAddressInRange -CompareTo $src -CompareWith $SourceAddress)
            {
                $srcAddressTest = $True;
                # Write-Debug ("isAddressInRange: Match Source: {0}, Output: {1}" -f $src, $srcAddressTest)
                break;
            }
        }

        # Check: Does Provided Protocol match the Protocol in the Rule?
        foreach($prot in $rule.protocols.protocolType)
        {
            #$prot = $prot.replace('*','Any')
            $prot = checkWildcard($prot)
            if ($prot -match 'Any' -or $Protocol -match 'Any')
            {
                $protocolTest = $True;
                break;
            }
            elseif($prot -match $Protocol)
                {
                    $protocolTest = $True;
                    break;
                }
            
            # Write-Debug("DST - CompareTo: {0}, CompareWith: {1}" -f $dst, $destinationAddress)
        }

        # Check: Does Provided DestinationFQDN match the TargetFQDNs in the Rule?
        foreach($fqdn in $rule.targetFqdns)
        {
            #$prot = $prot.replace('*','Any')
            #$prot = checkWildcard($prot)
            # $ipRegex = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            $ipRegex1 = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'; # Matches IP Address
            $ipRegex2 = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/([0-9]|[12][0-9]|3[0-2]))\b' ; # Matches IP Address/CIDR
            if (($fqdn -match $ipRegex1 -or $fqdn -match $ipRegex2) -and ($DestinationUrl -match $ipRegex1 -or $DestinationUrl -match $ipRegex2))
            {
                Write-Debug ('IP: {0}' -f $fqdn)
                $fqdn = checkWildcard($fqdn)
                if ($fqdn -match 'Any' -or $DestinationUrl -match 'Any')
                {
                    $dstFqdnTest = $True;
                    break;
                }
                elseif(isAddressInRange -CompareTo $fqdn -CompareWith $DestinationUrl)
                {
                    $dstFqdnTest = $True;
                    break;
                }
            }
            elseif (($fqdn -notmatch $ipRegex1 -or $fqdn -notmatch $ipRegex2) -and ($DestinationUrl -notmatch $ipRegex1 -or $DestinationUrl -notmatch $ipRegex2)) {
                Write-Debug ('FQDN: {0}' -f $fqdn)
                $fqdnRegEx = "^" + $fqdn.replace('.','\.') + "$"
                if ($fqdn -match 'Any' -or $DestinationUrl -match 'Any')
                {
                    $dstFqdnTest = $True;
                    break;
                }
                elseif($DestinationUrl -match $fqdnRegEx)
                    {
                        $dstFqdnTest = $True;
                        break;
                    }
            }
            # Write-Host $fqdnRegEx
            # Write-Debug("FQDN: CompareTo: {0}, CompareWith: {1} *** Result: {2}" -f $fqdn, $DestinationUrl, $dstFqdnTest)
        }

        # Check: Does Provided DestinationPorts match the DestinationPorts in the Rule?
        $dstPort = @($rule.protocols.port)
        $dstPort = checkWildcard($dstPort)
        Write-Debug("DstPort: {0} - Convert: {1}" -f $DestinationPort, $dstPort)

        if ($dstPort -match 'Any' -or $DestinationPort -match 'Any') {
            $dstPortTest = $True
        }
        elseif($dstPort -ne 'Any')
        {
            $dstPortA = buildArray -inputArray $dstPort
            if($DestinationPort -in $dstPortA){$dstPortTest = $True}
        }
        # Write-Debug ("User: {0}, Rule: {1}" -f $DestinationPort, $dstPort)
        Write-Debug ("SRC: {0}, Protocol: {1}, Port: {2}, FQDN: {3}" -f $srcAddressTest, $protocolTest, $dstPortTest, $dstFqdnTest)

        if($srcAddressTest -and $protocolTest -and $dstPortTest -and $dstFqdnTest)
        {
            $matchedRules += $rule
        }
    }
    # Return all Matched Rules
    $matchedRules
}

#endregion

function Main {
    Write-Host ("############################################################") -ForegroundColor 'Green'
    Write-Host ("Check-AzFirewallRules : Testing which rules match inputed parameters.`n`n") -ForegroundColor 'Green'

    if($Firewall) {
        $theObj = $Object | ConvertTo-JSON -Depth 100
        switch ($CollectionType) {
            Network { mainNetwork -RuleSet ($theObj | ConvertFrom-Json).networkRuleCollections }
            Application { mainApplication -RuleSet ($theObj | ConvertFrom-Json).applicationRuleCollections}
            Nat {return 'Application Rule Check is Not Yet Implemented!'}
            Default { mainNetwork}
        }
    }
    elseif($FirewallJson) {
        $theFile = (Get-Content $Object | ConvertFrom-JSON).properties
        switch ($CollectionType) {
            Network { mainNetwork -RuleSet $theFile.networkRuleCollections }
            Application { mainApplication -RuleSet $theFile.applicationRuleCollections}
            Nat {return 'Application Rule Check is Not Yet Implemented!'}
            Default { mainNetwork}
        }
    }
    Write-Host ("############################################################") -ForegroundColor 'Green'
}

# Call Main Function.
Main
