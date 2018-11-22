# Copyright 2018 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

Import-Module OpenStackCommon
Import-Module JujuHooks
Import-Module powershell-yaml
Import-Module JujuWindowsUtils
Import-Module JujuLogging
Import-Module JujuUtils
Import-Module JujuHelper

function Confirm-IsInDomain {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$WantedDomain
    )

    $currentDomain = (Get-ManagementObject -Class Win32_ComputerSystem).Domain.ToLower()
    $comparedDomain = ($WantedDomain).ToLower()
    $inDomain = $currentDomain.Equals($comparedDomain)
    return $inDomain
}

function Get-ConfADUsername {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['ad-admin-username']) {
        Throw "ad-admin-username config option cannot be empty"
    }

    return $cfg['ad-admin-username']
}

function Get-ConfADPassword {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['ad-admin-password']) {
        Throw "ad-admin-password config option cannot be empty"
    }

    return $cfg['ad-admin-password']
}

function Get-ConfADIP {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['ad-ip']) {
        Throw "ad-ip config option cannot be empty"
    }

    return $cfg['ad-ip']
}

function Get-ConfADDomain {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['ad-domain']) {
        Throw "ad-domain config option cannot be empty"
    }

    return $cfg['ad-domain']
}

function Get-ConfADServiceAccount {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['ad-service-account']) {
        Throw "ad-service-account config option cannot be empty"
    }

    return $cfg['ad-service-account']
}

function Get-ConfADOU {
    $cfg = Get-JujuCharmConfig
    return $cfg['ad-ou']
}

function Get-ConfADGroup {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['ad-group']) {
        Throw "ad-group config option cannot be empty"
    }

    return $cfg['ad-group']
}

function Get-ConfADCredential {
    $u = Get-ConfADUsername
    $p = Get-ConfADPassword | ConvertTo-SecureString -asPlainText -Force
    $d = Get-ConfADDomain
    $username = "{0}\{1}" -f @($d, $u)
    $credential = New-Object System.Management.Automation.PSCredential($username, $p)
    return $credential
}

function Get-ComputerName {
    return [System.Net.Dns]::GetHostName()
}

function Clear-ComputerConstraintsDelegations {
    $relationData = Get-JujuRelation
    $marshaledConstraints = $relationData["constraints"]
    if($marshaledConstraints) {
        $constraints = Get-UnmarshaledObject $marshaledConstraints
        $credential = Get-ConfADCredential
        $computer = Get-ADComputer -Credential $credential $(Get-ComputerName)
        $domain_group = Get-ConfADGroup

        $compute_nodes = Get-ADGroupMember -Identity $domain_group -Credential $credential
        if($compute_nodes -is [system.array]){
            foreach ($compute in $compute_nodes) {
                    foreach ($constraint in $constraints){
                        Set-ADObject -Credential $credential -Identity $computer `
                                     -Remove @{'msDS-AllowedToDelegateTo' = ('{0}/{1}' -f $constraint, $compute.name) }    
                        Set-ADObject -Credential $credential -Identity $compute `
                                     -Remove @{'msDS-AllowedToDelegateTo' = ('{0}/{1}' -f $constraint, $computer.name) }  
                    }            
            }
        }
    }
}

function New-ADSubRelationData {
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$RelationId,
        [Parameter(Mandatory=$true)]
        [System.String]$Unit
    )

    $relationData = Get-JujuRelation -RelationId $RelationId -Unit $Unit
    $relationSettings = @{
        'service-account' = Get-ConfADServiceAccount
        'domainName' = Get-ConfADDomain
    }  

    $marshaledConstraints = $relationData["constraints"]
    if($marshaledConstraints) {
        $constraints = Get-UnmarshaledObject $marshaledConstraints
        $credential = Get-ConfADCredential
        $computer = Get-ADComputer -Credential $credential $(Get-ComputerName)
        $domain_group = Get-ConfADGroup

        $compute_nodes = Get-ADGroupMember -Identity $domain_group -Credential $credential
        
        foreach ($compute in $compute_nodes) {
                foreach ($constraint in $constraints){
                    Set-ADObject -Credential $credential -Identity $computer `
                                 -Add @{'msDS-AllowedToDelegateTo' = ('{0}/{1}' -f $constraint, $compute.name) }    
                    Set-ADObject -Credential $credential -Identity $compute `
                                 -Add @{'msDS-AllowedToDelegateTo' = ('{0}/{1}' -f $constraint, $computer.name) }  
                }            
        }
    }
    return $relationSettings
}

function Invoke-InstallHook {
    Write-JujuWarning "Running install hook"

    Start-TimeResync

    Write-JujuWarning "Installing Windows Features"
    Install-WindowsFeatures -Features @('RSAT-AD-PowerShell')
    $ad_ip = Get-ConfADIP
    $service_account = Get-ConfADServiceAccount
    $credential = Get-ConfADCredential
    $domain = Get-ConfADDomain
    $domain_group = Get-ConfADGroup
    $domain_ou = Get-ConfADOU
    
    $username = "{0}\{1}" -f @($domain, $(Get-ConfADUsername))

    if (!((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)) {
        Set-DnsClientServerAddress -InterfaceAlias * -ServerAddresses $ad_ip

        if($domain_ou) {
            Write-JujuWarning "External AD -> Joining AD OU: $domain_ou"
            $join_ad_result = Add-Computer -DomainName $domain -Credential $credential -OUPath $domain_ou -PassThru
        } else {
            Write-JujuWarning "External AD -> AD OU not provided"
            $join_ad_result = Add-Computer -DomainName $domain -Credential $credential -PassThru
        }
        if ($join_ad_result.HasSucceeded){
            Write-JujuWarning "External AD -> Joined AD domain, adding computer to group: $domain_group"
            $computer = Get-ADComputer -Credential $credential $(Get-ComputerName)
            Add-ADGroupMember -Credential $credential -Identity $domain_group -Members $computer
            Write-JujuWarning "External AD -> Joined AD domain, rebooting"
            Invoke-JujuReboot -Now
        }
    } else {
        Write-JujuWarning "Computer is already part of a domain"
        $computer = Get-ADComputer -Credential $credential $(Get-ComputerName)
        Add-ADGroupMember -Credential $credential -Identity $domain_group -Members $computer
    }
    $computer = Get-ADComputer -Credential $credential $(Get-ComputerName)
    Add-LocalGroupMember -Group Administrators -Member $username -ErrorAction SilentlyContinue
    Add-LocalGroupMember -Group Administrators -Member "$domain\$service_account$" -ErrorAction SilentlyContinue
    Grant-Privilege -User $username -Grant SeServiceLogonRight
    Grant-Privilege -User "$domain\$service_account$" -Grant SeServiceLogonRight

    Enable-WSManCredSSP -Role Server -Force | Out-Null
    Enable-WSManCredSSP -Role Client -DelegateComputer '*' -Force | Out-Null

    $credssp_script = Join-Path (Get-JujuCharmDir) "files\enable-credssp.ps1"
    Start-ProcessAsUser -Command "$PShome\powershell.exe" `
        -Arguments @("-NonInteractive","-executionpolicy", "Unrestricted", `
        "-File", $credssp_script, "-Username", $username, "-Password", $(Get-ConfADPassword), `
        "-DomainName", $domain) -Credential $credential

    Write-JujuWarning "External AD -> adding service account"
    Add-ADComputerServiceAccount -Credential $credential -Identity $computer -ServiceAccount $service_account
    Set-ADServiceAccount -Credential $credential -Identity $service_account `
                         -PrincipalsAllowedToRetrieveManagedPassword $domain_group
    Invoke-Command -ComputerName $computer.name -Credential $credential -Authentication Credssp `
           { Install-ADServiceAccount -Identity $using:service_account }
    Set-ADAccountControl -Credential $credential -Identity $computer -TrustedToAuthForDelegation $true

    Set-JujuStatus -Status "active" -Message "Unit is ready"
}

function Invoke-StopHook {
    $credential = Get-ConfADCredential
    $domain = Get-ConfADDomain
    $computer = Get-ADComputer -Credential $credential $(Get-ComputerName)

    Write-JujuWarning "External AD -> Leaving External AD domain: $domain"
    if (Confirm-IsInDomain $domain) {
        Remove-ADComputer -Identity $computer -Credential $credential -Confirm:$false -ErrorAction SilentlyContinue
        Add-Computer -UnjoinDomainCredential $credential -WorkgroupName workgroup -force
        Invoke-JujuReboot -Now
    }
}

function Invoke-ADSubRelationChangedHook {
    $domain = Get-ConfADDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }

    $rids = Get-JujuRelationIds -Relation 'ad-sub'
    foreach($rid in $rids) {
        [array]$units = Get-JujuRelatedUnits -RelationId $rid
        if(!$units.Count) {
            continue
        }
        foreach($unit in $units) {
            $relationSettings = New-ADSubRelationData -RelationId $rid -Unit $unit
            Set-JujuRelation -RelationId $rid -Settings $relationSettings
        }
    }
}

function Invoke-ADSubRelationDepartedHook {
    $domain = Get-ConfADDomain
    if (!(Confirm-IsInDomain $domain)) {
        Write-JujuWarning "AD forest is not yet installed. Skipping the rest of the hook"
        return
    }
    Clear-ComputerConstraintsDelegations
}