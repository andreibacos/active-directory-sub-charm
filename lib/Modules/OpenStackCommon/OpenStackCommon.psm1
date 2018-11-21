# Copyright 2016 Cloudbase Solutions Srl
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
#

Import-Module JujuLogging
Import-Module JujuUtils
Import-Module JujuHooks
Import-Module JujuWindowsUtils
Import-Module JujuHelper


$COMPUTERNAME = [System.Net.Dns]::GetHostName()
$SUPPORTED_OPENSTACK_RELEASES = @('liberty', 'mitaka', 'newton')

# Nova constants
$NOVA_PRODUCT = @{
    'beta_name' = 'OpenStack Hyper-V Compute Beta'
    'liberty' = @{
        'name' = 'OpenStack Hyper-V Compute Liberty'
        'version' = '12.0.0'
        'default_installer_urls' = @{
            'msi' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Liberty_12_0_0.msi#md5=71b77c82dd7990891e108a98a1ecd234'
            'zip' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Liberty_12_0_0.zip#md5=f122e8f71be16fd7f20317e745c20263'
        }
        'compute_driver' = 'hyperv.nova.driver.HyperVDriver'
        'compute_cluster_driver' = $null
    }
    'mitaka' = @{
        'name' = 'OpenStack Hyper-V Compute Mitaka'
        'version' = '13.0.0'
        'default_installer_urls' = @{
            'msi' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Mitaka_13_0_0.msi#md5=af7421fa96bb0af46c4107550852056e'
            'zip' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Mitaka_13_0_0.zip#md5=9efe31e847c59886a57007f9dddcfffc'
        }
        'compute_driver' = 'hyperv.nova.driver.HyperVDriver'
        'compute_cluster_driver' = 'hyperv.nova.cluster.driver.HyperVClusterDriver'
    }
    'newton' = @{
        'name' = 'OpenStack Hyper-V Compute Newton'
        'version' = '14.0.1'
        'default_installer_urls' = @{
            'msi' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Newton_14_0_1.msi'
            'zip' = 'https://cloudbase.it/downloads/HyperVNovaCompute_Newton_14_0_1.zip'
        }
        'compute_driver' = 'compute_hyperv.driver.HyperVDriver'
        'compute_cluster_driver' = 'compute_hyperv.cluster.driver.HyperVClusterDriver'
    }
}
$NOVA_CHARM_PORTS = @{
    "tcp" = @("5985", "5986", "3343", "445", "135", "139")
    "udp" = @("5985", "5986", "3343", "445", "135", "139")
}
$NOVA_DEFAULT_SWITCH_NAME = "br100"
$NOVA_DEFAULT_LOG_DIR = Join-Path $env:SystemDrive "OpenStack\Log"
$NOVA_DEFAULT_LOCK_DIR = Join-Path $env:SystemDrive "OpenStack\Lock"
$NOVA_DEFAULT_INSTANCES_DIR = Join-Path $env:SystemDrive "OpenStack\Instances"
$NOVA_INSTALL_DIR = Join-Path ${env:ProgramFiles} "Cloudbase Solutions\OpenStack\Nova"
$NOVA_VALID_NETWORK_TYPES = @('hyperv', 'ovs')
$env:OVS_RUNDIR = Join-Path $env:ProgramData "openvswitch"
$OVS_JUJU_BR = "juju-br"
$OVS_EXT_NAME = "Open vSwitch Extension"
$OVS_PRODUCT_NAME = "Open vSwitch for Hyper-V 2.5"
$OVS_INSTALL_DIR = Join-Path ${env:ProgramFiles} "Cloudbase Solutions\Open vSwitch"
$OVS_VSCTL = Join-Path $OVS_INSTALL_DIR "bin\ovs-vsctl.exe"
$OVS_DEFAULT_INSTALLER_URL = "https://cloudbase.it/downloads/openvswitch-hyperv-2.5.0-certified.msi"

# Cinder constants
$CINDER_PRODUCT = @{
    'beta_name' = $null
    'liberty' = @{
        'name' = 'OpenStack Windows Cinder Volume Liberty'
        'version' = '7.0.0'
        'default_installer_urls' = @{
            'msi' = 'https://cloudbase.it/downloads/CinderVolumeSetup_Liberty_7_0_0.msi#md5=88ca1e0dd60a9d658c75b35735b85e14'
            'zip' = 'https://cloudbase.it/downloads/CinderVolumeSetup_Liberty_7_0_0.zip#md5=22bc540c6663cc74a1cd567db9f77f61'
        }
    }
    'mitaka' = @{
        'name' = 'OpenStack Cinder Volume Mitaka'
        'version' = '8.0.0'
        'default_installer_urls' = @{
            'msi' = 'https://cloudbase.it/downloads/CinderVolumeSetup_Mitaka_8_0_0.msi#md5=122cfccd70daf4273bcd486b2ed1c2ed'
            'zip' = 'https://cloudbase.it/downloads/CinderVolumeSetup_Mitaka_8_0_0.zip#md5=9b988012a4bc472a50710f5f5adffb79'
        }
    }
    'newton' = @{
        'name' = 'OpenStack Cinder Volume Newton'
        'version' = '9.0.0'
        'default_installer_urls' = @{
            'msi' = 'https://cloudbase.it/downloads/CinderVolumeSetup_Newton_9_0_0.msi'
            'zip' = 'https://cloudbase.it/downloads/CinderVolumeSetup_Newton_9_0_0.zip'
        }
    }
}
$CINDER_INSTALL_DIR = Join-Path ${env:SystemDrive} "OpenStack\Cinder"
$CINDER_VALID_BACKENDS = @('iscsi', 'smb')
$CINDER_DEFAULT_LOCK_DIR = Join-Path ${env:SystemDrive} "OpenStack\Lock"
$CINDER_DEFAULT_ISCSI_LUN_DIR = Join-Path ${env:SystemDrive} "OpenStack\iSCSIVirtualDisks"
$CINDER_DEFAULT_IMAGE_CONVERSION_DIR = Join-Path ${env:SystemDrive} "OpenStack\ImageConversionDir"
$CINDER_DEFAULT_MOUNT_POINT_BASE_DIR = Join-Path ${env:SystemDrive} "OpenStack\mnt"
$CINDER_DEFAULT_LOG_DIR = Join-Path ${env:SystemDrive} "OpenStack\Log"
$CINDER_DEFAULT_MAX_USED_SPACE_RATIO = '1.0'
$CINDER_DEFAULT_OVERSUBMIT_RATIO = '1.0'
$CINDER_DEFAULT_DEFAULT_VOLUME_FORMAT = 'vhdx'

# Nsclient constants
$NSCLIENT_INSTALL_DIR = Join-Path ${env:ProgramFiles} "NSClient++"
$NSCLIENT_DEFAULT_INSTALLER_URLS = @{
    'msi' = 'https://github.com/mickem/nscp/releases/download/0.5.0.62/NSCP-0.5.0.62-x64.msi#md5=74a460dedbd98659b8bad24aa91fc29c'
    'zip' = 'https://github.com/mickem/nscp/releases/download/0.5.0.62/nscp-0.5.0.62-x64.zip#md5=a766dfdb5d9452b3a7d1aec02ce89106'
}

function Get-PythonDir {
    <#
    .SYNOPSIS
     Returns the full path of a Python environment directory for an OpenStack
     project.
    .PARAMETER InstallDir
     Installation directory for the OpenStack project.
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [string]$InstallDir
    )

    $pythonDir = Join-Path $InstallDir "Python27"
    if (!(Test-Path $pythonDir)) {
        $pythonDir = Join-Path $InstallDir "Python"
        if (!(Test-Path $pythonDir)) {
            Throw "Could not find Python directory in '$InstallDir'."
        }
    }
    return $pythonDir
}

function Get-ServiceWrapper {
    <#
    .SYNOPSIS
     Returns the full path to the correct OpenStackService wrapper
     used for OpenStack Windows services.
    #>
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Service,
        [Parameter(Mandatory=$true)]
        [string]$InstallDir
    )

    $wrapperName = ("OpenStackService{0}.exe" -f $Service)
    $svcPath = Join-Path $InstallDir ("bin\{0}" -f $wrapperName)
    if (!(Test-Path $svcPath)) {
        $svcPath = Join-Path $InstallDir "bin\OpenStackService.exe"
        if (!(Test-Path $svcPath)) {
            Throw "Failed to find service wrapper"
        }
    }
    return $svcPath
}

function New-ConfigFile {
    <#
    .SYNOPSIS
     Generates a configuration file after it is populated with the variables
     from the context generators.
     Function returns a list with the incomplete mandatory relation names
     in order to be used later on to set proper Juju status with incomplete
     contexts.
    .PARAMETER ContextGenerators
     HashTable with the keys:
     - 'generator' representing the function name that returns a dictionary
     with the relation variables;
     - 'relation' representing the relation name;
     - 'mandatory', boolean flag to indicate that this context generator is
     mandatory.
    .PARAMETER Template
     Full path to the template used to generate the configuration file.
    .PARAMETER OutFile
     Full path to the configuration file.
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [Hashtable[]]$ContextGenerators,
        [Parameter(Mandatory=$true)]
        [String]$Template,
        [Parameter(Mandatory=$true)]
        [String]$OutFile
    )

    $incompleteContexts = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    $mergedContext = [System.Collections.Generic.Dictionary[string, object]](New-Object "System.Collections.Generic.Dictionary[string, object]")

    foreach ($context in $ContextGenerators) {
        Write-JujuInfo ("Getting context for {0}" -f $context["relation"])
        $ctxt = & $context["generator"]
        if (!$ctxt.Count -and ($context["mandatory"] -ne $null) -and ($context["mandatory"] -eq $true)) {
            # Context is empty. Probably peer not ready.
            Write-JujuWarning ("Context for {0} is EMPTY" -f $context["relation"])
            $incompleteContexts.Add($context["relation"])
            continue
        }
        Write-JujuInfo ("Got {0} context: {1}" -f @($context["relation"], ($ctxt.Keys -join ',' )))
        foreach ($val in $ctxt.Keys) {
            $mergedContext[$val] = $ctxt[$val]
        }
    }

    if (!$mergedContext.Count) {
        return ,$incompleteContexts
    }

    Start-RenderTemplate -Context $mergedContext -TemplateName $Template -OutFile $OutFile

    return ,$incompleteContexts
}

function Get-OpenstackVersion {
    $cfg = Get-JujuCharmConfig

    if($cfg['openstack-version'] -notin $SUPPORTED_OPENSTACK_RELEASES) {
        Throw ("'{0}' is not a supported OpenStack release." -f @($cfg['openstack-version']))
    }

    return $cfg['openstack-version']
}

function Get-ProductDefaultInstallerURLs {
    <#
    .SYNOPSIS
     Returns the default installer download URLs for an OpenStack product.
    .PARAMETER Project
     The OpenStack project name.
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Nova", "Cinder")]
        [String]$Project
    )

    $release = Get-OpenstackVersion
    switch($Project) {
        "Nova" {
            return $NOVA_PRODUCT[$release]['default_installer_urls']
        }
        "Cinder" {
            return $CINDER_PRODUCT[$release]['default_installer_urls']
        }
    }
}

function Get-InstallerPath {
    <#
    .SYNOPSIS
     Returns the installer path for an OpenStack project after it is downloaded.
     'installer-url' config option is used to get an installer provided by the
     user.
    .PARAMETER Project
     The OpenStack project for the installer. This is used to determine the
     default download URL in case 'installer-url' configuration option is not
     set.
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Nova", "Cinder")]
        [String]$Project
    )

    $release = Get-OpenstackVersion
    $cfg = Get-JujuCharmConfig
    if (!$cfg['installer-url']) {
        $installerType = "msi"
        if(Get-IsNanoServer) {
            $installerType = "zip"
        }
        try {
            $defaultUrls = Get-ProductDefaultInstallerURLs $Project
            $url = $defaultUrls[$installerType]
        } catch {
            Throw "Could not find a '$installerType' download installer URL for '$release'"
        }
        Write-JujuInfo "Using default installer url: '$url'"
    } else {
        Write-JujuInfo ("installer-url is set to: '{0}'" -f @($cfg['installer-url']))
        $url = $cfg['installer-url']
    }

    $file = ([System.Uri]$url).Segments[-1]
    $tempDownloadFile = Join-Path $env:TEMP $file
    Start-ExecuteWithRetry {
        $out = Invoke-FastWebRequest -Uri $url -OutFile $tempDownloadFile
    } -RetryMessage "Installer download failed. Retrying"

    return $tempDownloadFile
}

function Disable-Service {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $svc = Get-Service $Name -ErrorAction SilentlyContinue
    if (!$svc) {
        return
    }
    Get-Service $Name | Set-Service -StartupType Disabled | Out-Null
}

function Enable-Service {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    $svc = Get-Service $Name -ErrorAction SilentlyContinue
    if (!$svc) {
        return
    }
    Get-Service $Name | Set-Service -StartupType Automatic | Out-Null
}

function Get-RabbitMQConfig {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['rabbit-user']) {
        Throw "'rabbit-user' config option cannot be empty"
    }
    if(!$cfg['rabbit-vhost']) {
        Throw "'rabbit-vhost' config option cannot be empty"
    }

    return @($cfg['rabbit-user'], $cfg['rabbit-vhost'])
}

function Get-MySQLConfig {
    $cfg = Get-JujuCharmConfig

    if(!$cfg['database']) {
        Throw "'database' config option cannot be empty"
    }
    if(!$cfg['database-user']) {
        Throw "'database-user' config option cannot be empty"
    }

    return @($cfg['database'], $cfg['database-user'])
}

function Get-RabbitMQContext {
    Write-JujuInfo "Generating context for RabbitMQ"

    $required = @{
        "hostname" = $null
        "password" = $null
    }

    $optional = @{
        "vhost" = $null
        "username" = $null
        "ha_queues" = $null
    }

    $ctx = Get-JujuRelationContext -Relation "amqp" -RequiredContext $required -OptionalContext $optional

    $username, $vhost = Get-RabbitMQConfig

    if(!$ctx.Count) {
        return @{}
    }

    $data = @{}

    if (!$ctx["username"]) {
        $data["rabbit_userid"] = $username
    } else {
        $data["rabbit_userid"] = $ctx["username"]
    }

    if (!$ctx["vhost"]) {
        $data["rabbit_virtual_host"] = $vhost
    } else {
        $data["rabbit_virtual_host"] = $ctx["vhost"]
    }

    if ($ctx["ha_queues"]) {
        $data["rabbit_ha_queues"] = "True"
    } else {
        $data["rabbit_ha_queues"] = "False"
    }

    $data["rabbit_host"] = $ctx["hostname"]
    $data["rabbit_password"] = $ctx["password"]

    return $data
}

function Get-GlanceContext {
    Write-JujuInfo "Getting glance context"

    $required = @{
        "glance-api-server" = $null
    }
    $ctx = Get-JujuRelationContext -Relation 'image-service' -RequiredContext $required

    $new = @{}
    foreach ($i in $ctx.Keys) {
        $new[$i.Replace("-", "_")] = $ctx[$i]
    }

    return $new
}

function Get-MySQLContext {
    $requiredCtxt = @{
        "db_host" = $null
        "password" = $null
    }
    $ctxt = Get-JujuRelationContext -Relation "mysql-db" -RequiredContext $requiredCtxt

    if(!$ctxt.Count) {
        return @{}
    }

    $database, $databaseUser = Get-MySQLConfig

    return @{
        'db_host' = $ctxt['db_host']
        'db_name' = $database
        'db_user' = $databaseUser
        'db_user_password' = $ctxt['password']
    }
}

function Get-ConfigContext {
    $cfg = Get-JujuCharmConfig

    $ctxt = @{}
    foreach ($config in $cfg.GetEnumerator()) {
        $name = $config.Key.Replace("-", "_")
        if ($config.Value.Gettype() -is [System.String]) {
            $value = $config.Value.Replace('/', '\')
        } else {
            $value = $config.Value
        }
        $ctxt[$name] = $value
    }

    return $ctxt
}

function Start-AMQPRelationJoinedHook {
    $username, $vhost = Get-RabbitMQConfig

    $relationSettings = @{
        'username' = $username
        'vhost' = $vhost
    }

    $rids = Get-JujuRelationIds -Relation "amqp"
    foreach ($rid in $rids){
        Set-JujuRelation -RelationId $rid -Settings $relationSettings
    }
}

function Start-MySQLDBRelationJoinedHook {
    $database, $databaseUser = Get-MySQLConfig

    $settings = @{
        'database' = $database
        'username' = $databaseUser
        'hostname' = Get-JujuUnitPrivateIP
    }
    $rids = Get-JujuRelationIds 'mysql-db'
    foreach ($r in $rids) {
        Set-JujuRelation -Settings $settings -RelationId $r
    }
}

function Get-InstalledOpenStackProduct {
    <#
    .SYNOPSIS
     Returns the OpenStack product installed for the project passed as
     parameter.
    .PARAMETER Project
     Name of the OpenStack project for the product.
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Nova", "Cinder")]
        [string]$Project
    )

    if(Get-IsNanoServer) {
        return $null
    }

    switch($Project) {
        "Nova" {
            $productConstants = $NOVA_PRODUCT
        }
        "Cinder" {
            $productConstants = $CINDER_PRODUCT
        }
    }

    $release = Get-OpenstackVersion

    $productName = $productConstants[$release]['name']
    $product = Get-ManagementObject -ClassName 'Win32_Product' -Filter "Name='$productName'"
    if(!$product) {
        # Probably a custom beta MSI installer was used
        $productName = $productConstants['beta_name']
        $product = Get-ManagementObject -ClassName 'Win32_Product' -Filter "Name='$productName'"
        if(!$product) {
            return $null
        }
    }

    return $product
}

# TODO: Move to JujuHooks module
function Set-JujuApplicationVersion {
    <#
    .SYNOPSIS
    Set the version of the application Juju is managing. The version will be
    displayed in the "juju status" output for the application.
    .PARAMETER Version
    Version to be set
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [String]$Version
    )
    PROCESS {
        $cmd = @("application-version-set.exe", $Version)
        Invoke-JujuCommand -Command $cmd | Out-Null
    }
}

# TODO: Move to JujuWindowsUtils module
function Remove-WindowsServices {
    <#
    .SYNOPSIS
    Deletes the Windows system services. Used when MSI method is used to delete
    the default generated Windows services, so charm can create them later on.
    .PARAMETER Services
    List of Windows service names to be deleted.
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [string[]]$Names
    )

    foreach($name in $Names) {
        $service = Get-ManagementObject -ClassName "Win32_Service" -Filter "Name='$name'"
        if($service) {
            Stop-Service $name -Force
            Start-ExternalCommand { sc.exe delete $name } | Out-Null
        }
    }
}

# TODO: Move to JujuWindowsUtils module
function Uninstall-WindowsProduct {
    <#
    .SYNOPSIS
     Removes an Windows product.
    .PARAMETER Name
     The Name of the product to be removed.
    #>

    Param(
        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    if(Get-IsNanoServer) {
        Write-JujuWarning "Cannot uninstall Windows products on Nano server"
        return
    }

    $params = @{
        'ClassName' = "Win32_Product"
        'Filter' = "Name='$Name'"
    }

    if ($PSVersionTable.PSVersion.Major -lt 4) {
        $product = Get-WmiObject @params
        $result = $product.Uninstall()
    } else {
        $product = Get-CimInstance @params
        $result = Invoke-CimMethod -InputObject $product -MethodName "Uninstall"
    }

    if($result.ReturnValue) {
        Throw "Failed to uninstall product '$Name'"
    }
}


Export-ModuleMember -Function "*" -Variable "*"
