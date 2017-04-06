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

# Git Repositories
$REQUIREMENTS_GIT       = "https://github.com/openstack/requirements.git"
$NEUTRON_GIT           = "https://github.com/openstack/neutron.git"
$NOVA_GIT              = "https://github.com/openstack/nova.git"
$NETWORKING_HYPERV_GIT = "https://github.com/openstack/networking-hyperv.git"
$COMPUTE_HYPERV_GIT    = "https://github.com/openstack/compute-hyperv.git"
$OSWIN_GIT             = "https://git.openstack.org/openstack/os-win.git"


$NOVA_CHARM_PORTS = @{
    "tcp" = @("5985", "5986", "3343", "445", "135", "139")
    "udp" = @("5985", "5986", "3343", "445", "135", "139")
}

$OPENSTACK_DIR          = Join-Path $env:SystemDrive "OpenStack"
$PYTHON_DIR             = Join-Path $env:SystemDrive "Python27"
$LIB_DIR                = Join-Path $PYTHON_DIR "lib\site-packages"
$BUILD_DIR              = Join-Path $OPENSTACK_DIR "build"
$INSTANCES_DIR          = Join-Path $OPENSTACK_DIR "Instances"
$BIN_DIR                = Join-Path $OPENSTACK_DIR "bin"
$CONFIG_DIR             = Join-Path $OPENSTACK_DIR "etc"
$LOG_DIR                = Join-Path $OPENSTACK_DIR "log"
$SERVICE_DIR            = Join-Path $OPENSTACK_DIR "service"
$FILES_DIR              = Join-Path ${env:CHARM_DIR} "files"
$INTERFACES_TEMPLATE    = Join-Path $CONFIG_DIR "interfaces.template"
$POLICY_FILE            = Join-Path $CONFIG_DIR "policy.json"
$MKISO_EXE              = Join-Path $BIN_DIR "mkisofs.exe"
$QEMU_IMG_EXE           = Join-Path $BIN_DIR "qemu-img.exe"

$OVS_INSTALL_DIR            = Join-Path ${env:ProgramFiles} "Cloudbase Solutions\Open vSwitch"
$OVS_VSCTL                  = Join-Path $OVS_INSTALL_DIR "bin\ovs-vsctl.exe"
$env:OVS_RUNDIR             = Join-Path $env:ProgramData "openvswitch"
$NOVA_DEFAULT_SWITCH_NAME   = "br100"
$NOVA_VALID_NETWORK_TYPES   = @('hyperv', 'ovs')
$OVS_VSWITCHD_SERVICE_NAME  = "ovs-vswitchd"
$OVS_OVSDB_SERVICE_NAME     = "ovsdb-server"
$OVS_JUJU_BR                = "juju-br"
$OVS_PRODUCT_NAME           = "Open vSwitch"
$OVS_EXT_NAME               = "Open vSwitch Extension"
$OVS_DEFAULT_INSTALLER_URL  = "https://cloudbase.it/downloads/openvswitch-hyperv-2.5.0-certified.msi"

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

    $incompleteRelations = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    $mergedContext = [System.Collections.Generic.Dictionary[string, object]](New-Object "System.Collections.Generic.Dictionary[string, object]")

    foreach ($context in $ContextGenerators) {
        Write-JujuWarning ("Getting context for {0}" -f $context["relation"])
        $ctxt = Invoke-Command -ScriptBlock $context["generator"]
        if (!$ctxt.Count -and ($context["mandatory"] -ne $null) -and ($context["mandatory"] -eq $true)) {
            # Context is empty. Probably peer not ready.
            Write-JujuWarning ("Context for {0} is EMPTY" -f $context["relation"])
            $incompleteRelations.Add($context["relation"])
            continue
        }
        Write-JujuWarning ("Got {0} context: {1}" -f @($context["relation"], ($ctxt.Keys -join ',' )))
        foreach ($val in $ctxt.Keys) {
            $mergedContext[$val] = $ctxt[$val]
        }
    }

    if (!$mergedContext.Count) {
        return $incompleteRelations
    }

    Start-RenderTemplate -Context $mergedContext -TemplateName $Template -OutFile $OutFile

    return $incompleteRelations
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

function Get-DevStackContext {
    $requiredCtx =  @{
        "devstack_ip" = $null;
        "password"    = $null;
        "rabbit_user" = $null;
    }
    $ctx = Get-JujuRelationContext -Relation 'devstack' -RequiredContext $requiredCtx

    # Required context not found
    if(!$ctx.Count) {
        return @{}
    }

    return $ctx
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
