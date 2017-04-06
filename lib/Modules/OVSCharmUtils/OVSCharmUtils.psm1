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

Import-Module JujuHooks
Import-Module JujuLogging
Import-Module CICommon
Import-Module Networking
Import-Module HyperVNetworking
Import-Module JujuHelper


function Invoke-InterfacesDHCPRenew {
    <#
    .SYNOPSIS
     Renews DHCP for every NIC on the system with DHCP enabled.
    #>

    $interfaces = Get-CimInstance -Class Win32_NetworkAdapterConfiguration | Where-Object {
        $_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true -and $_.DHCPServer -eq "255.255.255.255"
    }
    if($interfaces) {
        $interfaces.InterfaceIndex | Invoke-DHCPRenew -ErrorAction SilentlyContinue | Out-Null
    }
}

function Confirm-IPIsInDataNetwork {
    <#
    .SYNOPSIS
     Checks if an IP is in data network
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [System.String]$DataNetwork,
        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$IP
    )

    if($IP.IPAddress -eq "127.0.0.1") {
        return $false
    }

    $port = Get-NetAdapter -InterfaceIndex $IP.IfIndex -ErrorAction SilentlyContinue
    if(!$port) {
        Write-JujuWarning ("Port with index '{0}' no longer exists" -f @($IP.IfIndex))
        return $false
    }

    if($port.DriverFileName -eq "vmswitch.sys") {
        Write-JujuWarning "Port '$port' is a Hyper-V network adapter. Skipping"
        return $false
    }

    $netDetails = $DataNetwork.Split("/")
    $decimalMask = ConvertTo-Mask $netDetails[1]

    Write-JujuWarning ("Checking {0} on interface {1}" -f @($IP.IPAddress, $IP.InterfaceAlias))

    if ($IP.PrefixLength -ne $netDetails[1]) {
        return $false
    }

    $network = Get-NetworkAddress $IP.IPv4Address $decimalMask
    Write-JujuWarning ("Network address for {0} is {1}" -f @($IP.IPAddress, $network))

    if ($network -ne $netDetails[0]) {
        return $false
    }

    return $true
}

function Get-DataPortsFromDataNetwork {
    <#
    .SYNOPSIS
     Returns a list with all the system ports in the data network
    #>

    $ports = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")

    $cfg = Get-JujuCharmConfig
    if (!$cfg["os-data-network"]) {
        Write-JujuWarning "'os-data-network' is not defined"
        return $ports
    }

    $ovsAdaptersInfo = Get-CharmState -Namespace "hvcomputesrc" -Key "ovs_adapters_info"
    if($ovsAdaptersInfo) {
        foreach($i in $ovsAdaptersInfo) {
            $adapter = Get-NetAdapter -Name $i["name"]
            $ports.Add($adapter)
        }
        return $ports
    }

    # If there is any network interface configured to use DHCP and did not get an IP address
    # we manually renew its lease and try to get an IP address before searching for the data network
    Invoke-InterfacesDHCPRenew

    $ovsAdaptersInfo = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")

    $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
    foreach ($i in $configuredAddresses) {
        if(Confirm-IPIsInDataNetwork -DataNetwork $cfg['os-data-network'] -IP $i) {
            $adapterInfo = Get-InterfaceIpInformation -InterfaceIndex $i.IfIndex
            $ovsAdaptersInfo.Add($adapterInfo)
            $adapter = Get-NetAdapter -InterfaceIndex $i.IfIndex
            $ports.Add($adapter)
        }
    }

    if($ovsAdaptersInfo) {
        Set-CharmState -Namespace "hvcomputesrc" -Key "ovs_adapters_info" -Value $ovsAdaptersInfo
    }

    return $ports
}

function Get-OVSDataPorts {
    $dataPorts = Get-DataPortsFromDataNetwork

    if ($dataPorts) {
        return $dataPorts
    }

    $fallbackPort = Get-FallbackNetadapter
    $adapterInfo = Get-InterfaceIpInformation -InterfaceIndex $fallbackPort.IfIndex
    Set-CharmState -Namespace "hvcomputesrc" -Key "ovs_adapters_info" -Value @($adapterInfo)

    return @($fallbackPort)
}

function Set-OVSAdapterAddress {
    Param(
        [Parameter(Mandatory=$true)]
        [Object]$AdapterInfo
    )

    $ovsIf = Get-NetAdapter $OVS_JUJU_BR
    if(!$ovsIf) {
        Throw "Could not find OVS adapter."
    }

    $ips = $AdapterInfo["addresses"]
    if(!$ips) {
        Write-JujuWarning "No IP addresses saved to configure OVS adapter."
    }

    foreach ($i in $ips) {
        $ipAddr = Get-NetIPAddress -AddressFamily $i["AddressFamily"] -IPAddress $i["IPAddress"] `
                                   -PrefixLength $i["PrefixLength"] -ErrorAction SilentlyContinue
        if($ipAddr) {
            if($ipAddr.InterfaceIndex -eq $ovsIf.ifIndex) {
                continue
            }
            $ipAddr | Remove-NetIPAddress -Confirm:$false | Out-Null
        }
        if ($i["AddressFamily"] -eq "IPv6") {
            continue
        }
        New-NetIPAddress -IPAddress $i["IPAddress"] -PrefixLength $i["PrefixLength"] -InterfaceIndex $ovsIf.ifIndex | Out-Null
    }
}

function New-OVSInternalInterfaces {
    $ovsAdaptersInfo = Get-CharmState -Namespace "hvcomputesrc" -Key "ovs_adapters_info"
    if(!$ovsAdaptersInfo) {
        Throw "Failed to find OVS adapters info"
    }

    # Use only one adapter as OVS bridge port
    foreach($i in $ovsAdaptersInfo) {
        if(!$i['addresses']) {
            continue
        }
        $adapterInfo = $i
        break
    }

    Invoke-JujuCommand -Command @($OVS_VSCTL, "--may-exist", "add-br", $OVS_JUJU_BR) | Out-Null
    Invoke-JujuCommand -Command @($OVS_VSCTL, "--may-exist", "add-port", $OVS_JUJU_BR, $adapterInfo["name"]) | Out-Null

    # Enable the OVS adapter
    Get-Netadapter $OVS_JUJU_BR | Enable-NetAdapter | Out-Null
    Set-OVSAdapterAddress -AdapterInfo $adapterInfo
}

function Get-OVSLocalIP {
    $ovsAdapter = Get-Netadapter $OVS_JUJU_BR -ErrorAction SilentlyContinue
    if(!$ovsAdapter) {
        $netType = Get-NetType
        if($netType -eq "ovs") {
            Throw "Trying to get OVS local IP, but OVS adapter is not up"
        }
        Write-JujuWarning "OVS adapter is not created yet"
        return $null
    }

    [array]$addresses = Get-NetIPAddress -InterfaceIndex $ovsAdapter.InterfaceIndex -AddressFamily IPv4
    if(!$addresses) {
        Throw "No IPv4 addresses configured for the OVS port"
    }

    return $addresses[0].IPAddress
}

function Get-OVSExtStatus {
    $vmSwitch = Get-JujuVMSwitch
    if(!$vmSwitch) {
        Write-JujuWarning "VM switch was not created yet"
        return $null
    }

    #$ext = Get-VMSwitchExtension -VMSwitchName $vmSwitch.Name -Name $OVS_EXT_NAME
    $ext = Get-VMSwitchExtension -VMSwitchName $vmSwitch.Name | Where-Object { $_.Name -match "$OVS_EXT_NAME" }
    if (!$ext){
        Write-JujuWarning "Open vSwitch extension not installed"
        return $null
    }

    return $ext
}

function Enable-OVSExtension {
    $ext = Get-OVSExtStatus

    if (!$ext){
       Throw "Cannot enable OVS extension. Not installed"
    }

    if (!$ext.Enabled) {
        #Enable-VMSwitchExtension $OVS_EXT_NAME $ext.SwitchName | Out-Null
        Enable-VMSwitchExtension -VMSwitchExtension $ext | Out-Null
    }
}

function Disable-OVSExtension {
    $ext = Get-OVSExtStatus

    if ($ext -and $ext.Enabled) {
        #Disable-VMSwitchExtension $OVS_EXT_NAME $ext.SwitchName | Out-Null
        Disable-VMSwitchExtension -VMSwitchExtension $ext | Out-Null
    }
}

function Get-OVSInstallerPath {
    $cfg = Get-JujuCharmConfig
    $installerUrl = $cfg['ovs-installer-url']
    if (!$installerUrl) {
        $installerUrl = $OVS_DEFAULT_INSTALLER_URL
    }

    $file = ([System.Uri]$installerUrl).Segments[-1]
    $tempDownloadFile = Join-Path $env:TEMP $file
    Start-ExecuteWithRetry {
        Invoke-FastWebRequest -Uri $installerUrl -OutFile $tempDownloadFile | Out-Null
    } -RetryMessage "OVS installer download failed. Retrying"

    return $tempDownloadFile
}

function Disable-OVS {
    $ovsServices = @($OVS_VSWITCHD_SERVICE_NAME, $OVS_OVSDB_SERVICE_NAME)

    # Check if both OVS services are up and running
    $ovsRunning = $true
    foreach($svcName in $ovsServices) {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if(!$service) {
            $ovsRunning = $false
            continue
        }
        if($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            $ovsRunning = $false
        }
    }

    if($ovsRunning) {
        $bridges = Start-ExternalCommand { & $OVS_VSCTL list-br }
        foreach($bridge in $bridges) {
            Start-ExternalCommand { & $OVS_VSCTL del-br $bridge }
        }
    }

    foreach($svcName in $ovsServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if($svc) {
            Stop-Service $svcName -Force
            Disable-Service $svcName
        }
    }

    Disable-OVSExtension
}

function Enable-OVS {
    Start-ExternalCommand { pip install -U "ovs" } -ErrorMessage "Failed to install $ovs_pip"
    
    Start-ExternalCommand { cmd.exe /c "sc triggerinfo ovs-vswitchd start/strcustom/6066F867-7CA1-4418-85FD-36E3F9C0600C/VmmsWmiEventProvider" } -ErrorMessage "Failed to modify ovs-vswitchd service."
    Start-ExternalCommand { cmd.exe /c "sc config ovs-vswitchd start=demand" } -ErrorMessage "Failed to modify ovs-vswitchd service."

    Enable-OVSExtension

    $ovsServices = @($OVS_OVSDB_SERVICE_NAME, $OVS_VSWITCHD_SERVICE_NAME)
    foreach($svcName in $ovsServices) {
        Enable-Service $svcName
        Start-Service $svcName
    }
}

function Install-OVS {
    if (Get-ComponentIsInstalled -Name $OVS_PRODUCT_NAME) {
        Write-JujuWarning "OVS is already installed"
        return
    }

    $installerPath = Get-OVSInstallerPath
    Write-JujuWarning "Installing OVS from '$installerPath'"

    $logFile = Join-Path $env:APPDATA "ovs-installer-log.txt"
    $extraParams = @("INSTALLDIR=`"$OVS_INSTALL_DIR`"")
    Install-Msi -Installer $installerPath -LogFilePath $logFile -ExtraArgs $extraParams
}

function Uninstall-OVS {
    $isOVSInstalled = Get-ComponentIsInstalled -Name $OVS_PRODUCT_NAME
    if (!$isOVSInstalled) {
        Write-JujuWarning "OVS is not installed"
        return
    }

    Write-JujuWarning "Uninstalling OVS"
    Uninstall-WindowsProduct -Name $OVS_PRODUCT_NAME
}
