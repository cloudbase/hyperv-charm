#
# Copyright 2015-2016 Cloudbase Solutions Srl
#

$ErrorActionPreference = 'Stop'

Import-Module JujuUtils
Import-Module JujuHooks
Import-Module JujuLogging
Import-Module JujuHelper
Import-Module JujuWindowsUtils
Import-Module ADCharmUtils
Import-Module Templating

$NEUTRON_GIT           = "https://github.com/openstack/neutron.git"
$NOVA_GIT              = "https://github.com/openstack/nova.git"
$NETWORKING_HYPERV_GIT = "https://github.com/openstack/networking-hyperv.git"
$COMPUTE_HYPERV_GIT    = "https://github.com/openstack/compute-hyperv.git"
$OSWIN_GIT             = "https://git.openstack.org/openstack/os-win.git"

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
$OVS_DIR                = "${env:ProgramFiles}\Cloudbase Solutions\Open vSwitch"
$OVS_VSCTL              = Join-Path $OVS_DIR "bin\ovs-vsctl.exe"
$env:OVS_RUNDIR         = Join-Path $env:ProgramData "openvswitch"
$OVS_EXT_NAME           = "Open vSwitch Extension"
$INTERFACES_TEMPLATE    = Join-Path $CONFIG_DIR "interfaces.template"
$POLICY_FILE            = Join-Path $CONFIG_DIR "policy.json"
$MKISO_EXE              = Join-Path $BIN_DIR "mkisofs.exe"
$QEMU_IMG_EXE           = Join-Path $BIN_DIR "qemu-img.exe"

function Get-TemplatesDir {
    return (Join-Path (Get-JujuCharmDir) "templates")
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


function Get-SystemContext {
    $systemCtxt = @{
        "instances_path"      = $INSTANCES_DIR;
        "interfaces_template" = $INTERFACES_TEMPLATE;
        "policy_file"         = $POLICY_FILE;
        "mkisofs_exe"         = $MKISO_EXE;
        "log_directory"       = $LOG_DIR;
        "qemu_img_exe"        = $QEMU_IMG_EXE;
        "compute_driver"      = Get-ComputeDriver
        "vswitch_name"        = Get-JujuVMSwitchName
        "local_ip"            = (Get-CharmState -Namespace "hvcomputesrc" -Key "local_ip");
        "cores_count"         = (Get-WmiObject -Class Win32_ComputerSystem | select -ExpandProperty "NumberOfLogicalProcessors")
        "etc_directory"       = $CONFIG_DIR;
        "bin_directory"       = $BIN_DIR;
    }
    return $systemCtxt
}


function Get-CharmServices {
    $services = @{
        'nova' = @{
            'description'  = "OpenStack nova Compute Service";
            'binary' = Join-Path $PYTHON_DIR "Scripts\nova-compute.exe";
            'config' = Join-Path $CONFIG_DIR "nova.conf";
            'template' = Join-Path (Get-TemplatesDir) "nova.conf";
            'service_name' = 'nova-compute';
            "context_generators" = @(
                @{
                    "generator" = "Get-DevStackContext";
                    "relation"  = "devstack";
                },
                @{
                    "generator" = "Get-SystemContext";
                    "relation"  = "system";
                }
            );
        };
        'neutron' = @{
            'description' = "OpenStack Neutron Hyper-V Agent Service";
            'binary' = (Join-Path $PYTHON_DIR "Scripts\neutron-hyperv-agent.exe");
            'config' = (Join-Path $CONFIG_DIR "neutron_hyperv_agent.conf");
            'template' = Join-Path (Get-TemplatesDir) "neutron_hyperv_agent.conf";
            'service_name' = "neutron-hyperv-agent";
            "context_generators" = @(
                @{
                    "generator" = "Get-DevStackContext";
                    "relation"  = "devstack";
                },
                @{
                    "generator" = "Get-SystemContext";
                    "relation"  = "system";
                }
            );
        };
        'neutron-ovs' = @{
            'description' = "OpenStack Neutron Open vSwitch Agent Service";
            'binary' = (Join-Path $PYTHON_DIR "Scripts\neutron-openvswitch-agent.exe");
            'config' = (Join-Path $CONFIG_DIR "ml2_conf.ini");
            'template' = Join-Path (Get-TemplatesDir) "ml2_conf.ini";
            'service_name' = "neutron-openvswitch-agent";
            "context_generators" = @(
                @{
                    "generator" = "Get-DevStackContext";
                    "relation"  = "devstack";
                },
                @{
                    "generator" = "Get-SystemContext";
                    "relation"  = "system";
                }
            );
        }
    }
    return $services
}


function Write-ConfigFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )
    $JujuCharmServices = Get-CharmServices
    $should_restart = $true
    $service = $JujuCharmServices[$ServiceName]
    if (!$service){
        Write-JujuWarning "No such service $ServiceName. Not generating config"
        return $false
    }
    
    # populate config with variables from context
    
    $incompleteContexts = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    $mergedContext = [System.Collections.Generic.Dictionary[string, object]](New-Object "System.Collections.Generic.Dictionary[string, object]")
    
    foreach ($context in $service['context_generators']){
        Write-JujuInfo ("Getting context for {0}" -f $context["relation"])
        $ctx = & $context["generator"]
        if (!$ctx.Count){
            # Context is empty. Probably peer not ready
            Write-JujuWarning "Context for $context is EMPTY"
            $incompleteContexts.Add($context["relation"])
            $should_restart = $false
            continue
        }
        Write-JujuInfo ("Got {0} context: {1}" -f @($context["relation"], $ctx.Keys))
        foreach ($val in $ctx.Keys) {
            $mergedContext[$val] = $ctx[$val]
        }
    }
    
    if ($incompleteContexts){
        $msg = "Incomplete relations: {0}" -f @($incompleteContexts -join ', ')
        Set-JujuStatus -Status blocked -Message $msg
    } 
    else {
        Set-JujuStatus -Status active -Message "Unit is ready"
    }
    # Any variables not available in context we remove
    $config = Invoke-RenderTemplateFromFile -Template $service["template"] -Context $mergedContext
    Set-Content $service["config"] $config
    # Restart-Service $service["service"]
    return $should_restart
}


# Returns the full path of the package after it is downloaded using
# the URL parameter (a checksum may optionally be specified). The
# package is cached on the disk until the installation successfully finishes.
# If the hook fails, on the second run this function will return the cached
# package path if checksum is given and it matches.
function Get-PackagePath {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$URL
    )

    $packagePath = Join-Path $env:TEMP $URL.Split('/')[-1]
    Start-ExecuteWithRetry {
        Invoke-FastWebRequest -Uri $URL -OutFile $packagePath | Out-Null
    } -RetryMessage "Download failed. Retrying"

    return $packagePath
}


function GitClonePull {
    Param(
        [string]$Path,
        [string]$URL,
        [string]$Branch="master"
    )

    $projectDir = $Path
    $gitPath = Join-Path $projectDir ".git"

    if (Test-Path -Path $Path) {
        rm $path -Recurse -Force -ErrorAction SilentlyContinue
    }
    Start-ExecuteWithRetry {
        Start-ExternalCommand -ScriptBlock { 
                git clone $URL $Path
                git -C $Path checkout $Branch
            }
    }
}


function Install-OpenStackProjectFromRepo {
    Param(
        [string]$ProjectPath
    )

    Start-ExternalCommand -ScriptBlock { pip install -e $ProjectPath } `
                          -ErrorMessage "Failed to install $ProjectPath from repo."
}


function GerritGitPrep {
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ZuulUrl,
        [Parameter(Mandatory=$True)]
        [string]$ZuulRef,
        [Parameter(Mandatory=$True)]
        [string]$ZuulChange,
        [Parameter(Mandatory=$True)]
        [string]$ZuulProject,
        [string]$GitOrigin,
        [string]$ZuulNewrev
    )

    if (!$ZuulRef -or !$ZuulChange -or !$ZuulProject) {
        Throw "ZUUL_REF ZUUL_CHANGE ZUUL_PROJECT are mandatory"
    }
    if (!$ZuulUrl) {
        Throw "The zuul site name (eg 'http://zuul.openstack.org/p') must be the first argument."
    }
    if (!$GitOrigin -or !$ZuulNewrev) {
        $GitOrigin="$ZuulUrl"
    }

    Write-JujuLog "Triggered by: $ZuulUrl/$ZuulChange"

    if (!(Test-Path -Path $BUILD_DIR -PathType Container)) {
        mkdir $BUILD_DIR
    }

    $projectDir = Join-Path $BUILD_DIR $ZuulProject
    $gitmodulesDir = Join-Path $projectDir ".gitmodules"
    if (!(Test-Path -Path $projectDir -PathType Container)) {
        mkdir $projectDir
        try {
            Start-ExternalCommand -ScriptBlock { git clone "$GitOrigin/$ZuulProject" $projectDir } `
                                  -ErrorMessage "Failed to clone $GitOrigin/$ZuulProject"
        } catch {
            rm -Recurse -Force $projectDir
            Throw $_
        }
    }

    Start-ExternalCommand { git -C $projectDir remote set-url origin "$GitOrigin/$ZuulProject" } `
        -ErrorMessage "Failed to set origin: $GitOrigin/$ZuulProject"

    try {
        Start-ExternalCommand { git -C $projectDir remote update } -ErrorMessage "Failed to update remote"
    }
    catch {
        Write-JujuLog "The remote update failed, so garbage collecting before trying again."
        Start-ExternalCommand {
                git -C $projectDir gc
                git -C $projectDir remote update
            }
    }

    Start-ExternalCommand { git -C $projectDir reset --hard } -ErrorMessage "Failed to git reset"
    try {
        Start-ExternalCommand { git -C $projectDir clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }
    catch {
        sleep 1
        Start-ExternalCommand { git -C $projectDir clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }

    echo "Before doing git checkout:"
    echo "Git branch output:"
    Start-ExternalCommand { git -C $projectDir branch } -ErrorMessage "Failed to show git branch."
    echo "Git log output:"
    Start-ExternalCommand { git -C $projectDir log -10 --pretty=format:"%h - %an, %ae, %ar : %s" } `
        -ErrorMessage "Failed to show git log."

    $ret = echo "$ZuulRef" | Where-Object { $_ -match "^refs/tags/" }
    if ($ret) {
        Start-ExternalCommand {
                git -C $projectDir fetch --tags "$ZuulUrl/$ZuulProject"
                git -C $projectDir checkout $ZuulRef
                git -C $projectDir reset --hard $ZuulRef
            }
    }
    elseif (!$ZuulNewrev) {
        Start-ExternalCommand {
                git -C $projectDir fetch "$ZuulUrl/$ZuulProject" $ZuulRef
                git -C $projectDir checkout FETCH_HEAD
                git -C $projectDir reset --hard FETCH_HEAD
            }
    }
    else {
        Start-ExternalCommand {
                git -C $projectDir checkout $ZuulNewrev
                git -C $projectDir reset --hard $ZuulNewrev
            }
    }

    try {
        Start-ExternalCommand { git -C $projectDir clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    } catch {
        sleep 1
        Start-ExternalCommand { git -C $projectDir clean -x -f -d -q } -ErrorMessage "Failed to git clean"
    }

    if (Test-Path $gitmodulesDir) {
        Start-ExternalCommand { 
                git -C $projectDir submodule init
                git -C $projectDir submodule sync
                git -C $projectDir submodule update --init
            }
    }

    echo "Final result:"
    echo "Git branch output:"
    Start-ExternalCommand { git -C $projectDir branch } -ErrorMessage "Failed to show git branch."
    echo "Git log output:"
    Start-ExternalCommand { git -C $projectDir log -10 --pretty=format:"%h - %an, %ae, %ar : %s" } `
        -ErrorMessage "Failed to show git log."

}


function Install-Projects ($project) {
    # Shared for all projects
    #$projectDir = $buildFor -replace 'openstack/'
    $projectDir = Split-Path -Path $project -Leaf
    Write-JujuLog "Installing $projectDir"
    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    Start-ExecuteWithRetry {
        Install-OpenStackProjectFromRepo "$openstackBuild\$projectDir"
    }
    
    # Individual projects
    # Nova
    if ($project -eq "openstack/nova") {
        CheckNovaHypervBin
        CopyNovaDefaultConfs
    }
    # Networking-Hyperv
    if ($project -eq "openstack/networking-hyperv") {
        CheckNeutronHypervBin
    }
}


function CheckNovaHypervBin {
    $novaBin = (Get-CharmServices)['nova']['binary']
    if (!(Test-Path $novaBin)) {
       Throw "$novaBin was not found."
    }
}


function CopyNovaDefaultConfs {
    Write-JujuLog "Copying default config files"
    $defaultConfigFiles = @('rootwrap.d', 'api-paste.ini', 'cells.json',
                                'rootwrap.conf')
    foreach ($config in $defaultConfigFiles) {
        Copy-Item -Recurse -Force "$openstackBuild\nova\etc\nova\$config" $CONFIG_DIR
    }
    Copy-Item -Force (Join-Path (Get-TemplatesDir) "policy.json") $CONFIG_DIR
    Copy-Item -Force (Join-Path (Get-TemplatesDir) "interfaces.template") $CONFIG_DIR
}


function CheckNeutronHypervBin {
    $neutronBin = (Get-CharmServices)['neutron']['binary']
    if (!(Test-Path $neutronBin)) {
        Throw "$neutronBin was not found."
    }
}


function Get-ComputeDriver {
    if ($buildFor -eq "openstack/compute-hyperv") {
        return "hyperv.nova.driver.HyperVDriver"
    }
    return "hyperv.driver.HyperVDriver"
}

function Install-NetworkType {
    $buildFor = Get-JujuCharmConfig -Scope 'zuul-project'
    $networkType = Get-JujuCharmConfig -Scope 'network-type'
    if (($networkType -eq 'ovs') -and ($buildFor -eq 'openstack/networking-hyperv')) {
        Throw "'$networkType' cannot be used when building for '$buildFor'"
    }
    if ($networkType -eq 'hyperv') {
#        Install-NetworkingHyperV
        Install-Projects "openstack/networking-hyperv"
    }
    elseif ($networkType -eq 'ovs') {
        Check-OVSPrerequisites
        Enable-OVS
        Ensure-InternalOVSInterfaces
    }
    else {
        Throw "Wrong network type config: '$networkType'"
    }
}


function Install-OVS {
    param(
        [Parameter(Mandatory=$true)]
        [string]$InstallerPath
    )

    Write-JujuInfo "Running OVS install"
    $ovs_name = "open vswitch"
    if (Get-ComponentIsInstalled -Name $ovs_name){
        Write-JujuInfo "OVS is already installed"
        return $true
    }

    if(!(Test-Path $InstallerPath)){
        $InstallerPath = Get-OVSInstaller
    }

    Write-JujuInfo "Installing from $InstallerPath"
    $logFile = Join-Path $env:APPDATA "ovs-installer-log.txt"
    $extraParams = @("INSTALLDIR=`"$OVS_DIR`"")
    Install-Msi -Installer $installerPath -LogFilePath $logFile -ExtraArgs $extraParams
    Remove-Item $InstallerPath
    return $true
}


function Import-OVSCertificate {
	param(
        [string]$CertificatePath
    )
    if (!(Test-Path $CertificatePath)) {
        $CertificatePath = Get-OVSCertificate
    }
    Write-JujuInfo "Importing certificate from $CertificatePath"
    Import-Certificate $CertificatePath -StoreLocation LocalMachine -StoreName TrustedPublisher
    Import-Certificate $CertificatePath -StoreLocation LocalMachine -StoreName Root
    Remove-Item $CertificatePath
    return $true
}


function Get-OVSInstaller {
    $ovsinstallerURL = Get-JujuCharmConfig -Scope 'ovs-installer-url'
    $location = Get-PackagePath $ovsinstallerURL
    return $location
}

function Get-OVSCertificate {
    $ovscertURL = Get-JujuCharmConfig -Scope 'ovs-certificate-url'
    $location = Get-PackagePath $ovscertURL
    return $location
}

function Check-OVSPrerequisites {
    try {
        $ovsdbSvc = Get-Service "ovsdb-server"
        $ovsSwitchSvc = Get-Service "ovs-vswitchd"
    } catch {
        $driverCertificate = Get-JujuCharmConfig -Scope "ovs-certificate-url"
        if ($driverCertificate) {
            $CertificatePath = Get-OVSCertificate
            Import-OVSCertificate $CertificatePath
        }
        else {
            Write-JujuLog "No OVS driver certificate specified. Be sure to use an offically signed driver."
        }
        $InstallerPath = Get-OVSInstaller
        Install-OVS $InstallerPath
    }
    if(!(Test-Path $OVS_VSCTL)){
        Throw "Could not find ovs-vsctl.exe in location: $OVS_VSCTL"
    }
}


function Enable-OVSExtension {
    $ext = Get-OVSExtStatus
    if (!$ext){
       Throw "Cannot enable OVS extension. Not installed"
    }
    if (!$ext.Enabled) {
        Enable-VMSwitchExtension $OVS_EXT_NAME $ext.SwitchName
    }
    return $true
}


function Get-OVSExtStatus {
    $br = Get-JujuVMSwitchName
    Write-JujuInfo "Switch name is $br"
    $ext = Get-VMSwitchExtension -VMSwitchName $br -Name $OVS_EXT_NAME

    if (!$ext){
        Write-JujuInfo "Open vSwitch extension not installed"
        return $null
    }

    return $ext
}


function Enable-Service {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$ServiceName
    )

    Get-Service $ServiceName | Set-Service -StartupType Automatic
}


function Set-HyperVMACS {
    $b1 = "0x{0:x}" -f (get-random -minimum 1 -maximum 255)
    $b2 = "0x{0:x}" -f (get-random -minimum 1 -maximum 255)
    $reg = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Virtualization"
    set-ItemProperty -path $reg -name minimummacaddress -type binary -value ([byte[]](0x00,0x15,0x5d,$b1,$b2,0x00))
    set-ItemProperty -path $reg -name maximummacaddress -type binary -value ([byte[]](0x00,0x15,0x5d,$b1,$b2,0xff))
}


function Enable-OVS {
    Start-ExternalCommand { pip install -U "ovs" } -ErrorMessage "Failed to install $ovs_pip"
    
    Start-ExternalCommand { cmd.exe /c "sc triggerinfo ovs-vswitchd start/strcustom/6066F867-7CA1-4418-85FD-36E3F9C0600C/VmmsWmiEventProvider" } -ErrorMessage "Failed to modify ovs-vswitchd service."
    Start-ExternalCommand { cmd.exe /c "sc config ovs-vswitchd start=demand" } -ErrorMessage "Failed to modify ovs-vswitchd service."

    Enable-OVSExtension

    Enable-Service "ovsdb-server"
    #Enable-Service "ovs-vswitchd"

    Start-Service "ovsdb-server"
    #Start-Service "ovs-vswitchd"
}


function Ensure-InternalOVSInterfaces {
    $ifIndex = Get-CharmState -Namespace "hvcomputesrc" -Key "dataNetworkIfindex"
    $lip = Get-CharmState -Namespace "hvcomputesrc" -Key "local_ip"
    $ifName = (Get-NetAdapter -ifindex $ifIndex).Name
    $lip_mask = Get-CharmState -Namespace "hvcomputesrc" -Key "local_ip_mask"

    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-br", "juju-br")
    Invoke-JujuCommand -Command @($ovs_vsctl, "--may-exist", "add-port", "juju-br", $ifName)

    Restart-Service "ovs-vswitchd"
    Enable-NetAdapter -Name "juju-br" -Confirm:$false

    New-NetIPAddress -interfacealias "juju-br" -AddressFamily "ipv4" -IPAddress $lip -PrefixLength $lip_mask
    Set-CharmState -Namespace "hvcomputesrc" -Key "local_ip" -Value $lip
    return
}
 

function Get-CherryPicksObject {
    $cfgOption = Get-JujuCharmConfig -Scope 'cherry-picks'
    if (!$cfgOption) {
        return @{}
    }
    $ret = @{
        'nova' = @();
        'networking-hyperv' = @();
        'compute-hyperv' = @();
        'neutron' = @();
        'os-win' = @()
    }
    $splitCfgOption = $cfgOption.Split(',')
    $validProjects = @('nova', 'networking-hyperv', 'neutron', 'compute-hyperv', 'os-win')
    foreach ($item in $splitCfgOption) {
        $splitItem = $item.Split('|')
        if ($splitItem.Count -ne 3) {
            Throw "ERROR: Wrong 'cherry-picks' config option format"
        }
        $projectName = Split-Path -Path $splitItem[0] -Leaf
        if ($projectName -notin $validProjects) {
            Throw "ERROR: Invalid git project name '$projectName'"
        }
        $ret[$projectName] += @{
            'git_url' = $splitItem[0];
            'branch_ref' = $splitItem[1];
            'branch' = $splitItem[2]
        }
    }
    return $ret
}


function Initialize-GitRepository {
    Param(
        [string]$BuildFolder,
        [string]$GitURL,
        [string]$BranchName,
        [array]$CherryPicks=@()
    )

    Write-JujuLog "Cloning $GitURL from $BranchName"
    Start-ExecuteWithRetry { GitClonePull $BuildFolder $GitURL $BranchName }
    foreach ($commit in $CherryPicks) {
        Write-JujuLog ("Cherry-picking commit {0} from {1}, branch {2}" -f
                       @($commit['branch_ref'], $commit['git_url'], $commit['branch']))
        if ($commit['branch'] -ne $BranchName) {
            Write-JujuWarning "The cherry-pick patch is not in branch $BranchName. Not running cherry-pick."
            return
        }
        try {
            Start-ExternalCommand -ScriptBlock {
                git -C $BuildFolder fetch $commit['git_url'] $commit['branch_ref']
                git -C $BuildFolder cherry-pick FETCH_HEAD
            }
        }
        catch {
            # If cherry-pick fails return to previous state.
            Write-JujuWarning ("Cherry-pick for {0} failed. Reverting to the previous state.Error: $_" -f
                              @($commit['branch_ref']))
            Start-ExternalCommand -ScriptBlock {
                git cherry-pick --abort
            }
        }
    }
}


function Initialize-GitRepositories {
    Param(
        [ValidateSet("hyperv", "ovs")]
        [string]$NetworkType,
        [string]$BranchName,
        [string]$BuildFor
    )

    Write-JujuLog "Cloning the required Git repositories"
    
    $cherryPicks = Get-CherryPicksObject
    $openstackBuild = Join-Path $BUILD_DIR "openstack"
    if ($NetworkType -eq 'hyperv') {
        if ($BuildFor -ne "openstack/networking-hyperv") {
                Initialize-GitRepository "$openstackBuild\networking-hyperv" $NETWORKING_HYPERV_GIT "master" $cherryPicks['networking-hyperv']
        }
    }

    if ($BuildFor -ne "openstack/nova") {
            Initialize-GitRepository "$openstackBuild\nova" $NOVA_GIT $BranchName $cherryPicks['nova']
    }
    
    if ($BuildFor -ne "openstack/neutron") {
            Initialize-GitRepository "$openstackBuild\neutron" $NEUTRON_GIT $BranchName $cherryPicks['neutron']
    }
    
    if ($BuildFor -ne "openstack/os-win") {
            Initialize-GitRepository "$openstackBuild\os-win" $OSWIN_GIT "master" $cherryPicks['os-win']
    }
}


function Initialize-Environment {
    Param(
        [string]$BranchName='master',
        [string]$BuildFor
    )

    $dirs = @($CONFIG_DIR, $BIN_DIR, $INSTANCES_DIR, $LOG_DIR, $SERVICE_DIR)
    foreach($dir in $dirs) {
        if (!(Test-Path $dir)) {
            Write-JujuLog "Creating $dir folder."
            mkdir $dir
        }
    }

    $mkisofsPath = Join-Path $BIN_DIR "mkisofs.exe"
    $qemuimgPath = Join-Path $BIN_DIR "qemu-img.exe"
    if (!(Test-Path $mkisofsPath) -or !(Test-Path $qemuimgPath)) {
        Write-JujuLog "Extracting OpenStack binaries"
        $zipPath = Join-Path $FILES_DIR "openstack_bin.zip"
        Expand-ZipArchive $zipPath $BIN_DIR
    }
  
    $networkType = Get-JujuCharmConfig -Scope 'network-type'
    Initialize-GitRepositories $networkType $BranchName $BuildFor

    $standardProjects = 'openstack/nova', 'openstack/neutron', 'openstack/os-win'
    if ($buildFor -in $standardProjects) {
        $defaultProjects = $standardProjects -notmatch $buildFor
        foreach ($project in $defaultProjects) {
            Install-Projects $project
        }
        Install-NetworkType
        Install-Projects $buildFor
    }
    else {
        foreach ($project in $standardProjects) {
            Install-Projects $project
        }
        Install-NetworkType
        if (($buildFor -ne "none") -and ($buildFor -ne "openstack/networking-hyperv")) {
            Install-Projects $buildFor
        }
    }

    Write-JujuLog "Environment initialization done."
}


function New-OpenStackService {
    Param(
        [string]$ServiceName,
        [string]$ServiceDescription,
        [string]$ServiceExecutable,
        [string]$ServiceConfig,
        [string]$ServiceUser,
        [string]$ServicePassword
    )

    $filter = "Name='{0}'" -f $ServiceName

    $service = Get-WmiObject -Namespace "root\cimv2" -Class Win32_Service -Filter $filter
    if($service) {
        Write-JujuLog "Service $ServiceName is already created."
        return $true
    }

    $serviceFileName = "OpenStackService.exe"
    if(!(Test-Path "$SERVICE_DIR\$serviceFileName")) {
        Copy-Item "$FILES_DIR\$serviceFileName" "$SERVICE_DIR\$serviceFileName"
    }

    New-Service -Name "$ServiceName" -DisplayName "$ServiceName" -Description "$ServiceDescription" -StartupType "Manual" `
                -BinaryPathName "$SERVICE_DIR\$serviceFileName $ServiceName $ServiceExecutable --config-file $ServiceConfig" `

    if((Get-Service -Name $ServiceName).Status -eq "Running") {
        Stop-Service $ServiceName
    }

    Set-ServiceLogon -Services @($ServiceName) -UserName $ServiceUser -Password $ServicePassword
}


function Watch-ServiceStatus {
    Param(
        [string]$ServiceName,
        [int]$IntervalSeconds
    )

    $count = 0
    while ($count -lt $IntervalSeconds) {
        if ((Get-Service -Name $ServiceName).Status -ne "Running") {
            $count += 1
            Start-Sleep -Seconds 1
            continue
        }
        return
    }
    Throw "$ServiceName has errors. Please check the logs."
}


function Get-JujuVMSwitchName {
    $VMswitchName = Get-JujuCharmConfig -Scope "vmswitch-name"
    if (!$VMswitchName){
        return "br100"
    }
    return $VMswitchName
}


function Get-InterfaceFromConfig {
    Param (
        [string]$ConfigOption="data-port",
        [switch]$MustFindAdapter=$false
    )

    $nic = $null
    $DataInterfaceFromConfig = Get-JujuCharmConfig -Scope $ConfigOption
    Write-JujuInfo "Looking for $DataInterfaceFromConfig"
    if (!$DataInterfaceFromConfig){
        if($MustFindAdapter) {
            Throw "No data-port was specified"
        }
        return $null
    }
    $byMac = @()
    $byName = @()
    $macregex = "^([a-f-A-F0-9]{2}:){5}([a-fA-F0-9]{2})$"
    foreach ($i in $DataInterfaceFromConfig.Split()){
        if ($i -match $macregex){
            $byMac += $i.Replace(":", "-")
        }else{
            $byName += $i
        }
    }
    if ($byMac.Length){
        $nicByMac = Get-NetAdapter | Where-Object { $_.MacAddress -in $byMac -and $_.DriverFileName -ne "vmswitch.sys" }
    }
    if ($byName.Length){
        $nicByName = Get-NetAdapter | Where-Object { $_.Name -in $byName }
    }
    if ($nicByMac -ne $null -and $nicByMac.GetType() -ne [System.Array]){
        $nicByMac = @($nicByMac)
    }
    if ($nicByName -ne $null -and $nicByName.GetType() -ne [System.Array]){
        $nicByName = @($nicByName)
    }
    $ret = $nicByMac + $nicByName
    if ($ret.Length -eq 0 -and $MustFindAdapter){
        Throw "Could not find network adapters"
    }
    return $ret
}


function Get-DataPortFromDataNetwork {
    $dataNetwork = Get-JujuCharmConfig -Scope "os-data-network"
    if (!$dataNetwork) {
        Write-JujuInfo "os-data-network is not defined"
        return $false
    }

    $local_ip = Get-CharmState -Namespace "hvcomputesrc" -Key "local_ip"
    $ifIndex = Get-CharmState -Namespace "hvcomputesrc" -Key "dataNetworkIfindex"

    if($local_ip -and $ifIndex){
        if((Confirm-LocalIP -IPaddress $ifIndex -ifIndex $ifIndex)){
            return Get-NetAdapter -ifindex $ifIndex
        }
    }

    # If there is any network interface configured to use DHCP and did not get an IP address
    # we manually renew its lease and try to get an IP address before searching for the data network
    $interfaces = Get-CimInstance -Class win32_networkadapterconfiguration | Where-Object { 
        $_.IPEnabled -eq $true -and $_.DHCPEnabled -eq $true -and $_.DHCPServer -eq "255.255.255.255"
    }
    if($interfaces){
        $interfaces.InterfaceIndex | Invoke-DHCPRenew -ErrorAction SilentlyContinue
    }
    $netDetails = $dataNetwork.Split("/")
    $decimalMask = ConvertTo-Mask $netDetails[1]

    $configuredAddresses = Get-NetIPAddress -AddressFamily IPv4
    foreach ($i in $configuredAddresses) {
        Write-JujuInfo ("Checking {0} on interface {1}" -f @($i.IPAddress, $i.InterfaceAlias))
        if ($i.PrefixLength -ne $netDetails[1]){
            continue
        }
        $network = Get-NetworkAddress $i.IPv4Address $decimalMask
        Write-JujuInfo ("Network address for {0} is {1}" -f @($i.IPAddress, $network))
        if ($network -eq $netDetails[0]){
            Set-CharmState -Namespace "hvcomputesrc" -Key "local_ip_mask" -Value $i.PrefixLength
            Set-CharmState -Namespace "hvcomputesrc" -Key "local_ip" -Value $i.IPAddress
            Set-CharmState -Namespace "hvcomputesrc" -Key "dataNetworkIfindex" -Value $i.IfIndex
            return Get-NetAdapter -ifindex $i.IfIndex
        }
    }
    return $false
}


function Get-RealInterface {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Microsoft.Management.Infrastructure.CimInstance]$interface
    )
    PROCESS {
        if($interface.DriverFileName -ne "vmswitch.sys") {
            return $interface
        }
        $realInterface = Get-NetAdapter | Where-Object {
            $_.MacAddress -eq $interface.MacAddress -and $_.ifIndex -ne $interface.ifIndex
        }

        if(!$realInterface){
            Throw "Failed to find interface attached to VMSwitch"
        }
        return $realInterface[0]
    }
}


function Get-FallbackNetadapter {
    $name = Get-MainNetadapter
    $net = Get-NetAdapter -Name $name
    return $net
}


function Get-OVSDataPort {
    $dataPort = Get-DataPortFromDataNetwork
    if ($dataPort){
        return Get-RealInterface $dataPort
    }else{
        $port = Get-FallbackNetadapter
        $local_ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $port.IfIndex -ErrorAction SilentlyContinue
        if(!$local_ip){
            Throw "failed to get fallback adapter IP address"
        }
        Set-CharmState -Namespace "hvcomputesrc" -Key "local_ip_mask" -Value $i.PrefixLength
        Set-CharmState -Namespace "hvcomputesrc" -Key "local_ip" -Value $local_ip[0]
        Set-CharmState -Namespace "hvcomputesrc" -Key "dataNetworkIfindex" -Value $port.IfIndex
    }

    return Get-RealInterface $port
}


function Get-DataPort {
    $managementOS = Get-JujuCharmConfig -Scope "vmswitch-management"
    $networkType = Get-JujuCharmConfig -Scope 'network-type'

    if ($networkType -eq "ovs"){
        Write-JujuInfo "Trying to fetch OVS data port"
        $dataPort = Get-OVSDataPort
        return @($dataPort[0], $managementOS)
    }

    Write-JujuInfo "Trying to fetch data port from config"
    $nic = Get-InterfaceFromConfig
    if(!$nic) {
        $nic = Get-FallbackNetadapter
        $managementOS = $true
    }
    $nic = Get-RealInterface $nic[0]
    return @($nic, $managementOS)
}


function ConfigureVMSwitch {
    $VMswitchName = Get-JujuVMSwitchName
    $vmswitch = Get-VMSwitch -SwitchType External -Name $VMswitchName -ErrorAction SilentlyContinue

    if($vmswitch){
        return $true
    }

    Set-HyperVMACS

    $dataPort, $managementOS = Get-DataPort
    $VMswitches = Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue
    if ($VMswitches -and $VMswitches.Count -gt 0){
        foreach($i in $VMswitches){
            if ($i.NetAdapterInterfaceDescription -eq $dataPort.InterfaceDescription) {
                Rename-VMSwitch $i -NewName $VMswitchName
                Set-VMSwitch -Name $VMswitchName -AllowManagementOS $managementOS
                return $true
            }
        }
    }

    Write-JujuInfo "Adding new vmswitch: $VMswitchName"
    New-VMSwitch -Name $VMswitchName -NetAdapterName $dataPort.Name -AllowManagementOS $managementOS
    return $true
}


function Install-VC2012 {
    $vcURL = Get-JujuCharmConfig -Scope 'vc-2012-url'
    $installerPath = Get-PackagePath $vcURL
    $ArgumentList = @("/q")
    Write-JujuWarning "Installing VC2012 from '$installerPath'"

    $stat = Start-Process -FilePath $installerPath -ArgumentList $ArgumentList `
                           -PassThru -Wait
    if ($stat.ExitCode -ne 0) {
        throw "Package '$URL' failed to install."
    }
    Remove-Item $installerPath
 
    Write-JujuLog "Finished installing VC2012."
}


function Install-Git {
    $gitURL = Get-JujuCharmConfig -Scope 'git-url'
    $installerPath = Get-PackagePath $gitURL
    $ArgumentList = @("/SILENT")
    Write-JujuLog "Installing Git from '$installerPath'"

    $stat = Start-Process -FilePath $installerPath -ArgumentList $ArgumentList `
                           -PassThru -Wait
    if ($stat.ExitCode -ne 0) {
        throw "Package '$URL' failed to install."
    }
    Remove-Item $installerPath
 
    Write-JujuLog "Finished installing Git."
}


function Install-Python27 {
    $pythonURL = Get-JujuCharmConfig -Scope 'python27-url'
    $installerPath = Get-PackagePath $pythonURL
    Write-JujuLog "Installing Python27 from '$installerPath'"

    $logFile = Join-Path $env:APPDATA "python-installer-log.txt"
    $extraParams = @("/qn")
    Install-Msi -Installer $installerPath -LogFilePath $logFile -ExtraArgs $extraParams

    Write-JujuLog "Finished installing Python27."
}


function Install-Pip {
    Write-JujuLog "Installing pip"
    $pipURL = "https://bootstrap.pypa.io/get-pip.py"
    $installerPath = Get-PackagePath $pipURL
    $conf_pip_version = Get-JujuCharmConfig -Scope 'pip-version'
    Start-ExternalCommand -ScriptBlock { python $installerPath $conf_pip_version } -ErrorMessage "Failed to install pip."
    Remove-Item $installerPath
    $version = Start-ExternalCommand { pip.exe --version } -ErrorMessage "Failed to get pip version."
    Write-JujuLog "Pip version: $version"
}


function Install-PipDependencies {
    Write-JujuLog "Installing pip dependencies"
    $pythonPkgs = Get-JujuCharmConfig -Scope 'extra-python-packages'
    if ($pythonPkgs) {
        $pkgsTXT = Join-Path $env:TEMP 'extrapypkg.txt'
        $pythonPkgsArr = $pythonPkgs.Split()
        Set-Content -Path $pkgsTXT -Value $pythonPkgsArr
        Write-JujuLog "Installing $pythonPkgsArr"
        Start-ExternalCommand -ScriptBlock { pip install -r $pkgsTXT } `
                                -ErrorMessage "Failed to install extra python packages"
        Remove-Item -Force -Path $pkgsTXT
    }
}


function Install-PosixLibrary {
    Write-JujuLog "Installing posix_ipc library"
    $zipPath = Join-Path $FILES_DIR "posix_ipc.zip"
    $posixIpcEgg = Join-Path $LIB_DIR "posix_ipc-0.9.8-py2.7.egg-info"
    if (!(Test-Path $posixIpcEgg)) {
        Expand-ZipArchive $zipPath $LIB_DIR
    }
}


function Install-PyWin32 {
    Write-JujuLog "Installing pywin32"
    Start-ExternalCommand -ScriptBlock { pip install pywin32 } `
                          -ErrorMessage "Failed to install pywin32."
    Start-ExternalCommand {
        python "$PYTHON_DIR\Scripts\pywin32_postinstall.py" -install
    } -ErrorMessage "Failed to run pywin32_postinstall.py"
}


function Install-FreeRDPConsole {
    Write-JujuLog "Installing FreeRDP"

    Install-VC2012

    $freeRDPZip = Join-Path $FILES_DIR "FreeRDP_powershell.zip"
    $charmLibDir = Join-Path (Get-JujuCharmDir) "lib"
    Expand-ZipArchive $freeRDPZip $charmLibDir

    # Copy wfreerdp.exe and DLL file to Windows folder
    $freeRDPFiles = @('wfreerdp.exe', 'libeay32.dll', 'ssleay32.dll')
    $windows = Join-Path $env:SystemDrive "Windows"
    foreach ($file in $freeRDPFiles) {
        Copy-Item "$charmLibDir\FreeRDP\$file" $windows
    }

    $freeRDPModuleFolder = Join-Path $windows "system32\WindowsPowerShell\v1.0\Modules\FreeRDP"
    if (!(Test-Path $freeRDPModuleFolder)) {
        mkdir $freeRDPModuleFolder
    }
    Copy-Item "$charmLibDir\FreeRDP\FreeRDP.psm1" $freeRDPModuleFolder
    Remove-Item -Recurse "$charmLibDir\FreeRDP"

    Write-JujuLog "Finished installing FreeRDP."
}


function Write-PipConfigFile {
    $pipDir = Join-Path $env:APPDATA "pip"
    if (Test-Path $pipDir){
        Remove-Item -Force -Recurse $pipDir
    }

    $pypiMirror = Get-JujuCharmConfig -scope 'pypi-mirror'
    if ($pypiMirror -eq $null -or $pypiMirror.Length -eq 0) {
        Write-JujuLog ("pypi-mirror config is not present. " +
                       "Will not generate the pip.ini file.")
        return
    }
    mkdir $pipDir
    $pipIni = Join-Path $pipDir "pip.ini"
    New-Item -ItemType File $pipIni

    $mirrors = $pypiMirror.Split()
    $hosts = @()
    foreach ($i in $mirrors){
        $h = ([System.Uri]$i).Host
        if ($h -in $hosts) {
            continue
        }
        $hosts += $h
    }

    Set-IniFileValue "index-url" "global" $mirrors[0] $pipIni
    if ($mirrors.Length -gt 1){
        Set-IniFileValue "extra-index-url" "global" ($mirrors[1..$mirrors.Length] -Join " ") $pipIni
    }
    Set-IniFileValue "trusted-host" "install" ($hosts -Join " ") $pipIni
}


function Get-HypervADUser {
    $adUsername = Get-JujuCharmConfig -scope 'ad-user-name'
    if (!$adUsername) {
        $adUsername = "hyper-v-user"
    }
    return $adUsername
}


function Set-DevStackRelationParams {
    Param(
        [HashTable]$RelationParams
    )

    $rids = Get-JujuRelationIds -Relation "devstack"
    foreach ($rid in $rids) {
        try {
            Set-JujuRelation -Settings $RelationParams -RelationId $rid
        } catch {
            Write-JujuError "Failed to set DevStack relation parameters."
        }
    }
}


function Import-CloudbaseCert {
    $crt = Join-Path $FILES_DIR "Cloudbase_signing.cer"
    if (!(Test-Path $crt)){
        return $false
    }
    Import-Certificate $crt -StoreLocation LocalMachine -StoreName TrustedPublisher
}


function Set-AD2DevstackCreds {
    $adUserCred = @{
        'domain'   = $adCtx["domainName"];
        'username' = $adCtx['adcredentials'][0]['username'];
        'password' = $adCtx['adcredentials'][0]['password']
    }
    $relationParams = @{'ad_credentials' = (Get-MarshaledObject $adUserCred);}
    Set-DevStackRelationParams $relationParams
}


function Join-ADDomain {
    $adCtx = Get-ActiveDirectoryContext
    if (Confirm-IsInDomain $adCtx["domainName"]) {
        # Add AD user to local Administrators group
            Start-ExecuteWithRetry {
                Grant-PrivilegesOnDomainUser -Username $adCtx['adcredentials'][0]['username']
            }
            Enable-LiveMigration
    }
    else {
        Start-JoinDomain
    }
}


function Enable-LiveMigration {
    Write-JujuLog "Enabling live migration"
    Enable-VMMigration
    $name = Get-MainNetadapter
    $netAddresses = Get-NetIPAddress -InterfaceAlias $name -AddressFamily IPv4
    foreach($netAddress in $netAddresses) {
        $prefixLength = $netAddress.PrefixLength
        $netmask = ConvertTo-Mask -MaskLength $prefixLength
        $networkAddress = Get-NetworkAddress -IPAddress $netAddress.IPAddress -SubnetMask $netmask
        $migrationNet = Get-VMMigrationNetwork | Where-Object { $_.Subnet -eq "$networkAddress/$prefixLength" }
        if (!$migrationNet) {
            Add-VMMigrationNetwork -Subnet "$networkAddress/$prefixLength" -Confirm:$false
        }
    }
}


# HOOKS FUNCTIONS

function Invoke-InstallHook {
    # Set machine to use high performance settings.
    try {
        Set-PowerProfile -PowerProfile Performance
    } catch {
        # No need to error out the hook if this fails.
        Write-JujuWarning "Failed to set power scheme."
    }

    Start-TimeResync

    # Set Administrator user password
    $admin_user = "Administrator"
    $admin_password = Get-JujuCharmConfig -Scope 'administrator-password'
    net user $admin_user "$admin_password"
    
    # Install Hyperv feature if not present
    if (!(Get-WindowsFeature hyper-v).Installed) {
        Install-WindowsFeature -Name Hyper-V -includemanagementtools
        #Invoke-JujuReboot -Now
    }
    
    # Allow self-signed drivers installation
    $bcdedit = "C:\bcdedit.txt"
    $signingStatus = Get-JujuCharmConfig -Scope "test-signing"
    if ((!(Test-Path -path $bcdedit)) -and ($signingStatus)){
        bcdedit -set loadoptions DDISABLE_INTEGRITY_CHECKS
        bcdedit -set TESTSIGNING ON
        New-Item -ItemType file $bcdedit
        Write-JujuLog "Restarting in order to enable test signing."
        Invoke-JujuReboot -Now
    }
    

    # Disable firewall
    Start-ExternalCommand { netsh.exe advfirewall set allprofiles state off } -ErrorMessage "Failed to disable firewall."
    # Disable automatic updates
    Write-JujuLog "Disabling automatic updates"
    $update_service = Get-WmiObject Win32_Service -Filter 'Name="wuauserv"'
    $update_service.ChangeStartMode("Disabled")
    $update_service.StopService()

    
    Write-JujuLog "Enable and start MSiSCSI"
    $msiscsi_service = Get-WmiObject Win32_Service -Filter 'Name="MSiSCSI"'
    $msiscsi_service.ChangeStartMode("Automatic")
    $msiscsi_service.StartService()

    ConfigureVMSwitch
    Write-PipConfigFile

    # Install Git
    Install-Git
    Add-ToUserPath "${env:ProgramFiles(x86)}\Git\cmd"
    Add-ToSystemPath "${env:ProgramFiles(x86)}\Git\cmd"

    # Install Python 2.7.x (x86)
    Install-Python27
    Add-ToUserPath "${env:SystemDrive}\Python27;${env:SystemDrive}\Python27\scripts"
    Add-ToSystemPath "${env:SystemDrive}\Python27;${env:SystemDrive}\Python27\scripts"

    # Install FreeRDP Hyper-V console access
    $enableFreeRDP = Get-JujuCharmConfig -Scope 'enable-freerdp-console'
    if ($enableFreeRDP -eq $true) {
        Install-FreeRDPConsole
    }

    # Install PIP
    Install-Pip

    # Install dependencies from juju config
    Install-PipDependencies

    # Install Posix library
    Install-PosixLibrary

    # Install pip pywin32
    Install-PyWin32
    
    $zuulUrl = Get-JujuCharmConfig -Scope 'zuul-url'
    $zuulRef = Get-JujuCharmConfig -Scope 'zuul-ref'
    $zuulChange = Get-JujuCharmConfig -Scope 'zuul-change'
    $zuulProject = Get-JujuCharmConfig -Scope 'zuul-project'

    if (!$zuulProject) {
        Write-JujuLog "zuulProject is empty. Setting it to 'none'. Not running Git Prep"
        $zuulProject = "none"
    }
    else {
        GerritGitPrep -ZuulUrl $zuulUrl -ZuulRef $zuulRef `
                            -ZuulChange $zuulChange -ZuulProject $zuulProject
    }
    
    $gitEmail = Get-JujuCharmConfig -scope 'git-user-email'
    $gitName = Get-JujuCharmConfig -scope 'git-user-name'
    Start-ExternalCommand { git config --global user.email $gitEmail } `
        -ErrorMessage "Failed to set git global user.email"
    Start-ExternalCommand { git config --global user.name $gitName } `
        -ErrorMessage "Failed to set git global user.name"
    $zuulBranch = Get-JujuCharmConfig -scope 'zuul-branch'
    if (!$zuulBranch) {
        Write-JujuLog "zuulBranch is empty. Setting branch to master"
        $zuulBranch = "master"
    }

    Write-JujuLog "Initializing the environment"
    Initialize-Environment -BranchName $zuulBranch -BuildFor $zuulProject
}


function Invoke-ADRelationJoinedHook {
    $hypervADUser = Get-HypervADUser
    $userGroup = @{$hypervADUser = @("CN=Users")}
    $encUserGroup = Get-MarshaledObject $userGroup
    $constraintsList = @("Microsoft Virtual System Migration Service", "cifs")
    $relationParams = @{
        'computername' = [System.Net.Dns]::GetHostName()
        'constraints' = Get-MarshaledObject $constraintsList
        'adusers' = $encUserGroup
    }

    $rids = Get-JujuRelationIds -Relation "ad-join"
    foreach ($rid in $rids) {
        try {
            Set-JujuRelation -Settings $relationParams -RelationId $rid
        } catch {
            Write-JujuError "Failed to set AD relation parameters."
        }
    }
}


function Invoke-RelationHooks {
    $charmServices = Get-CharmServices
    $networkType = Get-JujuCharmConfig -Scope 'network-type'
    if ($networkType -eq "hyperv") {
        $charmServices.Remove('neutron-ovs')
    } elseif ($networkType -eq "ovs") {
        $charmServices.Remove('neutron')
    } else {
        Throw "ERROR: Unknown network type: '$networkType'."
    }
    
    $adCtx = Get-ActiveDirectoryContext
    
    if (!$adCtx.Count) {
        Write-JujuLog "AD context is not ready."
    }
    else {
        Join-ADDomain
        Set-AD2DevstackCreds
    }
    
    $devstackCtx = Get-DevStackContext
    
    if (!$devstackCtx.Count -or !$adCtx.Count) {
        Write-JujuLog ("Both AD context and DevStack context must be complete " +
                       "before starting the OpenStack services.")
        if (!$adCtx.Count -and !$devstackCtx.Count){
            $msg = "Waiting on AD and DevStack relations."
        }
        elseif (!$adCtx.Count) {
            $msg = "Waiting on AD relation."
        }
        else {
            $msg = "Waiting on DevStack relation."
        }
        Set-JujuStatus -Status blocked -Message $msg
    }
    else {
        # Create services and write configs.
        foreach($key in $charmServices.Keys) {
            New-OpenStackService $charmServices[$key]['service_name'] $charmServices[$key]['description'] `
                                $charmServices[$key]['binary'] $charmServices[$key]['config'] `
                                $adCtx['adcredentials'][0]['username'] `
                                $adCtx['adcredentials'][0]['password']
            Write-ConfigFile $key
        }
    
        # Start Openstack Services
        Start-Service "MSiSCSI"
        Write-JujuLog "Starting OpenStack services"
        $pollingInterval = 60
        foreach($key in $charmServices.Keys) {
            $serviceName = $charmServices[$key]['service_name']
            Write-JujuLog "Starting $serviceName service"
            Start-Service -ServiceName $serviceName
            Write-JujuLog "Polling $serviceName service status for $pollingInterval seconds."
            Watch-ServiceStatus $serviceName -IntervalSeconds $pollingInterval
        }
        Set-JujuStatus -Status active -Message "Unit is ready"
    }
}
