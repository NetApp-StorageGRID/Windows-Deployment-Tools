
param (
    [parameter(mandatory=$true, position=0)]
    [ValidateNotNullOrEmpty()]
    [string]$FilePath,

    [parameter(position=1)]
    [ValidateNotNullOrEmpty()]
    [string]$Source,

    [parameter(position=2)]
    [ValidateNotNullOrEmpty()]
    [switch]$Serial=$false,

    [parameter(position=3)]
    [ValidateNotNullOrEmpty()]
    [switch]$Validate=$false,

    [parameter(position=4)]
    [string[]]$Nodes,

    [parameter(position=5)]
    [PSObject]$ConfigData
)

$VIModules = @(
  'VMware.VimAutomation.Core',
  'VMware.VimAutomation.Vds',
  'VMware.VimAutomation.Storage'
)

# Try to load VMware PowerCLI.  No point in doing anything if that fails
$Error.Clear()
foreach ($mod in $VIModules) {
  if (!(Get-Module -Name $mod -ErrorAction SilentlyContinue)) {
    Import-Module $mod -Scope Global
    if ($Error.Count -gt 0) {
      #Try the snap in
      Add-PSSnapin $mod
      if ($Error.Count -gt 0) {
        Write-Host -ForegroundColor Red "Unable to load VMware module $mod"
        Exit 99
      }
    }
  }
}

$vmMod = Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue
if (! $vmMod) {
    $vmMod = Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
}

if ($vmMod.Version.Major -lt 5 -or ($vmMod.version.major -eq 5 -and $vmMod.version.minor -lt 5)) { #check PowerCLI version
  throw "Error: Unsupported PowerCLI version: Must be 5.5 or greater"
  Exit 99
}

if (! $ConfigData) {
  Write-Host "Using PowerCLI Version $($vmMod.Version)`n"
}

# Initialize some constants
$ValidDiskModes = @('thin', 'thick', 'eagerzeroedthick')

$ValidAdminRoles = @('primary', 'non-primary')

$OvfKeyNames = @(
  "ADMIN_IP",
  "ADMIN_NETWORK_CONFIG",
  "ADMIN_NETWORK_ESL",
  "ADMIN_NETWORK_GATEWAY",
  "ADMIN_NETWORK_IP",
  "ADMIN_NETWORK_MASK",
  "CLIENT_NETWORK_CONFIG",
  "CLIENT_NETWORK_GATEWAY",
  "CLIENT_NETWORK_IP",
  "CLIENT_NETWORK_MASK",
  "GRID_NETWORK_CONFIG",
  "GRID_NETWORK_GATEWAY",
  "GRID_NETWORK_IP",
  "GRID_NETWORK_MASK",
  "NODE_TYPE",
  "PORT_REMAP",
  "PORT_REMAP_INBOUND"
)

$NodeTypeToOvf = @{
    'VM_Storage_Node' = 'vsphere-storage.ovf';
    'VM_API_Gateway' = 'vsphere-gateway.ovf';
    'VM_Archive_Node' = 'vsphere-archive.ovf';
}

$Status = @{
  'Importing' = "Importing OVF";
  'Adding'    = "Adding hard disk {0,2}"; # It'll be a problem if this becomes longest
  'Replacing' = "Removing existing disks";
}
$Status.Add('MaxLen', ($Status.Values | Measure -Maximum -Property Length).Maximum)

# Find the OVF file for the given node type
function Get-OvfFile {
  param (
    [parameter(mandatory=$true, position=0)]
    [hashtable]$Config,

    [parameter(mandatory=$true, position=1)]
    [string]$Node,

    [parameter(mandatory=$true, position=2)]
    [string]$NodeType
  )

  if (! $NodeType) {
    throw [System.ArgumentException] "NODE_TYPE must be specified for node $Node"
  }
  if ($NodeType -eq 'VM_Admin_Node') {
    # Admin nodes have specific OVFs for Primary and Non-primary
    [string]$AdminRole = Get-Value -Config $Config -Section $Node -Name 'ADMIN_ROLE'
    if (! $ValidAdminRoles.Contains($AdminRole.ToLower())) {
      throw [System.ArgumentException] "malformed ADMIN_ROLE value '$AdminRole', must be one of " + ($ValidAdminRoles -join ', ')
    }
    if ($AdminRole.ToLower() -eq 'primary') {
      return 'vsphere-primary-admin.ovf'
    }
    else {
      return 'vsphere-non-primary-admin.ovf'
    }
  }

  # Other node types can be mapped directly
  if (! $NodeTypeToOvf.Contains($NodeType)) {
    throw [System.ArgumentException] "invalid NODE_TYPE value '$NodeType', must be one of VM_Admin_Node, " + ($NodeTypeToOvf.Keys -join ', ')
  }
  return $NodeTypeToOvf[$NodeType]
}


# Parse the INI file into nested hashtables
function Get-IniFile {
  param (
    [parameter(mandatory=$true, position=0)]
    [string]$FilePath
  )
 
  $ini = New-Object System.Collections.Specialized.OrderedDictionary
  $currentSection = New-Object System.Collections.Specialized.OrderedDictionary
  $curSectionName = "default"
  $lineno = 0
  Switch -regex (gc $FilePath) {
    ".*" {
      $lineno++
      #Write-Host "LINE ${lineno}: $_"
    }
    "^\s*$" {
      # ignore empty lines
      Continue
    }
    "^[#\;]" {
      # ignore comment lines
      Continue
    }
    "^\[(?<section>.*)\]" {
      $ini.Add($curSectionName, $currentSection)
      $curSectionName = $Matches['Section']

      if ($ini.Contains($curSectionName)) {
        throw "Duplicate node name $curSectionName at line $lineno"
      }
      $currentSection = New-Object System.Collections.Specialized.OrderedDictionary
      Continue
    }
    "(?<key>\w+)\s*\=\s*(?<value>.*)" {
      $key = $Matches['Key']
      $value = $Matches['Value']
      if ($key -eq 'DISK') {
        # DISK can have multiple entries for a node
        if ($currentSection.Contains($key)) {
          $specs = $currentSection[$key] + $value
        }
        else {
          $specs = @($value)
        }
        $value = $specs
      }
      else {
        if ($currentSection.Contains($key)) {
          throw "Duplicate option $key in section $curSectionName at line $lineno"
        }
      }
      # add to current section Hash Set
      $currentSection[$key] = $value
      Continue
    }
    default {
      throw [System.ArgumentException] "Unidentified: $_ at line $lineno"  # should not happen
    }
  }
  if ($ini.Keys -notcontains $curSectionName) { $ini.Add($curSectionName, $currentSection) }
  $ini
}

# Get a value from the configuration, using defaults
function Get-Value {
  param (
    [parameter(mandatory=$true, position=0)]
    [hashtable]$Config,

    [parameter(mandatory=$true, position=1)]
    [string]$Section,

    [parameter(mandatory=$true, position=2)]
    [string]$Name
  )

  if (!$Config.containsKey($Section)) {
    throw [System.ArgumentException] "Node '$Section' does not exist in configuration"
  }

  $value = $Config.Get_Item($Section).Get_Item($Name)
  if (!$value) { $value = $Config['default'].Get_Item($Name) }

  $value
}

# Log into the vCenter server
function Login-VIServer {
  param (
    [parameter(mandatory=$true, position=0)]
    [System.Uri]$Target,

    [parameter(mandatory=$true, position=1)]
    [string]$User,

    [parameter(mandatory=$true, position=2)]
    [string]$Password
  )

  if ($global:CurTarget -eq $Target -And $global:CurUsername -eq $User -And $global:CurPassword -eq $Password) {
    return
  }

  $global:CurTarget = $null
  $global:CurUsername = $null
  $global:CurPassword = $null
  Disconnect-VIServer -Force -Confirm:$false -ErrorAction SilentlyContinue
  Try {
    Connect-VIServer -Server $Target.Host -User $User -Password $Password -ErrorAction Stop > $null
    $global:CurTarget = $Target
    $global:CurUsername = $User
    $global:CurPassword = $Password 
    Write-Host "`nConnected to vCenter Server $defaultVIServer"
  }
  Catch {
    throw
  }
  $global:PortGroups = @{}
  Get-VDPortgroup -ErrorAction SilentlyContinue | % { $PortGroups[$_.Name] = $_ }
  Get-VirtualPortGroup -Standard -ErrorAction SilentlyContinue | % { $PortGroups[$_.Name] = $_ } 
  $global:Datastores = @{}
  Get-Datastore -ErrorAction SilentlyContinue | % { $Datastores[$_.Name] = $_ } 
}

# Set Network OvfConfiguration parameters for a given network
function Set-Network {
  param (
    [parameter(mandatory=$true, position=0)]
    [PSObject]$OvfConfig,

    [parameter(mandatory=$true, position=1)]
    [string]$Node,

    [parameter(mandatory=$true, position=2)]
    [string]$Network
  )

  # Config options use uppercase
  $netName = $Network.ToUpper()
  $netConfig = Get-Value -Config $Config -Section $Node -Name "$($netName)_NETWORK_CONFIG"

  # Grid network for vSphere only supports STATIC, and isn't normally specified in the file
  # or OVF.
  if ($netName -eq 'GRID') {
    if ($netConfig -And $netConfig -ne 'STATIC') {
      Write-Host -ForegroundColor Yellow "Overriding GRID_NETWORK_CONFIG, must be STATIC"
    }
    $netConfig = 'STATIC'
  }
  else {
    if (!$netConfig) { $netConfig = 'DISABLED' }
    $ovfConfig.Common.psobject.Members["$($netName)_NETWORK_CONFIG"].Value.Value = $netConfig
  }

  if ($netConfig -eq 'DISABLED') {
    # All interfaces must have a value, even if disabled.  Use grid network, which must be defined.
    $ovfConfig.NetworkMapping.psobject.Members["$($Network)_Network"].Value.Value = $GridPortGroup
    return
  }

  $netTarget = Get-Value -Config $Config -Section $Node -Name "$($netName)_NETWORK_TARGET"
  if (!$netTarget)   {
    throw [System.ArgumentException] "$($netName)_NETWORK_TARGET must have a value for node $Node"
  }

  # Confirm the target value is valid
  if (! $PortGroups.ContainsKey($netTarget)) {
    throw [System.ArgumentException] "$($netName)_NETWORK_TARGET value '$netTarget' doesn't exist in vSphere"
  }

  if ($netName -eq 'GRID') {
    $global:GridPortGroup = $PortGroups[$netTarget]
  }

  $ovfConfig.NetworkMapping.psobject.Members["$($Network)_Network"].Value.Value = $PortGroups[$netTarget]

  if ($netConfig -eq 'DHCP') { return }

  foreach ($opt in @('IP', 'MASK', 'GATEWAY')) {
    $fieldName = "$($netName)_NETWORK_$opt"
    $value = Get-Value -Config $Config -Section $Node -Name $fieldName
    if (!$value) {
      throw [System.ArgumentException] "$fieldName must have a value"
    }
    # Validate we have valid IP values
    Try {
      switch ($opt) {
        'IP' { $ip = [IPAddress]$value; }
        'MASK' { $mask = [IPAddress]$value; }
        'GATEWAY' { $gateway = [IPAddress]$value; }
      }
    }
    Catch {
      if ($_.FullyQualifiedErrorId -eq "InvalidCastParseTargetInvocation") {
        throw [System.ArgumentException] "Invalid IP address or mask '$value' for $fieldName"
      }
      else {
        throw
      }
    }
    $ovfConfig.Common.psobject.Members[$fieldName].Value.Value = $value
  }
  # Validate we have a valid MASK
  $mask.GetAddressBytes() | % { 
    if ([convert]::ToString($_, 2) -match '01') {
      throw [System.ArgumentException] "Invalid IP network mask '$value' for $fieldName"
    }
  }
  # Validate IP and Gateway are in the same subnet
  if (($ip.Address -band $mask.Address) -ne ($gateway.Address -band $mask.Address)) {
    throw [System.ArgumentException] "Network $netName IP and Gateway are not in the same subnet"
  }
}

# Get and populate an OvfConfiguration for deployment
function Get-OvfConfig {
  param (
    [parameter(mandatory=$true, position=0)]
    [hashtable]$Config,

    [parameter(mandatory=$true, position=1)]
    [string]$Node,

    [parameter(mandatory=$true, position=2)]
    [string]$OvfFile
  )

  $ovfConfig = Get-OvfConfiguration -Ovf $OvfFile

  $ovfConfig.Common.NODE_NAME.Value = $Node
  if ($ovfConfig.Common.psobject.properties.name -match 'ADMIN_IP')
  {
    $ovfConfig.Common.ADMIN_IP.Value = (Get-Value -Config $Config -Section $Node -Name 'ADMIN_IP')
  }
  Set-Network -OvfConfig $ovfConfig -Node $Node -Network 'Grid'
  Set-Network -OvfConfig $ovfConfig -Node $Node -Network 'Admin'
  $ovfConfig.Common.ADMIN_NETWORK_ESL.Value = (Get-Value -Config $Config -Section $Node -Name 'ADMIN_NETWORK_ESL')
  Set-Network -OvfConfig $ovfConfig -Node $Node -Network 'Client'

  $ovfConfig
}

# Parse out the value of an OVFTOOLS_ARGUMENT option
function Get-OvfArgumentValue() {
  param (
    [parameter(mandatory=$true, position=0)]
    [string[]]$OvfArguments,

    [parameter(mandatory=$true, position=1)]
    [string]$Name
  )

  $index = $OvfArguments.IndexOf($Name)
  if ($index -lt 0) { return $null }

  $value = $ovftool_arguments[$index+1] -replace "'", ""
  if (!$value)
  {
    throw [System.ArgumentException] "Malformed $Name parameter in OVFTOOL_ARGUMENTS, must be $Name=<value>"
  }
  $value
}

# Starting from the last element of the TARGET, go up until we find
# a container that has VMHosts we can deploy to.
function Find-Host {
  param (
    [parameter(mandatory=$true, position=0)]
    [PSObject]$Location
  )
  
  Try
  {
    $hosts = Get-VMHost -Location $location -State Connected -ErrorAction SilentlyContinue
  }
  Catch
  {
  }
  if ($hosts)
  {
    return $hosts | Get-Random
  }
  Find-Host -Location $Location.Parent
}


function Parse-Disk {
  param (
    [parameter(mandatory=$true, position=0)]
    [string[]]$DiskStmts,

    [parameter(mandatory=$true, position=1)]
    [string]$NodeType,

    [parameter(mandatory=$true, position=2)]
    [string]$Datastore
  )

  $instances = $null
  $capacity = $null
  $datastore = $null
  $totalInstances = 0
  $diskSpecs = @()
  # Ex:   DISK  = INSTANCES = 2 , CAPACITY = 100, DATASTORE = ds1
  $DiskStmts | %{ 
    $parts = $_ -Split ','
    if ($parts.Count -lt 2) {
      throw [System.ArgumentException] "Malformed DISK option"
    }
    $parts | %{
      $param = $_ -Split '='
      if ($param.Count -lt 2) {
        throw [System.ArgumentException] "Malformed DISK option"
      }
      $opt = $param[0].Trim().ToUpper()
      $val = $param[1].Trim()
      switch ($opt) {
        'INSTANCES' { $instances = $val; Continue }
        'CAPACITY' { $capacity = $val; Continue }
        'DATASTORE' { $datastore = $val; Continue }
        default { throw [System.ArgumentException] "Unknown DISK option $opt" }
      }
    }
    if (! $instances -Or ! $capacity) {
      throw [System.ArgumentException] "Malformed DISK option"
    }
    if (! $datastore) {
      $datastore = $Datastore
    }
    switch ($NodeType) {
      'VM_Admin_Node' {
        if ($capacity -lt 100) {
          throw [System.ArgumentException] "Admin node DISK option must have CAPACITY >= 100"
        }
      }
      'VM_Storage_Node' {
        if ($capacity -lt 50) {
          throw [System.ArgumentException] "Storage node DISK option must have CAPACITY >= 50 (production minimum is 4096)"
        }
      }
    }
    if (! $Datastores.ContainsKey($datastore)) {
      throw [System.ArgumentException] "Datastore $datastore not found"
    }
    $diskSpec = @{ 'instances' = $instances; 'capacity' = $capacity; 'datastore' = $datastore }
    $diskSpecs += $diskSpec
    $totalInstances = $totalInstances + $instances
  }

  if ($NodeType -eq 'VM_Admin_Node') {
    if ($totalInstances -ne 2) {
      throw [System.ArgumentException] "Admin node DISK option must have total INSTANCES = 2"
    }
  }
  elseif ($NodeType -eq 'VM_Storage_Node') {
    if ($totalInstances -lt 3 -Or $totalInstances -gt 16) {
      throw [System.ArgumentException] "Storage node DISK options must have total INSTANCES >= 3 and <= 16"
    }
  }
  $diskSpecs
}


function Replace-Storage {
  param (
    [parameter(mandatory=$true, position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [PSObject]$VM,

    [parameter(mandatory=$true, position=1)]
    [PSObject]$Info
  )

  $totalInstances = ($Info.DiskSpecs | Measure-Object 'instances' -Sum).Sum
  # First, remove default storage. Hard disk 1 is root - don't delete.
  # Admin nodes have 2-3, SN have 2-4.
  New-Event -SourceIdentifier StorageEvent -Sender $Info.Id -MessageData $Status.Replacing.PadRight($Status.MaxLen) -EventArguments @{
    'PercentComplete' = $(1/($totalInstances+1)*100);
    'Node' = $Info.Node;
  } > $null
  $progressPreference = 'silentlyContinue'
  $VM | Get-HardDisk -Name 'Hard disk [2-4]' | Remove-HardDisk -Confirm:$false
  $progressPreference = 'Continue'

  # Create and attach new storage
  foreach ($diskSpec in $Info.DiskSpecs) {
    $datastore = $Datastores[$diskSpec['datastore']]
    $capacity = $diskSpec['capacity']
    $instances = $diskSpec['instances']
    for ($i=1; $i -le $instances; $i++) {
      $msg = ($Status.Adding -f $i).PadRight($Status.MaxLen)
      New-Event -SourceIdentifier StorageEvent -Sender $Info.Id -MessageData $Msg -EventArguments @{
        'PercentComplete' = $(($i+1)/($totalInstances+1)*100);
        'Node' = $Info.Node;
      } > $null
      $progressPreference = 'silentlyContinue'
      $VM | New-HardDisk -CapacityGB $capacity -Datastore $datastore -Persistence persistent -StorageFormat $Info.DiskFormat -WarningAction SilentlyContinue > $null
      $progressPreference = 'Continue'
    }
  }
}


function ConfigAndStart-Node {
  param (
    [parameter(mandatory=$true, position=0)]
    [PSObject]$Config
  )

  Register-EngineEvent -SourceIdentifier StorageEvent -Forward
  if ($Config.Info) {
    Get-VM -Name $Config.Node | Replace-Storage -Info $Config.Info
  }
  if ($Config.PowerOn) {
    Get-VM -Name $Config.Node | Start-VM -Confirm:$false
  }
}

#
# MAIN
#

# Background job case
if ($ConfigData) {
  ConfigAndStart-Node -Config $ConfigData
  Exit 0
}

# Keep track of which vCenter/account we are currently logged into
# so we don't log in unnecessarily
$CurTarget = $null
$CurUsername = $null
$CurPassword = $null

$Tasks = @{}
$StorageInfo = @{}

$config = Get-IniFile $FilePath -ErrorAction Stop

if (! $Nodes) {
  $Nodes = $config.Keys
}

if (! $Validate) {
  # Register for progress events from the storage jobs
  $action = Register-EngineEvent -SourceIdentifier StorageEvent -Action {
  #  Write-Host "Progress:" $Event.SourceArgs.PercentComplete $Event.MessageData
    Write-Progress -Id $Event.Sender -Activity "Deploy Node $($Event.SourceArgs.Node)" -Status $Event.MessageData -PercentComplete $Event.SourceArgs.PercentComplete
    if ($Event.SourceArgs.PercentComplete -ge 100) {
      Start-Sleep -Seconds 2
      Write-Progress -Id $Event.Sender -Activity "Deploy Node $($Event.SourceArgs.Node)" -Completed
    }
  }

  Trap {
    $action | Remove-Job -Force
    Break
  }
}

# Deploy nodes
$ArgErrors = 0
$nodeId = 0
$error_found = $false
foreach ($node in $Nodes) {
  $script:StartTime = get-date
  if ('default' -eq $node) { continue }
  if (! $config.Contains($node)) {
    Write-Host -ForegroundColor RED "Error: Node $node not found in configuration file $Filepath"
    $error_found = $true
    Continue
  }
  if ($error_found) {
    continue
  }
  $nodeId++
  Try {
    $target = [System.Uri](Get-Value -Config $config -Section $node -Name 'TARGET')
    $leaf = Split-Path $target.AbsolutePath -Leaf
    if (! $leaf)
    {
      throw [System.ArgumentException] "Malformed TARGET, path must end in either a Cluster, VApp, or Resource Pool"
    }
 
    $username = Get-Value -Config $config -Section $node -Name 'USERNAME'
    $password = Get-Value -Config $config -Section $node -Name 'PASSWORD'

    # Doesn't log in unless necessary 
    Login-VIServer -Target $target -User $username -Password $password

    # Start building Import-VApp arguments
    $ImportArgs = @{
      'Confirm' = $false;
      'Name' = $node;
    }

    if ($Validate) {
      Write-Host "Validating $node"
    }

    # Get the location we are deploying from TARGET
    $location = Get-Inventory -Name $leaf -ErrorAction SilentlyContinue
    if (! $location)
    {
      throw [System.ArgumentException] "Malformed TARGET, path must end in either a Cluster, VApp, or Resource Pool"
    }
    $ImportArgs.Add('Location', $location)

    # Find a deployment host from location
    $vmHost = Find-Host -Location $location
    if (! $vmHost)
    {
      throw [System.ArgumentException] "Unable to find host from TARGET"
    }
    $ImportArgs.Add('VMHost', $vmHost)

    # If source isn't passed in, look for it in the config file
    if (! $source)
    {
      $source = Get-Value -Config $config -Section $node -Name 'SOURCE'
    }

    # Get the OVF file for our type and add it to source path if we have one
    # Also does NODE_TYPE validation
    $nodeType = Get-Value -Config $Config -Section $Node -Name 'NODE_TYPE'
    $ovfFile = Get-OvfFile -Config $config -Node $node -NodeType $nodeType
    if ($source)
    {
      $ovfFile = Join-Path -Path $source -ChildPath $ovfFile
    }
    $ImportArgs.Add('Source', $ovfFile)

    # Build an OvfConfiguration with our parameters
    $ovfConfig = Get-OvfConfig -Config $config -Node $node -OvfFile $ovfFile
    $ImportArgs.Add('OvfConfiguration', $ovfConfig)

    # OVFTOOL based INI files combine arguments into a single setting (alas)
    $ovftool_arguments = (Get-Value  -Config $config -Section $node -Name 'OVFTOOL_ARGUMENTS') -split '[\s=]'
 
    # Add our disk format, if specified
    $dsFormat = Get-OvfArgumentValue -OvfArguments $ovftool_arguments -Name '--diskMode'
    if (! $ValidDIskModes.Contains($dsFormat.ToLower())) { 
      throw [System.ArgumentException] "malformed --diskMode value '$dsFormat' in OVFTOOL_ARGUMENTS, must be one of " + ($ValidDiskModes -join ', ')
    }
    if ($dsFormat) {
      $ImportArgs.Add('DiskStorageFormat', $dsFormat)
    }

    # Add datastore, if specified, confirming it exists
    $dsName = Get-OvfArgumentValue -OvfArguments $ovftool_arguments -Name '--datastore'
    if ($dsName) {
      if (! $Datastores.ContainsKey($dsName)) {
        throw [System.ArgumentException] "Datastore $dsName not found"
      }
      $ImportArgs.Add('Datastore', $Datastores[$dsName])
    }

    # See if we have a DISK option.  If so, gather up storage parameters
    $diskStmts = Get-Value  -Config $config -Section $node -Name 'DISK'
    if ($diskStmts) {
      $diskSpecs = Parse-Disk -DiskStmts $diskStmts -NodeType $nodeType -Datastore $dsName
      $StorageInfo[$node] = @{
        'Node' = $node;
        'Id' = $nodeId;
        'DiskFormat' = $dsFormat;
        'Datastore' = $dsName;
        'NodeType' = $nodeType;
        'DiskSpecs' = $diskSpecs;
      }
    }

    # Don't deploy if only validating or there was an error
    if ($Validate -or $error_found) {
      Continue
    }

    Write-Host "Deploying $node to $vmHost in datastore $dsName"
    $Error.clear()
    if ($Serial -Or $Nodes.Count -eq 1) {
      #$vm = Get-VM $node
      $vm = Import-VApp @ImportArgs
      if ($Error.Count -le 0) {
        ConfigAndStart-Node -Config @{
          'Node' = $node;
          'Id' = $nodeId;
          'Info' = $StorageInfo[$node];
          'PowerOn' = ($ovftool_arguments -contains "--powerOn");
        }
      }
    }
    else {
      # Import the OVF asynchronously, keeping track of tasks.
      $task = Import-VApp @ImportArgs -RunAsync -ErrorAction Stop
      $Tasks[$node] = @{
        'Id' = $nodeId;
        'Task' = $task;
        'PowerOn' = ($ovftool_arguments -contains "--powerOn");
      }
    }
  }
  Catch [System.ArgumentException]
  {
    $ArgErrors++
    Write-Host -ForegroundColor Red "Error: $($node): $_"
  }
  Catch
  {
    if ($action) {
      $action | Remove-Job -Force
    }
    throw
  }
}

if ($Validate) {
  if ($ArgErrors -gt 0) {
    Write-Host -ForegroundColor Red "Configuration Errors Found."
  }
  else {
    Write-Host "Configuration validated."
  }
  Exit
}

if ($action -and ($Serial -or $Nodes.Count -le 1)) {
  $action | Remove-Job -Force
  Exit 0
}

# Monitor tasks

$Jobs = @()
while ($Tasks.Count -gt 0) {
  foreach ($node in $($Tasks.Keys)) {
    $task = $Tasks[$node]['Task']
    $nodeId = $Tasks[$node]['Id']
    Switch ($task.State) {
      'Success' {
        $ConfigData = @{
          'Node' = $node;
          'Id' = $nodeId;
          'Info' = $StorageInfo.Get_Item($node);
          'PowerOn' = $Tasks[$node]['PowerOn']
        }
        ConfigAndStart-Node -ConfigData $ConfigData
        #$Jobs += Start-Job -Name $node -ScriptBlock $ScriptBlock
        $Tasks.Remove($node)
        Continue
      }
      'Error' {
        $Tasks.Remove($node)
        Write-Progress -Id $nodeId -Activity "Deploy Node $node" -Completed
        Write-Host -ForegroundColor Red "Deployment failed for node ${node}: " $task.TerminatingError.Message
        Continue
      }
      default {
        Write-Progress -Id $nodeId -Activity "Deploy Node $node" -Status $Status.Importing.PadRight($Status.MaxLen) -PercentComplete $task.PercentComplete
      }
    }
  }
  if ($Tasks.Count -gt 0) {
    Start-Sleep -Seconds 5
  }
}

if (! $Jobs) {
  $action | Remove-Job -Force
  Exit 0
}

while (($Jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
  $Jobs | Receive-Job
  Start-Sleep -Seconds 3
}

Write-Host "Job Status"
$Jobs | Receive-Job -Wait -AutoRemoveJob -WriteJobInResults | % {
  if ($_.State -eq 'Completed') {
    Write-Host "Completed deployment of $($_.Name)"
  }
  else {
    Write-Host -ForegroundColor Red "Error: Deployment of $($_.Name) failed"
    $_ | fl * -Force
  }
}

$action | Remove-Job -Force
