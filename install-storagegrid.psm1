<#
  .SYNOPSIS
  Install-StorageGRID (alias Deploy-StorageGRID) installs StorageGRID Webscale VM images into vSphere using PowerCLI.

  .DESCRIPTION
  Deploy-StorageGRID takes the same INI configuration file format as the deploy-vsphere-ovftool.sh script documented in the product, with an enhanced DISK statement that accepts a DATASTORE= parameter to allow individual disks to be spread across multiple datastores (the root disk of the VM uses the values specified in OVFTOOL_ARGUMENTS, see the the comments in the deploy-vsphere-ovftool.sample.ini file for details).

  By default, the script will upload the OVF files to vCenter in parallel; specify the -Serial switch to upload the OVFs one by one. Once uploaded, the VMs are reconfigured for storage if a DISK option is specified in the configuration file, and started if OVFTOOL_ARGUMENTS contains the --powerOn flag.

  The actual command name is Install-StorageGRID, which avoids warnings about unapproved verbs in the command name.  To be more consistent with existing deployment tools, the command is aliased to Deploy-StorageGRID. Either may be used and are the same.

  .PARAMETER ConfigFile
  Full path to the node configuration INI file. See deploy-vsphere-ovftool.sample.ini for detailed usage comments.

  .PARAMETER Validate
  Only validate the configuration file and exit.

  .PARAMETER Serial
  Upload the OVF files to vCenter one after the other. The default is to upload them simultaneously.

  .PARAMETER Source
  The path to the directory containing the OVF files. Overrides the value of SOURCE in the configuration file.

  .PARAMETER VCenter
  The vCenter server host name or IP adddress. Overrides the value of VCENTER in the configuration file.  Also overrides TARGET.

  .PARAMETER Username
  The vCenter server user name. Overrides the value of USERNAME in the configuration file.

  .PARAMETER Password
  The vCenter server password. Overrides the value of PASSWORD in the configuration file.

  .PARAMETER Path
  The inventory path to the folder to place the VMs in. Overrides the value of PATH in the configuration file. Also overrides TARGET.

  .PARAMETER Node
  Nodes to validate or deploy. The default is to validate or deploy all nodes defined in the configuration file.

  .EXAMPLE
  Deploy-StorageGRID -ConfigFile .\grid.ini

  Deploy all grid nodes defined in grid.ini in parallel using the SOURCE value in grid.ini.

  .EXAMPLE
  Deploy-StorageGRID -ConfigFile .\grid.ini -Node dc1-adm1,dc1-g1

  Deploy only the specified grid nodes.

  .EXAMPLE
  Deploy-StorageGRID -ConfigFile .\grid.ini -Source c:\StorageGRID-10.4.0\vsphere

  Deploy all grid nodes defined in grid.ini overriding the value of SOURCE

  .EXAMPLE
  Deploy-StorageGRID -ConfigFile .\grid.ini -Validate

  Validate the configuration for all grid nodes in grid.ini

  .EXAMPLE
  Deploy-StorageGRID -ConfigFile .\grid.ini -Serial

  Deploy all grid nodes defined in grid.ini one after the other.

  .INPUTS
  System.String[]. Node names to deploy or validate.

  .OUTPUTS
  None

  .LINK
  http://www.netapp.com/us/products/data-management-software/object-storage-grid-sds.aspx

  .LINK
  https://mysupport.netapp.com/info/web/ECMLP2472003.html

  .LINK
  http://www.netapp.com/
#>
function Install-StorageGRID {
  [CmdletBinding(DefaultParameterSetName="Deploy",
                 PositionalBinding=$false,
                 SupportsShouldProcess=$true)]
  param (
    [parameter(Position=0,
               ParameterSetName="Deploy",
               Mandatory,
               HelpMessage="Provide path to configuration file"
              )]
    [parameter(Position=0,
               ParameterSetName="Validate",
               Mandatory,
               HelpMessage="Provide path to configuration file"
              )]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigFile,

    [parameter(Position=1,
               ParameterSetName="Deploy",
               ValueFromRemainingArguments
              )]
    [parameter(Position=1,
               ParameterSetName="Validate",
               ValueFromRemainingArguments
             )]
    [string[]]$Nodes,

    [parameter(ParameterSetName="Deploy"
              )]
    [parameter(ParameterSetName="Validate"
              )]
    [ValidateNotNullOrEmpty()]
    [string]$Source,

    [parameter(ParameterSetName="Deploy"
              )]
    [switch]$Serial=$false,

    [parameter(ParameterSetName="Validate",
               Mandatory
              )]
    [switch]$Validate=$false,

    [parameter(ParameterSetName="Deploy"
              )]
    [parameter(ParameterSetName="Validate"
              )]
    [ValidateNotNullOrEmpty()]
    [string]$VCenter,

    [parameter(ParameterSetName="Deploy"
              )]
    [parameter(ParameterSetName="Validate"
              )]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [parameter(ParameterSetName="Deploy"
              )]
    [parameter(ParameterSetName="Validate"
              )]
    [ValidateNotNullOrEmpty()]
    [string]$Password,

    [parameter(ParameterSetName="Deploy"
              )]
    [ValidateNotNullOrEmpty()]
    [string]$Path
  )


  if (!$ConfigFile) {
    Write-Error "ConfigFile must be specified"
    Return
  }

  $VIModules = @(
    'VMware.VimAutomation.Core',
    'VMware.VimAutomation.Vds',
    'VMware.VimAutomation.Storage'
  )

  # Try to load VMware PowerCLI. No point in doing anything if that fails
  $Error.Clear()
  foreach ($mod in $VIModules) {
    if (!(Get-Module -Name $mod -ErrorAction SilentlyContinue)) {
      Import-Module $mod -Scope Global
      if ($Error.Count -gt 0) {
        #Try the snap in
        Add-PSSnapin $mod
        if ($Error.Count -gt 0) {
          throw "Unable to load VMware module $mod"
        }
      }
    }
  }

  $vmMod = Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue
  if (!$vmMod) {
    $vmMod = Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue
  }

  if ($vmMod.Version.Major -lt 5 -or ($vmMod.version.major -eq 5 -and $vmMod.version.minor -lt 5)) { #check PowerCLI version
    throw "Error: Unsupported PowerCLI version: Must be 5.5 or greater"
  }
  Write-Host "Using PowerCLI Version $($vmMod.Version)`n"

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
    'Starting'  = "Starting VM";
  }
  $Status.Add('MaxLen', ($Status.Values | Measure -Maximum -Property Length).Maximum)

  # Keep track of IPs to check for duplicates
  $ipaddrs = New-Object System.Collections.Generic.HashSet[string]

  # Keep track of which vCenter/account we are currently logged into
  # so we don't log in unnecessarily
  $CurTarget = $null
  $CurUsername = $null
  $CurPassword = $null

  $Tasks = @{}
  $StorageInfo = @{}

  $Config = Get-IniFile $ConfigFile -ErrorAction Stop

  if (!$Nodes) {
    $Nodes = $Config.Keys
  }

  if (!$Validate) {
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
  foreach ($curNode in $Nodes) {
    if ('default' -eq $curNode) { continue }
    if (!$Config.Contains($curNode)) {
      Write-Host -ForegroundColor RED "Error: Node $curNode not found in configuration file $Filepath"
      $error_found = $true
      $ArgErrors++
      Continue
    }
    if ($error_found) {
      continue
    }
    $nodeId++
    Write-Verbose "Processing $curNode"
    Try {
      # Use parameters if provided, otherwise get values from config file
      if (!$Username) {
        $val = Get-Value -Config $Config -Section $curNode -Name 'USERNAME'
        if (!$val) {
          throw [System.ArgumentException] "Username must be provided, either on the command line or in the configuration file."
        }
        $Username = $val
      }

      if (!$Password) {
        $val = Get-Value -Config $Config -Section $curNode -Name 'PASSWORD'
        if (!$val) {
          throw [System.ArgumentException] "Password must be provided, either on the command line or in the configuration file."
        }
        $Password = $val
      }

      if (!$Source) {
        $val = Get-Value -Config $Config -Section $curNode -Name 'SOURCE'
        if (!$val) {
          throw [System.ArgumentException] "Source must be provided, either on the command line or in the configuration file."
        }
        $Source = $val
      }

      if (!$VCenter) {
        $val = Get-Value -Config $Config -Section $curNode -Name 'VCENTER'
        if ($val) {
          $VCenter = $val
          $viserver = $VCenter
        }
      }

      if (!$Path) {
        $val = Get-Value -Config $Config -Section $curNode -Name 'PATH'
        if ($val) {
          $Path = $val
          $vipath = $Path
        }
      }

      # Get vCenter server from vcenter if we have it, otherwise use TARGET
      $val = Get-Value -Config $Config -Section $curNode -Name 'TARGET'
      if ($val) {
        $target = [System.Uri]$val
      }
      if ($target) {
        if ($VCenter) {
          Write-Warning "VCENTER overrides TARGET host"
        }
        else {
          $viserver = $target.Host
        }
      }
      elseif (!$VCenter) {
        throw [System.ArgumentException] "Either both VCENTER and PATH must be specified, or TARGET must be specified."
      }

      # Use PATH if we have it, otherwise use TARGET
      if ($target) {
        if ($Path) {
          Write-Warning "PATH overrides TARGET path"
        }
        else {
          $vipath = $target.AbsolutePath
          if (!$vipath)
          {
            throw [System.ArgumentException] "Malformed TARGET, path must end in either a Cluster, VApp, or Resource Pool"
          }
        }
      }
      elseif (!$Path) {
        throw [System.ArgumentException] "Either both VCENTER and PATH must be specified, or TARGET must be specified."
      }

      # Do not log in unless necessary
      Login-VIServer -VCenter $viserver -User $username -Password $password

      # Start building Import-VApp arguments
      $ImportArgs = @{
        'Confirm' = $false;
        'Name' = $curNode;
      }

      if ($Validate) {
        Write-Host "Validating $curNode"
      }

      # Get the inventory location to deploy to
      if ($script:CurPath -ne $vipath) {
          $script:location = Get-Location -Path $vipath
          if (!$script:location) {
            if ($Path) {
              throw [System.ArgumentException] "PATH must reference either a Cluster, VApp, or Resource Pool"
            }
            else {
              throw [System.ArgumentException] "Malformed TARGET, path must end in either a Cluster, VApp, or Resource Pool"
            }
          }
          Write-Verbose "Found location $script:location"
          $script:CurPath = $vipath
      }
      else {
          Write-Verbose "Using location $script:location"
      }
      $ImportArgs.Add('Location', $script:location)

      # Find a deployment host from location
      $vmHost = Find-Host -Location $script:location
      if (!$vmHost)
      {
        throw [System.ArgumentException] "Unable to find host from TARGET or PATH"
      }
      Write-Verbose "Choosing random host in path: $vmHost"
      $ImportArgs.Add('VMHost', $vmHost)

      # Get the OVF file for our type and add it to source path if we have one
      # Also does NODE_TYPE validation
      $nodeType = Get-Value -Config $Config -Section $curNode -Name 'NODE_TYPE'
      $ovfFile = Get-OvfFile -Config $Config -Node $curNode -NodeType $nodeType
      if ($source)
      {
        $ovfFile = Join-Path -Path $source -ChildPath $ovfFile
      }
      $ImportArgs.Add('Source', $ovfFile)

      # Build an OvfConfiguration with our parameters
      $ovfConfig = Get-OvfConfig -Config $Config -Node $curNode -OvfFile $ovfFile
      $ImportArgs.Add('OvfConfiguration', $ovfConfig)

      # OVFTOOL based INI files combine arguments into a single setting (alas)
      $ovftool_arguments = (Get-Value  -Config $Config -Section $curNode -Name 'OVFTOOL_ARGUMENTS') -split '[\s=]'

      # Add our disk format, if specified
      $dsFormat = Get-OvfArgumentValue -OvfArguments $ovftool_arguments -Name '--diskMode'
      if (!$ValidDIskModes.Contains($dsFormat.ToLower())) {
        throw [System.ArgumentException] "malformed --diskMode value '$dsFormat' in OVFTOOL_ARGUMENTS, must be one of " + ($ValidDiskModes -join ', ')
      }
      if ($dsFormat) {
        $ImportArgs.Add('DiskStorageFormat', $dsFormat)
      }

      # Add datastore, if specified, confirming it exists
      $dsName = Get-OvfArgumentValue -OvfArguments $ovftool_arguments -Name '--datastore'
      if ($dsName) {
        if (!$Datastores.ContainsKey($dsName)) {
          throw [System.ArgumentException] "Datastore $dsName not found"
        }
        Write-Verbose "Deploying to datastore: $dsName"
        $ImportArgs.Add('Datastore', $Datastores[$dsName])
      }

      # See if we have a DISK option. If so, gather up storage parameters
      $diskStmts = Get-Value -Config $Config -Section $curNode -Name 'DISK'
      if ($diskStmts) {
        $diskSpecs = Parse-Disk -DiskStmts $diskStmts -NodeType $nodeType -DefaultDatastore $dsName
        $StorageInfo[$curNode] = @{
          'Node' = $curNode;
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

      $ShouldProcess = $PSCmdlet.ShouldProcess("$curNode", "Deploy Node")
      if ($ShouldProcess) {
          Write-Host "Deploying $curNode to $vmHost on datastore $dsName"
      }
      else {
          Continue;
      }
      
      $Error.clear()
      if ($Serial -Or $Nodes.Count -eq 1) {
        $vm = Import-VApp @ImportArgs -ErrorAction Stop -Verbose:$false
        if ($Error.Count -le 0) {
          ConfigAndStart-Node -ConfigData @{
            'Node' = $curNode;
            'Id' = $nodeId;
            'Info' = $StorageInfo[$curNode];
            'PowerOn' = ($ovftool_arguments -contains "--powerOn");
          }
        }
      }
      else {
        # Import the OVF asynchronously, keeping track of tasks.
        $task = Import-VApp @ImportArgs -RunAsync -ErrorAction Stop -Verbose:$false
        $Tasks[$curNode] = @{
          'Id' = $nodeId;
          'Task' = $task;
          'PowerOn' = ($ovftool_arguments -contains "--powerOn");
        }
      }
    }
    Catch [System.ArgumentException] {
      $ArgErrors++
      Write-Host -ForegroundColor Red "Error: $($curNode): $_"
    }
    Catch {
      if ($action) {
        $action | Remove-Job -Force
      }
      throw
    }
  }

  if (!$ShouldProcess) {
    Return
  }

  if ($Validate) {
    if ($ArgErrors -gt 0) {
      Write-Host -ForegroundColor Red "Configuration Errors Found.`n"
    }
    else {
      Write-Host "Configuration validated.`n"
    }
    Return
  }

  if ($Serial -or $Nodes.Count -le 1) {
    Write-Host "`n"
    if ($action) {
      $action | Remove-Job -Force
    }
    Return
  }

  Try {
    # Monitor tasks and complete reconfig/startup if necessary
    while ($Tasks.Count -gt 0) {
      foreach ($curNode in $($Tasks.Keys)) {
        $task = $Tasks[$curNode]['Task']
        $nodeId = $Tasks[$curNode]['Id']
          Switch ($task.State) {
          'Success' {
            $ConfigData = @{
              'Node' = $curNode;
              'Id' = $nodeId;
              'Info' = $StorageInfo.Get_Item($curNode);
              'PowerOn' = $Tasks[$curNode]['PowerOn']
            }
            ConfigAndStart-Node -ConfigData $ConfigData
            $Tasks.Remove($curNode)
            Continue
          }
          'Error' {
            $Tasks.Remove($curNode)
            Write-Progress -Id $nodeId -Activity "Deploy Node $curNode" -Completed
            Write-Host -ForegroundColor Red "Deployment failed for node ${curNode}: " $task.TerminatingError.Message
            Continue
          }
          default {
            Write-Progress -Id $nodeId -Activity "Deploy Node $curNode" -Status $Status.Importing.PadRight($Status.MaxLen) -PercentComplete $task.PercentComplete
          }
        }
      }
      if ($Tasks.Count -gt 0) {
        Start-Sleep -Seconds 5
      }
    }
  }
  Finally {
    Write-Host "`n"
    if ($action) {
      $action | Remove-Job -Force
    }
  }
}

# Parse the INI file into nested hashtables
function Get-IniFile {
  param (
    [parameter(mandatory=$true)]
    [string]$ConfigFile
  )

  $ini = [ordered]@{}
  $currentSection = [ordered]@{}
  $curSectionName = "default"
  $lineno = 0
  Switch -regex (gc $ConfigFile) {
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
      $currentSection = [ordered]@{}
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
  if ($ini.Keys -notcontains $curSectionName) {
    $ini.Add($curSectionName, $currentSection)
  }
  $ini
}

# Get a value from the configuration, using defaults
function Get-Value { [OutputType([String])]
  param (
    [parameter(mandatory=$true)]
    [hashtable]$Config,

    [parameter(mandatory=$true)]
    [string]$Section,

    [parameter(mandatory=$true)]
    [string]$Name
  )

  if (!$Config.containsKey($Section)) {
    throw [System.ArgumentException] "Node '$Section' does not exist in configuration"
  }

  $value = $Config.Get_Item($Section).Get_Item($Name)
  if (!$value) {
    $value = $Config['default'].Get_Item($Name)
  }
  if (!$value) {
    $value = ''
  }
  $value
}

# Find the OVF file for the given node type
function Get-OvfFile {
  param (
    [parameter(mandatory=$true)]
    [hashtable]$Config,

    [parameter(mandatory=$true)]
    [string]$Node,

    [parameter(mandatory=$true)]
    [string]$NodeType
  )

  if ($NodeType -eq 'VM_Admin_Node') {
    # Admin nodes have specific OVFs for Primary and Non-primary
    [string]$AdminRole = Get-Value -Config $Config -Section $Node -Name 'ADMIN_ROLE'
    if (!$ValidAdminRoles.Contains($AdminRole.ToLower())) {
      throw [System.ArgumentException] ("Invalid ADMIN_ROLE value '$AdminRole', must be one of " + ($ValidAdminRoles -join ', '))
    }
    if ($AdminRole.ToLower() -eq 'primary') {
      return 'vsphere-primary-admin.ovf'
    }
    else {
      return 'vsphere-non-primary-admin.ovf'
    }
  }

  # Other node types can be mapped directly
  if (!$NodeTypeToOvf.Contains($NodeType)) {
    throw [System.ArgumentException] ("invalid NODE_TYPE value '$NodeType', must be one of VM_Admin_Node, " + ($NodeTypeToOvf.Keys -join ', '))
  }
  return $NodeTypeToOvf[$NodeType]
}

# Log into the vCenter server
function Login-VIServer {
  param (
    [parameter(mandatory=$true)]
    [System.Uri]$VCenter,

    [parameter(mandatory=$true)]
    [string]$User,

    [parameter(mandatory=$true)]
    [string]$Password
  )

  if ($script:CurVCenter -eq $VCenter -And $script:CurUsername -eq $User -And $script:CurPassword -eq $Password) {
    Write-Verbose "Reusing vCenter server $defaultVIServer"
    return
  }

  $script:CurVCenter = $null
  $script:CurUsername = $null
  $script:CurPassword = $null
  Disconnect-VIServer -Force -Confirm:$false -ErrorAction SilentlyContinue -WhatIf:$false -Verbose:$false
  Try {
    Connect-VIServer -Server $VCenter -User $User -Password $Password -ErrorAction Stop | Out-Null
    $script:CurVCenter = $VCenter
    $script:CurUsername = $User
    $script:CurPassword = $Password
    Write-Host "Connected to vCenter Server $defaultVIServer"
  }
  Catch {
    throw
  }
  $script:PortGroups = @{}
  Get-VDPortgroup -ErrorAction SilentlyContinue -Verbose:$false | % { $PortGroups[$_.Name] = $_ }
  Get-VirtualPortGroup -Standard -ErrorAction SilentlyContinue -Verbose:$false | % { $PortGroups[$_.Name] = $_ }
  $script:Datastores = @{}
  Get-Datastore -ErrorAction SilentlyContinue -Verbose:$false | % { $Datastores[$_.Name] = $_ }
}

# Resolve path
function Get-Location {
    param (
        [parameter(mandatory=$true)]
        [string]$Path
    )

    $root = Get-Inventory -Name 'Datacenters' -NoRecursion -Verbose:$false
    $elements = $Path.Split('/')
    $elements = $elements[1..($elements.Length-1)]
    Write-Verbose "Resolving PATH $Path"
    Return Get-NextChild -Parent $root -Elements $elements -Index 0
}

# Recursively resolve path elements
function Get-NextChild {
    param (
        [parameter(mandatory=$true)]
        [Object]$Parent,

        [parameter(mandatory=$true)]
        [string[]]$Elements,

        [parameter(mandatory=$true)]
        [int]$Index,

        [parameter(mandatory=$false)]
        [string]$Indent=''
    )

    Write-Verbose "$Indent Looking for $($Elements[$Index])"
    $Children = Get-Inventory -Location $Parent -NoRecursion -Verbose:$false | Select -ExpandProperty Name
    # See if our next element is a direct child
    if ($Children -contains $Elements[$Index]) {
        $Child = Get-Inventory -Location $Parent -Name $Elements[$Index] -NoRecursion -Verbose:$false
        if ((1+$Index) -ge $Elements.Length) {
            Return $Child
        }
        Write-Verbose "$Indent Found $Child"
        $Child = Get-NextChild -Parent $Child -Elements $Elements -Index (1+$Index) -Indent ($Indent + '  ')
        if ($Child) {
            Return $Child
        }
    }
    # See if it's under hidden folder 'Resources'
    if ($Children -contains 'Resources') {
        $inv = Get-Inventory -Location $Parent -Name 'Resources' -NoRecursion -Verbose:$false
        Write-Verbose "$Indent Checking $inv"
        $Child = Get-NextChild -Parent $inv -Elements $Elements -Index $Index -Indent ($Indent + '  ')
        if ($Child) {
            Return $Child
        }
    }
    # See if it's under hidden folder 'host'
    if ($Children -contains 'host') {
        $inv = Get-Inventory -Location $Parent -Name 'host' -NoRecursion -Verbose:$false
        Write-Verbose "$Indent Checking: $inv"
        $Child = Get-NextChild -Parent $inv -Elements $Elements -Index $Index -Indent ($Indent + '  ')
        if ($Child) {
            Return $Child
        }
    }
    Return $null
}

# Set a field on an object
function Set-Object {
  param (
    [parameter(mandatory=$true)]
    [PSObject]$Object,

    [parameter(mandatory=$true)]
    [string]$Name,

    [parameter(mandatory=$true)]
    [string]$Value
  )

  $Object.$Name.Value = $Value
}

# Set Network OvfConfiguration parameters for a given network
function Set-Network {
  param (
    [parameter(mandatory=$true)]
    [hashtable]$Config,

    [parameter(mandatory=$true)]
    [PSObject]$OvfConf,

    [parameter(mandatory=$true)]
    [string]$Node,

    [parameter(mandatory=$true)]
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
    Set-Object -Object $OvfConf.Common -Name "$($netName)_NETWORK_CONFIG" -Value $netConfig
  }

  if ($netConfig -eq 'DISABLED') {
    # All interfaces must have a value, even if disabled. Use grid network, which must be defined.
    Set-Object -Object $OvfConf.NetworkMapping -Name "$($Network)_Network" -Value $GridPortGroup
    return
  }

  $netTarget = Get-Value -Config $Config -Section $Node -Name "$($netName)_NETWORK_TARGET"
  if (!$netTarget)   {
    throw [System.ArgumentException] "$($netName)_NETWORK_TARGET must have a value for node $Node"
  }

  # Confirm the target value is valid
  if (!$PortGroups.ContainsKey($netTarget)) {
    throw [System.ArgumentException] "$($netName)_NETWORK_TARGET value '$netTarget' does not exist in vSphere"
  }

  if ($netName -eq 'GRID') {
    $script:GridPortGroup = $PortGroups[$netTarget]
  }
  Set-Object $OvfConf.NetworkMapping -Name "$($Network)_Network" -Value $PortGroups[$netTarget]

  if ($netConfig -eq 'DHCP') { return }

  if ($netConfig -ne 'STATIC') {
    throw [System.ArgumentException] "Value $netConfig invalid for $($netName)_NETWORK_CONFIG, must be one of DISABLED, STATIC, DHCP"
  }

  foreach ($opt in @('IP', 'MASK', 'GATEWAY')) {
    $fieldName = "$($netName)_NETWORK_$opt"
    $value = Get-Value -Config $Config -Section $Node -Name $fieldName
    if (!$value) {
      if ($netName -eq 'ADMIN' -and $opt -eq 'GATEWAY') {
        continue
      }
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
    Set-Object $OvfConf.Common -Name $fieldName -Value $value
  }

  # Add gateway first
  if ($gateway -and !$ipaddrs.Contains($gateway)) {
    $ipaddrs.Add($gateway) | Out-Null
  }
  if ($ipaddrs.Contains($ip)) {
    throw [System.ArgumentException] "Duplicate IP address '$ip' for $($netName)_NETWORK_IP"
  }
  else {
    $ipaddrs.Add($ip) | Out-Null
  }

  # Validate we have a valid MASK
  $mask.GetAddressBytes() | % {
    if ([convert]::ToString($_, 2) -match '01') {
      throw [System.ArgumentException] "Invalid IP network mask '$mask' for $fieldName"
    }
  }

  # Validate IP and Gateway are in the same subnet
  if ($gateway -and ($ip.Address -band $mask.Address) -ne ($gateway.Address -band $mask.Address)) {
    throw [System.ArgumentException] "$netName network IP and Gateway are not in the same subnet"
  }

  # Validate ADMIN gateway present if ESL set
  if ($netName -eq 'ADMIN') {
    $esl = Get-Value -Config $Config -Section $Node -Name 'ADMIN_NETWORK_ESL'
    if ($esl) {
      if (!$gateway) {
        throw [System.ArgumentException] "ADMIN_NETWORK_GATEWAY required when ADMIN_NETWORK_ESL is set"
      }

      # Validate ESL entries
      $esl_list = @()
      foreach ($entry in $esl -split '[, ]+') {
        if (!$entry) { Continue }
        $parts = $entry -split '/'
        if ($parts.Count -ne 2) {
          throw [System.ArgumentException] "ADMIN_NETWORK_ESL entry $entry invalid, must be in CIDR notation"
        }
        $cidr = [int]$parts[1]
        if ($cidr -lt 1 -or $cidr -gt 32) {
          throw [System.ArgumentException] "ADMIN_NETWORK_ESL entry $entry invalid, CIDR must be between 1 and 32"
        }
        Try {
          $esl_ip = [IPAddress]$parts[0]
        }
        Catch {
          if ($_.FullyQualifiedErrorId -eq "InvalidCastParseTargetInvocation") {
            throw [System.ArgumentException] "ADMIN_NETWORK_ESL entry $entry invalid, IP address part invalid"
          }
          else {
            throw
          }
        }
        # Normalize and pretty the list
        $esl_list += "$esl_ip/$cidr"
      }
      Set-Object -Object $OvfConf.Common -Name ADMIN_NETWORK_ESL -Value ($esl_list -join ',')
    }
  }
}

# Get and populate an OvfConfiguration for deployment
function Get-OvfConfig {
  param (
    [parameter(mandatory=$true)]
    [hashtable]$Config,

    [parameter(mandatory=$true)]
    [string]$Node,

    [parameter(mandatory=$true)]
    [string]$OvfFile
  )

  $ovfConfig = Get-OvfConfiguration -Ovf $OvfFile -Verbose:$false

  $ovfConfig.Common.NODE_NAME.Value = $Node
  if ($ovfConfig.Common.psobject.properties.name -match 'ADMIN_IP') {
    $ovfConfig.Common.ADMIN_IP.Value = (Get-Value -Config $Config -Section $Node -Name 'ADMIN_IP')
  }
  Set-Network -Config $Config -OvfConf $ovfConfig -Node $Node -Network 'Grid'
  Set-Network -Config $Config -OvfConf $ovfConfig -Node $Node -Network 'Admin'
  Set-Network -Config $Config -OvfConf $ovfConfig -Node $Node -Network 'Client'

  $ovfConfig
}

# Parse out the value of an OVFTOOLS_ARGUMENT option
function Get-OvfArgumentValue {
  param (
    [parameter(mandatory=$true)]
    [string[]]$OvfArguments,

    [parameter(mandatory=$true)]
    [string]$Name
  )

  $index = $OvfArguments.IndexOf($Name)
  if ($index -lt 0) { return $null }

  $value = $ovftool_arguments[$index+1] -replace "'", ""
  if (!$value) {
    throw [System.ArgumentException] "Malformed $Name parameter in OVFTOOL_ARGUMENTS, must be $Name=<value>"
  }
  $value
}

# Starting from the last element of the TARGET, go up until we find
# a container that has VMHosts we can deploy to.
function Find-Host {
  param (
    [parameter(mandatory=$true)]
    [PSObject]$Location
  )

  Try {
    $hosts = Get-VMHost -Location $Location -State Connected -ErrorAction SilentlyContinue -Verbose:$false
  }
  Catch {
  }
  if ($hosts) {
    return $hosts | Get-Random
  }
  Find-Host -Location $Location.Parent
}

function Parse-Disk {
  param (
    [parameter(mandatory=$true)]
    [string[]]$DiskStmts,

    [parameter(mandatory=$true)]
    [string]$NodeType,

    [parameter(mandatory=$true)]
    [string]$DefaultDatastore
  )

  if ($NodeType -ne 'VM_Admin_Node' -and $NodeType -ne 'VM_Storage_Node') {
    throw [System.ArgumentException] "DISK option is only allowed on VM_Admin_Node and VM_Storage_Node types"
  }

  $instances = $null
  $capacity = $null
  $datastore = $null
  $totalInstances = 0
  $diskSpecs = @()
  # Possible multiple lines of: INSTANCES = 2 , CAPACITY = 100, DATASTORE = ds1
  $DiskStmts | %{
    $stmt = $_.Trim()
    $parts = $stmt -Split '\s*,\s*'
    if ($parts.Count -lt 2) {
      throw [System.ArgumentException] "Malformed DISK option, format: INSTANCES=<n>, CAPACITY=<y> [, DATASTORE=<ds> ]"
    }
    $parts | %{
      if (!$_.Trim()) {
        throw [System.ArgumentException] "Malformed DISK option, missing key/value pair before or after comma"
      }
      $param = $_ -Split '\s*=\s*'
      if ($param.Count -lt 2) {
        throw [System.ArgumentException] "Malformed DISK option, format: <key> = <value>"
      }
      $opt = $param[0].ToUpper()
      $val = $param[1]
      Try {
        switch ($opt) {
          'INSTANCES' { $instances = [int]$val; Continue }
          'CAPACITY' { $capacity = [int]$val; Continue }
          'DATASTORE' { $datastore = $val; Continue }
          default { throw [System.ArgumentException] "Unknown DISK option '$opt'" }
        }
      }
      Catch {
        if ($_.FullyQualifiedErrorId -eq 'InvalidCastFromStringToInteger') {
          throw [System.ArgumentException] "Malformed DISK option, INSTANCES and CAPACITY must have integer values"
        }
        throw
      }
    }
    if (!$instances -or !$capacity) {
      throw [System.ArgumentException] "Malformed DISK option, INSTANCES and CAPACITY are required"
    }
    if (!$datastore) {
      $datastore = $DefaultDatastore
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
    if (!$Datastores.ContainsKey($datastore)) {
      throw [System.ArgumentException] "Datastore '$datastore' not found"
    }
    $diskSpec = @{ 'instances' = $instances; 'capacity' = $capacity; 'datastore' = $datastore }
    $diskSpecs += [pscustomobject]$diskSpec
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
    [parameter(mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [PSObject]$VM,

    [parameter(mandatory=$true)]
    [PSObject]$Info
  )

  $totalInstances = ($Info.DiskSpecs | Measure-Object 'instances' -Sum).Sum
  # First, remove default storage. Hard disk 1 is root - don't delete.
  # Admin nodes have 2-3, SN have 2-4.
  # Account for remove and starting VM in percent complete
  New-Event -SourceIdentifier StorageEvent -Sender $Info.Id -MessageData $Status.Replacing.PadRight($Status.MaxLen) -EventArguments @{
    'PercentComplete' = $(1/($totalInstances+2)*100);
    'Node' = $Info.Node;
  } | Out-Null
  Write-Verbose "$($Info.Node): Removing default hard disks"
  $progressPreference = 'silentlyContinue'
  $VM | Get-HardDisk -Name 'Hard disk [2-4]' -Verbose:$false | Remove-HardDisk -Confirm:$false -Verbose:$false
  $progressPreference = 'Continue'

  # Create and attach new storage
  foreach ($diskSpec in $Info.DiskSpecs) {
    $datastore = $Datastores[$diskSpec.datastore]
    $capacity = $diskSpec.capacity
    $instances = $diskSpec.instances
    for ($i=1; $i -le $instances; $i++) {
      Write-Verbose "$($Info.Node): Adding ${capacity}GB hard disk on datastore $datastore"
      $msg = ($Status.Adding -f $i).PadRight($Status.MaxLen)
      New-Event -SourceIdentifier StorageEvent -Sender $Info.Id -MessageData $Msg -EventArguments @{
        'PercentComplete' = $(($i+1)/($totalInstances+2)*100);
        'Node' = $Info.Node;
      } | Out-Null
      $progressPreference = 'silentlyContinue'
      $VM | New-HardDisk -CapacityGB $capacity -Datastore $datastore -Persistence persistent -StorageFormat $Info.DiskFormat -WarningAction SilentlyContinue -Verbose:$false | Out-Null
      $progressPreference = 'Continue'
    }
  }
}

function ConfigAndStart-Node {
  param (
    [parameter(mandatory=$true)]
    [PSObject]$ConfigData
  )

  Register-EngineEvent -SourceIdentifier StorageEvent -Forward
  if ($ConfigData.Info) {
    Get-VM -Name $ConfigData.Node -Verbose:$false | Replace-Storage -Info $ConfigData.Info
  }
  if ($ConfigData.PowerOn) {
    New-Event -SourceIdentifier StorageEvent -Sender $ConfigData.Id -MessageData $Status.Starting.PadRight($Status.MaxLen) -EventArguments @{
      'PercentComplete' = 95
      'Node' = $ConfigData.Node
    } | Out-Null
    Write-Verbose "$($ConfigData.Node): Starting VM"
    $progressPreference = 'silentlyContinue'
    Get-VM -Name $ConfigData.Node -Verbose:$false | Start-VM -Confirm:$false -Verbose:$false | Out-Null
    $progressPreference = 'Continue'
  }
  Write-Verbose "$($ConfigData.Node): Deployment Complete"
  New-Event -SourceIdentifier StorageEvent -Sender $ConfigData.Id -MessageData $Status.Starting.PadRight($Status.MaxLen) -EventArguments @{
    'PercentComplete' = 100
    'Node' = $ConfigData.Node
  } | Out-Null
}

Set-Alias -Name Deploy-StorageGRID -Value Install-StorageGRID
Export-ModuleMember -Function Install-StorageGRID -Alias Deploy-StorageGRID
