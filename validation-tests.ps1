Get-Module Install-StorageGRID | Remove-Module -Force
Import-Module .\install-storagegrid.psm1

InModuleScope Install-StorageGRID {
    Describe 'Parse-Disk' {
        BeforeEach {
            $Datastores = @{ ds1 = 'ds1'; defaultDS = 'defaultDS' }
        }

        It 'Should require keys and values separated by equal signs' {
        
            $stmts = 'INSTANCES 2, CAPACITY 100'
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "format: <key> = <value>"
        }

        It 'Should require 2 entries comma separated' {
        
            $stmts = 'INSTANCES=2'
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "format: INSTANCES"
        }

        It 'Should require non empty entries' {
        
            $stmts = 'INSTANCES=2,'
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "missing key/value pair before or after comma"
        }

        It 'Should require INSTANCES' {

            $stmts = 'CAPACITY=400,DATASTORE=ds1 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "INSTANCES and CAPACITY are required"
        }

        It 'Should require CAPACITY' {

            $stmts = 'INSTANCES = 5 , DATASTORE = ds1 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "INSTANCES and CAPACITY are required"
        }

        It 'Should succeed' {

            $stmts = 'INSTANCES = 2 , CAPACITY = 100 '
            $specs = Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS'
            $specs.instances | Should be 2
            $specs.capacity | Should be 100
            $specs.datastore | Should be 'defaultDS'
        }

        It 'Should accept DATASTORE' {

            $stmts = 'INSTANCES = 2 , CAPACITY = 500 , DATASTORE = ds1 '
            $specs = Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS'
            $specs.instances | Should be 2
            $specs.capacity | Should be 500
            $specs.datastore | Should be 'ds1'
        }

        It 'Should accept multiple DISK options for VM_Admin_Node' {

            $stmts = @('INSTANCES = 1 , CAPACITY = 100 ', 'INSTANCES = 1 , CAPACITY = 500 , DATASTORE = ds1 ')
            $specs = Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS'
            $specs[0].instances | Should be 1
            $specs[0].capacity | Should be 100
            $specs[0].datastore | Should be 'defaultDS'
            $specs[1].instances | Should be 1
            $specs[1].capacity | Should be 500
            $specs[1].datastore | Should be 'ds1'
        }

        It 'Should accept multiple DISK options for VM_Storage_Node' {

            $stmts = @('INSTANCES = 1 , CAPACITY = 100 ', 'INSTANCES = 2 , CAPACITY = 500 , DATASTORE = ds1 ')
            $specs = Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS'
            $specs[0].instances | Should be 1
            $specs[0].capacity | Should be 100
            $specs[0].datastore | Should be 'defaultDS'
            $specs[1].instances | Should be 2
            $specs[1].capacity | Should be 500
            $specs[1].datastore | Should be 'ds1'
        }
        It 'Should require integer INSTANCE value' {

            $stmts = 'INSTANCES = sam , CAPACITY = 100 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "INSTANCES and CAPACITY must have integer values"
        }

        It 'Should require integer CAPACITY value' {

            $stmts = 'INSTANCES = 2 , CAPACITY = sam '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "INSTANCES and CAPACITY must have integer values"
        }

        It 'Should require INSTANCES = 2 for VM_Admin_Node type' {

            $stmts = 'INSTANCES = 5 , CAPACITY = 100 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "Admin node DISK option must have total INSTANCES = 2"
        }

         It 'Should require INSTANCES = 2 over multiple DISK options' {
           $stmts = @('INSTANCES = 1 , CAPACITY = 100 ', 'INSTANCES = 2 , CAPACITY = 500 , DATASTORE = ds1 ')
           { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
               Should Throw "Admin node DISK option must have total INSTANCES = 2"
        }

        It 'Should require INSTANCES >= 3 for VM_Storage_Node type' {

            $stmts = 'INSTANCES = 2 , CAPACITY = 100 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "INSTANCES >= 3"
        }

        It 'Should require INSTANCES >= 3 across multiple DISK options' {

           $stmts = @('INSTANCES = 1 , CAPACITY = 100 ', 'INSTANCES = 1 , CAPACITY = 500 , DATASTORE = ds1 ')
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "INSTANCES >= 3"
        }

        It 'Should require INSTANCES <= 16 for VM_Storage_Node type' {

            $stmts = 'INSTANCES = 17 , CAPACITY = 100 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "<= 16"
        }

        It 'Should require INSTANCES <= 16 across multiple disk options' {

           $stmts = @('INSTANCES = 1 , CAPACITY = 100 ', 'INSTANCES = 1 , CAPACITY = 500 , DATASTORE = ds1 ')
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "<= 16"
        }

        It 'Should require CAPACITY >= 100 for VM_Admin_Node type' {

            $stmts = 'INSTANCES = 2 , CAPACITY = 50 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Admin_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "CAPACITY >= 100"
        }

        It 'Should require CAPACITY >= 50 for VM_Storage_Node type' {

            $stmts = 'INSTANCES = 3 , CAPACITY = 49 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "CAPACITY >= 50"
        }

        It 'Should reject unknown datastore as default' {

            $stmts = 'INSTANCES = 17 , CAPACITY = 100 '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'bogus' } |
                Should Throw "Datastore 'bogus' not found"
        }

        It 'Should reject unknown datastore specified in DISK' {

            $stmts = 'INSTANCES = 17 , CAPACITY = 100, datastore = bogus '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "Datastore 'bogus' not found"
        }

        It 'Should reject unknown DISK option' {

            $stmts = 'INSTANCES = 17 , BOGUS = 100, datastore = bogus '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Storage_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "Unknown DISK option 'BOGUS'"
        }

        It 'Should reject DISK option on VM_API_Gateway' {

            $stmts = 'INSTANCES = 17 , BOGUS = 100, datastore = bogus '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_API_Gateway' -DefaultDatastore 'defaultDS' } |
                Should Throw "DISK option is only allowed on VM_Admin_Node and VM_Storage_Node types"
        }

        It 'Should reject DISK option on VM_Archive_Node' {

            $stmts = 'INSTANCES = 17 , BOGUS = 100, datastore = bogus '
            { Parse-Disk -DiskStmts $stmts -NodeType 'VM_Archive_Node' -DefaultDatastore 'defaultDS' } |
                Should Throw "DISK option is only allowed on VM_Admin_Node and VM_Storage_Node types"
        }
    }

    Describe 'Set-Network' {
        BeforeEach {
            $ipaddrs = New-Object System.Collections.Generic.HashSet[string]

            $ovfConfigMock = [PSCustomObject]@{
                Common = [PSCustomObject]@{
                    GRID_NETWORK_IP = [PSCustomObject]@{
                        Value=''
                    }
                    GRID_NETWORK_MASK = [PSCustomObject]@{
                        Value=''
                    }
                    GRID_NETWORK_GATEWAY = [PSCustomObject]@{
                        Value=''
                    }
                    ADMIN_NETWORK_CONFIG = [PSCustomObject]@{
                        Value=''
                    }
                    ADMIN_NETWORK_IP = [PSCustomObject]@{
                        Value=''
                    }
                    ADMIN_NETWORK_MASK = [PSCustomObject]@{
                        Value=''
                    }
                    ADMIN_NETWORK_GATEWAY = [PSCustomObject]@{
                        Value=''
                    }
                    ADMIN_NETWORK_ESL = [PSCustomObject]@{
                        Value=''
                    }
                    CLIENT_NETWORK_CONFIG = [PSCustomObject]@{
                        Value=''
                    }
                    CLIENT_NETWORK_IP = [PSCustomObject]@{
                        Value=''
                    }
                    CLIENT_NETWORK_MASK = [PSCustomObject]@{
                        Value=''
                    }
                    CLIENT_NETWORK_GATEWAY = [PSCustomObject]@{
                        Value=''
                    }
                }
                NetworkMapping = [PSCustomObject]@{
                    Grid_Network = [PSCustomObject]@{
                        Value='VM Network'
                    }
                    Admin_Network = [PSCustomObject]@{
                        Value='VM Network'
                    }
                    Client_Network = [PSCustomObject]@{
                        Value='VM Network'
                    }
                }
            }

            $config = [psobject]@{
                default = @{}
                TestNode = @{}
            }

            $PortGroups = @{
                'Grid Network' = 'Grid Network'
                'Admin Network' = 'Admin Network'
                'Client Network' = 'Client Network'
            }
        }


      Context 'General network validation' {
        It 'Should require valid TARGET' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_CONFIG'} { return 'STATIC' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_TARGET'} { return 'JUNK' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "does not exist in vSphere"
        }

        It 'Should require valid CONFIG' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_CONFIG'} { return 'JUNK' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_TARGET'} { return 'Admin Network' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "must be one of DISABLED, STATIC, DHCP"
        }

        It 'Should require valid IP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_CONFIG'} { return 'STATIC' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_IP'} { return '300.10.10.10' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "Invalid IP address"
        }

        It 'Should require valid MASK' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_IP'} { return '10.10.10.10' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_MASK'} { return '255.0.0.10' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "Invalid IP network mask"
        }

        It 'Should require valid GATEWAY' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_MASK'} { return '255.255.255.0' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.10.257' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "Invalid IP address"
        }

        It 'Should require IP and GATEWAY in the same subnet' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.20.1' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "not in the same subnet"
        }

        It 'Should detect IP GATEWAY duplication' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.10.10' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "Duplicate IP address"
        }

        It 'Should require valid ESL CIDR' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.10.1' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_ESL'} { return '10.0.0.0/0' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "CIDR must be between 1 and 32"
        }

        It 'Should require valid ESL IP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.10.1' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_ESL'} { return '10.0.257.0/8' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "IP address part invalid"
        }

        It 'Should require valid ESL syntax' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.10.1' }
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_ESL'} { return '10.0.0.0' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "must be in CIDR notation"
        }
      }

      Context 'Grid network validation' {
        # Mock is scoped in Context, so no need to repeat, but order is significant
        It 'Should require TARGET' {
            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Grid' } |
                Should Throw "GRID_NETWORK_TARGET"
        }

        It 'Should require IP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'GRID_NETWORK_TARGET'} { return 'Grid Network' }
            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Grid' } |
                Should Throw "GRID_NETWORK_IP"
        }

        It 'Should require MASK' {
            Mock Get-Value -ParameterFilter {$Name -eq 'GRID_NETWORK_IP'} { return '10.10.10.10' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Grid' } |
                Should Throw "GRID_NETWORK_MASK"
        }

        It 'Should require GATEWAY' {
            Mock Get-Value -ParameterFilter {$Name -eq 'GRID_NETWORK_MASK'} { return '255.255.255.0' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Grid' } |
                Should Throw "GRID_NETWORK_GATEWAY"
        }

        It 'Should succeed' {
            Mock Get-Value -ParameterFilter {$Name -eq 'GRID_NETWORK_GATEWAY'} { return '10.10.10.1' }
            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Grid'
            $ovfConfigMock.NetworkMapping.Grid_Network.Value | Should Be 'Grid Network'
            $ovfConfigMock.Common.GRID_NETWORK_IP.Value | Should Be '10.10.10.10'
            $ovfConfigMock.Common.GRID_NETWORK_MASK.Value | Should Be '255.255.255.0'
            $ovfConfigMock.Common.GRID_NETWORK_GATEWAY.Value | Should Be '10.10.10.1'
        }
      }

      Context 'Admin network validation' {
        It 'Should default to DISABLED' {
            Mock Get-Value

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin'
            $ovfConfigMock.Common.ADMIN_NETWORK_CONFIG.Value | Should Be 'DISABLED'
            $ovfConfigMock.NetworkMapping.Admin_Network.Value | Should Be 'Grid Network'
        }

        It 'Should require TARGET for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_CONFIG'} { return 'STATIC' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "ADMIN_NETWORK_TARGET"
        }

        It 'Should require TARGET for DHCP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_CONFIG'} { return 'DHCP' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "ADMIN_NETWORK_TARGET"
        }

        It 'Should succeed for DHCP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_TARGET'} { return 'Admin Network' }

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin'
            $ovfConfigMock.NetworkMapping.Admin_Network.Value | Should Be 'Admin Network'
            $ovfConfigMock.Common.ADMIN_NETWORK_CONFIG.Value | Should Be 'DHCP'
        }

        It 'Should require IP for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_CONFIG'} { return 'STATIC' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "ADMIN_NETWORK_IP"
        }

        It 'Should require MASK for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_IP'} { return '10.10.10.10' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "ADMIN_NETWORK_MASK"
        }

        It 'Should succeed w/o ESL and Gateway' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_MASK'} { return '255.255.255.0' }

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin'
            $ovfConfigMock.Common.ADMIN_NETWORK_CONFIG.Value | Should Be 'STATIC'
            $ovfConfigMock.Common.ADMIN_NETWORK_IP.Value | Should Be '10.10.10.10'
            $ovfConfigMock.Common.ADMIN_NETWORK_MASK.Value | Should Be '255.255.255.0'
            $ovfConfigMock.Common.ADMIN_NETWORK_GATEWAY.Value | Should Be ''
        }

        It 'Should require GATEWAY with ESL' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_ESL'} { return '10.0.0.0/8 , 11.0.0.0/8,' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin' } |
                Should Throw "ADMIN_NETWORK_ESL"
        }

        It 'Should succeed with ESL and Gateway' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_NETWORK_GATEWAY'} { return '10.10.10.1' }

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Admin'
            $ovfConfigMock.Common.ADMIN_NETWORK_CONFIG.Value | Should Be 'STATIC'
            $ovfConfigMock.Common.ADMIN_NETWORK_IP.Value | Should Be '10.10.10.10'
            $ovfConfigMock.Common.ADMIN_NETWORK_MASK.Value | Should Be '255.255.255.0'
            $ovfConfigMock.Common.ADMIN_NETWORK_GATEWAY.Value | Should Be '10.10.10.1'
            $ovfConfigMock.Common.ADMIN_NETWORK_ESL.Value | Should Be '10.0.0.0/8,11.0.0.0/8'
        }
      }

      Context 'Client network validation' {
        It 'Should default to DISABLED' {
            Mock Get-Value

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client'
            $ovfConfigMock.Common.CLIENT_NETWORK_CONFIG.Value | Should Be 'DISABLED'
            $ovfConfigMock.NetworkMapping.Client_Network.Value | Should Be 'Grid Network'
        }

        It 'Should require TARGET for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_CONFIG'} { return 'STATIC' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client' } |
                Should Throw "CLIENT_NETWORK_TARGET"
        }

        It 'Should require TARGET for DHCP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_CONFIG'} { return 'DHCP' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client' } |
                Should Throw "CLIENT_NETWORK_TARGET"
        }

        It 'Should succeed for DHCP' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_TARGET'} { return 'Client Network' }

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client'
            $ovfConfigMock.NetworkMapping.Client_Network.Value | Should Be 'Client Network'
            $ovfConfigMock.Common.CLIENT_NETWORK_CONFIG.Value | Should Be 'DHCP'
        }

        It 'Should require IP for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_CONFIG'} { return 'STATIC' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client' } |
                Should Throw "CLIENT_NETWORK_IP"
        }

        It 'Should require MASK for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_IP'} { return '10.10.10.10' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client' } |
                Should Throw "CLIENT_NETWORK_MASK"
        }

        It 'Should require GATEWAY for STATIC' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_MASK'} { return '255.255.255.0' }

            { Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client' } |
                Should Throw "CLIENT_NETWORK_GATEWAY"
        }

        It 'Should succeed with GATEWAY' {
            Mock Get-Value -ParameterFilter {$Name -eq 'CLIENT_NETWORK_GATEWAY'} { return '10.10.10.1' }

            Set-Network -Config $config -OvfConfig $ovfConfigMock -Node 'TestNode' -Network 'Client'
            $ovfConfigMock.Common.CLIENT_NETWORK_CONFIG.Value | Should Be 'STATIC'
            $ovfConfigMock.Common.CLIENT_NETWORK_IP.Value | Should Be '10.10.10.10'
            $ovfConfigMock.Common.CLIENT_NETWORK_MASK.Value | Should Be '255.255.255.0'
            $ovfConfigMock.Common.CLIENT_NETWORK_GATEWAY.Value | Should Be '10.10.10.1'
        }
      }
    }
}
