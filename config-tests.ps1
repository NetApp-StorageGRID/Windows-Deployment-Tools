Get-Module Install-StorageGRID | Remove-Module -Force
Import-Module .\install-storagegrid.psm1

InModuleScope Install-StorageGRID {
    Describe 'Get-Value' {
        BeforeEach {
            $Config = @{
                default = @{
                    Item1 = 'd1'
                    Item3 = 'd3'
                }
                NODE1 = @{
                    Item1 = 'i1'
                    Item2 = 'i2'
                    DISK = @('v1', 'v2')
                }
            }
        }

        It 'Should fail on unknown section' {
            { Get-Value -Config $Config -Section 'Node2' -Name 'Item1' } |
                Should Throw "'Node2' does not exist"
        }

        It 'Should return proper value' {
            Get-Value -Config $Config -Section 'Node1' -Name 'Item1' | Should be 'i1'
            Get-Value -Config $Config -Section 'Node1' -Name 'Item2' | Should be 'i2'
            $mv = Get-Value -Config $Config -Section 'Node1' -Name 'DISK'
            $mv[0] | Should be 'v1'
            $mv[1] | Should be 'v2'
        }

        It 'Should return default for unset key' {
            Get-Value -Config $Config -Section 'Node1' -Name 'Item3' | Should be 'd3'
        }

        It 'Should return empty string if key not found' {
            Get-Value -Config $Config -Section 'Node1' -Name 'Item4' | Should be ''
        }
    }

    Describe 'Get-OvfFile' {
        BeforeEach {
            $ValidAdminRoles = @('primary', 'non-primary')

            $NodeTypeToOvf = @{
                'VM_Storage_Node' = 'vsphere-storage.ovf';
                'VM_API_Gateway' = 'vsphere-gateway.ovf';
                'VM_Archive_Node' = 'vsphere-archive.ovf';
            }

            $Config = @{}
        }

        It 'Should return PA OVF' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_ROLE'} { return 'Primary' }

            Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_Admin_Node' | Should be 'vsphere-primary-admin.ovf'
        }

        It 'Should return non-PA OVF' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_ROLE'} { return 'Non-primary' }

            Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_Admin_Node' | Should be 'vsphere-non-primary-admin.ovf'
        }

        It 'Should return storage node OVF' {
            Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_Storage_Node' | Should be 'vsphere-storage.ovf'
        }

 
        It 'Should return gateway node OVF' {
            Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_API_Gateway' | Should be 'vsphere-gateway.ovf'
        }

        It 'Should return archive node OVF' {
            Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_Archive_Node' | Should be 'vsphere-archive.ovf'
        }

        It 'Should reject invalid ADMIN_ROLE' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_ROLE'} { return 'bogus' }

            { Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_Admin_Node' } |
                Should throw 'must be one of primary, non-primary'
        }

        It 'Should reject invalid NODE_TYPE' {
            Mock Get-Value -ParameterFilter {$Name -eq 'ADMIN_ROLE'} { return 'bogus' }

            { Get-OvfFile -Config $Config -Node 'Node2' -NodeType 'VM_Bogus_Node' } |
                Should throw 'invalid NODE_TYPE value'
        }
    }
}
