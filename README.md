# Windows-Deployment-Tools
This repository contains Windows based tools to assist with StorageGRID&reg; Webscale deployment.

## Excel Based Planning and Configuration Tools

### SGWS\_Config.xltm
Macro enabled Excel template. Creates spreadsheets for gathering node information and generating
deployment configuration files.

### SGWS\_Config\_Example.xlsm
Macro enabled Excel workbook created from SGWS\_Config.xltm with example data.

## PowerShell Scripts

### install-storagegrid.psm1
PowerShell module for installing the **Install-StorageGRID** command. Deploy-StorageGRID is an alias for Install-StorageGRID.  
Usage:  
&nbsp;&nbsp;&nbsp;&nbsp;Import-Module .\install-storagegrid.psm1  
&nbsp;&nbsp;&nbsp;&nbsp;Get-Help Install-StorageGRID -Full

Requires: VMware PowerCLI version 5.5 or greater

### install-storagegrid.example.ini
Example configuration file for use with Install-StorageGRID

For a detailed explanation of the INI file, see the *deploy-vsphere-ovftool.sample.ini* file in the *vsphere*
directory of the standard StorageGRID Webscale distribution. This file is meant to be compatible with that format.

This script also accepts *DATASTORE* on the *DISK* option, and you can avoid the need to use ovftool to find 
the value for TARGET by specifying the vCenter server with VCENTER and the inventory path with PATH. PATH is as you see the hierarchy in vCenter. See file for examples of these enhancements.

# Additional Information

For product information on StorageGRID Webscale, see:  
<http://www.netapp.com/us/products/data-management-software/object-storage-grid-sds.aspx>

For product resources and documentation, see:  
<https://mysupport.netapp.com/info/web/ECMLP2472003.html>

NetApp corporate web site:  
<http://www.netapp.com/>

