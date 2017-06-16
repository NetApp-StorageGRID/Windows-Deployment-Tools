# Windows-Deployment-Tools
This repository contains Windows based tools to assist with StorageGRID Webscale deployment.

## Excel Based Planning and Configuration Tools

### SGWS\_Config.xltm
Macro enabled Excel template. Creates spreadsheets for gathering node information and generating
deployment configuration files.

### SGWS\_Config\_Example.xlsm
Macro enabled Excel workbook created from SGWS\_Config.xltm with example data.

## PowerShell Scripts

### deploy-storagegrid.psm1
PowerShell module for installing Deploy-StorageGRID command.  
Usage:  
&nbsp;&nbsp;&nbsp;&nbsp;Import-Module <path>\deploy-storagegrid.psm1  
&nbsp;&nbsp;&nbsp;&nbsp;Get-Help Deploy-StorageGRID -Full

### grid.ini
Example configuration file for use with Deploy-StorageGRID

### deploy-vsphere-ovftool.sample.ini
Example INI file with detailed comments (from StorageGRID 10.4 vSphere installation package).

# Additional Information

For product information on StorageGRID Webscale, see:  
<http://www.netapp.com/us/products/data-management-software/object-storage-grid-sds.aspx>

For product resources and documentation, see:  
<https://mysupport.netapp.com/info/web/ECMLP2472003.html>

NetApp corporate web site:  
<http://www.netapp.com/>

