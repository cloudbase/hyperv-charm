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
# Module manifest for module 'Networking'
#
# Generated by: Gabriel Adrian Samfira
#
# Generated on: 16/01/2016
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'Networking.psm1'

NestedModules = @("IPOperations.psm1")

# Version number of this module.
ModuleVersion = '0.1'

# ID used to uniquely identify this module
GUID = 'f48652df-b026-479d-a9c3-8758702f843a'

# Author of this module
Author = "Gabriel Adrian Samfira","Chris Dent"

# Company or vendor of this module
CompanyName = 'Cloudbase Solutions SRL'

# Copyright statement for this module
Copyright = '(c) 2016 Cloudbase Solutions SRL. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Networking operations'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Modules that must be imported into the global environment prior to importing this module
RequiredModules = ''

# Functions to export from this module
FunctionsToExport = @(
    "Invoke-DHCPRenew",
    "Invoke-DHCPRelease",
    "ConvertTo-DecimalIP",
    "ConvertTo-MaskLength",
    "ConvertTo-DottedDecimalIP",
    "ConvertTo-Mask",
    "Get-NetworkAddress")

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

}

