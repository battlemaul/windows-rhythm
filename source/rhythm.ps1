<#
.SYNOPSIS
    Windows rhythm device baseline configurator.
.DESCRIPTION
    The goal of Windows rhythm is to provide a consistent baseline configuration to end user devices in Windows Autopilot scenarios.
    Windows rhyth can easily be implemented using more traditionally deployment methods, like OSD or other methods utilized.
    Current features:
    - Enabling and disabling Windows features.
    - Remove Windows In-box Apps and Store Apps.
    - Configure/re-configure Windows Services.
    - Modifying Windows registry entries (add and remove).
.PARAMETER configFile
    Start script with the defined configuration file to be used for the task.
    If no configuration file is defined, script will look for .\config.json. If the configuration is not found or invalid, the script will exit.
.PARAMETER logFile
    Start script logging to the desired logfile.
    If no log file is defined, the script will default to Windows rhythm log file within %ProgramData%\Microsoft\IntuneManagementExtension\Logs\ folder.
.EXAMPLE
    .\rhythm.ps1
.EXAMPLE
    .\rhythm.ps1 -configFile ".\usercfg.json"
.EXAMPLE
    .\rhythm.ps1 -configFile ".\usercfg.json" -logFile ".\output.log" -Verbose
.NOTES
	version: 0.9.2.0
	author: @dotjesper
	date: September 12, 2021
#>
#requires -version 5.1
[CmdletBinding()]
param (
    #variables
    [Parameter(Mandatory = $false)]
    [Alias("config")]
    [ValidateScript( { Test-Path $_ })]
    [string]$configFile = ".\config.json",
    [Parameter(Mandatory = $false)]
    [Alias("log")]
    [string]$logFile = ""
)
begin {
    #variables :: environment
    #
    #variables :: conditions
    [bool]$runScriptIn64bitPowerShell = $true
    #variables :: configuation file
    if (Test-Path -Path $configFile -PathType Leaf) {
        try {
            $config = Get-Content -Path $configFile -Raw
            $config = ConvertFrom-Json $config
        }
        catch {
            throw $_.Exception.Message
            exit 1
        }
    }
    else {
        Write-Output -InputObject "Cannot read [$configFile] - file not found, script exiting."
        exit 1
    }
    #
    #variables :: logfile
    [string]$fLogContentpkg = "$($config.metadata.title -replace '[^a-zA-Z0-9]','-')"
    [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    if ($logfile.Length -gt 0) {
        [string]$fLogContentFile = $logfile
    }
    #
    #region :: functions
    function fLogContent () {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$fLogContent,
            [Parameter(Mandatory = $false)]
            [string]$fLogContentComponent
        )
        begin {
            $fdate = $(Get-Date -Format "M-dd-yyyy")
            $ftime = $(Get-Date -Format "HH:mm:ss.fffffff")
        }
        process {
            try {
                if (!(Test-Path -Path "$(Split-Path -Path $fLogContentFile)")) {
                    New-Item -itemType "Directory" -Path "$(Split-Path -Path $fLogContentFile)" | Out-Null
                }
                Add-Content -Path $fLogContentFile -Value "<![LOG[[$fLogContentpkg] $($fLogContent)]LOG]!><time=""$($ftime)"" date=""$($fdate)"" component=""$fLogContentComponent"" context="""" type="""" thread="""" file="""">" | Out-Null
            }
            catch {
                throw $_.Exception.Message
                exit 1
            }
            finally {}
            Write-Verbose -Message "$($fLogContent)"
        }
        end {}
    }
    function fRegistryItem () {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$task,
            [Parameter(Mandatory = $true)]
            [string]$froot,
            [Parameter(Mandatory = $true)]
            [string]$fpath,
            [Parameter(Mandatory = $true)]
            [string]$fname,
            [Parameter(Mandatory = $true)]
            [string]$fpropertyType,
            [Parameter(Mandatory = $false)]
            [string]$fvalue
        )
        begin {
            switch ($fpropertyType) {
                "REG_SZ" {
                    $fpropertyType = "String"
                }
                "REG_EXPAND_SZ" {
                    $fpropertyType = "ExpandString"
                }
                "REG_BINARY" {
                    $fpropertyType = "Binary"
                }
                "REG_DWORD" {
                    $fpropertyType = "DWord"
                }
                "REG_MULTI_SZ" {
                    $fpropertyType = "MultiString"
                }
                "REG_QWOR" {
                    $fpropertyType = "Qword"
                }
                "REG_RESOURCE_LIST" {
                    $fpropertyType = "Unknown"
                }
                Default {}
            }
            if ($($(Get-PSDrive -PSProvider "Registry" -Name "$froot" -ErrorAction "SilentlyContinue").Name)) {
                fLogContent -fLogContent "registry PSDrive $($froot) found." -fLogContentComponent "fRegistryItem"
            }
            else {
                switch ("$froot") {
                    "HKCR" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope "Script" -Verbose:$false| Out-Null
                    }
                    "HKCU" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCU" -PSProvider "Registry" -Root "HKEY_CURRENT_USER" -Scope "Script" -Verbose:$false| Out-Null
                    }
                    "HKLM" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCU" -PSProvider "Registry" -Root "HKEY_LOCAL_MACHINE" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    Default {
                        fLogContent -fLogContent "registry PSDrive $($froot) is an unknown or unsupported value, exiting." -fLogContentComponent "fRegistryItem"
                        exit 1
                    }
                }
            }
        }
        process {
            switch ($task) {
                "add" { 
                    try {
                        #Test Registry path exists and create if not found.
                        if (!(Test-Path -Path "$($froot):\$($fpath)")) {
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] not found." -fLogContentComponent "fRegistryItem"
                            New-Item -Path "$($froot):\$($fpath)" | Out-Null
                        }
                        else {
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] exists." -fLogContentComponent "fRegistryItem."
                        }
                        $fcurrentValue = $(Get-ItemProperty -path "$($froot):\$($fpath)" -name $fname -ErrorAction SilentlyContinue)."$fname"
                        if ($fcurrentValue -eq $fvalue) {
                            fLogContent -fLogContent "registry value already configured" -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value not found or different, forcing update: [$fpropertyType] $fname [ '$fcurrentValue' -> '$fvalue' ]" -fLogContentComponent "fRegistryItem"
                        }
                        New-ItemProperty -Path "$($froot):\$($fpath)" -Name "$fname" -PropertyType "$fpropertyType" -Value "$fvalue" -Force | Out-Null
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem."
                        exit 1
                    }
                    finally {}  
                }
                "remove" {
                    try {
                        #Test Registry key exists and delete if found.
                        if (!(Get-ItemPropertyValue -Path "$($froot):\$($fpath)" -Name "$fname" -ErrorAction "SilentlyContinue")) {
                            fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) not found." -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) found." -fLogContentComponent "fRegistryItem."
                            fLogContent -fLogContent "deleting registry value [$($froot):\$($fpath)] : $($fname)." -fLogContentComponent "fRegistryItem."
                            Remove-ItemProperty -Path "$($froot):\$($fpath)" -Name $($fname) -Force | Out-Null
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem."
                        exit 1
                    }
                    finally {}
                }
                Default {}
            }
        }
        end {}
    }
    #endregion
    #
    #logfile environment entries
    [array]$logfileItems = @(
        [pscustomobject]@{fLogContent = "## $($config.metadata.title) by $($config.metadata.developer)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Config file: $($configFile)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Config file version: $($config.metadata.version) | $($config.metadata.date)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Log file: $($fLogContentFile)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Command line: $($MyInvocation.Line)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Run script in 64 bit PowerShell: $($runScriptIn64bitPowerShell)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Running 64 bit PowerShell: $([System.Environment]::Is64BitProcess)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Running elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Detected user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Detected keyboard layout Id: $((Get-Culture).KeyboardLayoutId)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Detected language mode: $($ExecutionContext.SessionState.LanguageMode)"; fLogContentComponent = "" }
        [pscustomobject]@{fLogContent = "Detected culture name: $((Get-Culture).Name)"; fLogContentComponent = "" }
    )
    foreach ($logfileItem in $logfileItems) {
        fLogContent -fLogContent "$($logfileItem.fLogContent)" -fLogContentComponent "$($logfileItem.fLogContentComponent)"
    }
}
Process {
    #region :: check conditions
    if ($runScriptIn64bitPowerShell -eq $true -and $([System.Environment]::Is64BitProcess) -eq $false) {
        fLogContent -fLogContent "Script must be run using 64-bit PowerShell." -fLogContentComponent "windowsFeatures."
        exit 1
    }
    #endregion
    #
    #region :: windowsFeatures
    if ($($config.windowsFeatures.enabled) -eq $true) {
        fLogContent -fLogContent "Processing Windows Features" -fLogContentComponent "windowsFeatures."
        try {
            [array]$windowsFeatures = $($config.windowsFeatures.features)
            foreach ($windowsFeature in $windowsFeatures) {
                fLogContent -fLogContent "Processing $($windowsFeature.FeatureName)." -fLogContentComponent "windowsFeatures."
                [string]$featureState = $(get-WindowsOptionalFeature -Online -FeatureName $($windowsFeature.FeatureName) -Verbose:$false).state
                if ($($windowsFeature.State) -eq $featureState) {
                    fLogContent -fLogContent "$($windowsFeature.FeatureName) configured [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures."
                }
                else {
                    fLogContent -fLogContent "configuring $($windowsFeature.FeatureName) [$($windowsFeature.State)]" -fLogContentComponent "windowsFeatures."
                    switch ($($windowsFeature.State).ToUpper()) {
                        "ENABLED" {
                            fLogContent -fLogContent "enabling $($windowsFeature.FeatureName)." -fLogContentComponent "windowsFeatures."
                            Enable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -All -Verbose:$false | Out-Null
                        }
                        "DISABLED" {
                            fLogContent -fLogContent "disabling $($windowsFeature.FeatureName)." -fLogContentComponent "windowsFeatures."
                            Disable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -Verbose:$false | Out-Null
                        }
                        Default {
                            fLogContent -fLogContent "unsupported state $($windowsFeature.FeatureName) [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures."
                        }
                    }
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFeatures."
            exit 1
        }
        finally {}
    }
    #endregion
    #
    #region :: windowsApps
    if ($($config.windowsApps.enabled) -eq $true) {
        fLogContent -fLogContent "Processing Windows Apps." -fLogContentComponent "windowsApps."
        try {
            [array]$windowsApps = $($config.windowsApps.apps)
            foreach ($windowsApp in $windowsApps) {
                fLogContent -fLogContent "Processing $($windowsApp.Name)." -fLogContentComponent "windowsApps"
                [array]$AppxProvisionedPackage = Get-AppxProvisionedPackage -Online -Verbose:$false | Where-Object { $_.DisplayName -eq $($windowsApp.DisplayName) } | Select-Object "DisplayName", "Version", "PublisherId", "PackageName"
                if ($AppxProvisionedPackage) {
                    fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName), $($AppxProvisionedPackage.PackageName), $($AppxProvisionedPackage.Version)." -fLogContentComponent "windowsApps"
                    #Get-AppxPackage -AllUsers | where-object {$_.name -eq $($AppxProvisionedPackage.DisplayName)}
                    #Get-AppxPackage -AllUsers -Name "Microsoft.SecHealthUI"

                    if ($($windowsApp.Remove) -eq $true) {
                        fLogContent -fLogContent "removing $($windowsApp.DisplayName) for all users." -fLogContentComponent "windowsApps"
                        #Remove-AppxPackage -Package "" -Verbose:$false | Out-Null
                    }
                    if ($($windowsApp.RemoveProvisionedPackage) -eq $true) {
                        fLogContent -fLogContent "removing $($windowsApp.DisplayName) provisioned app package." -fLogContentComponent "windowsApps"
                        #Remove-AppxProvisionedPackage -PackageName "" -Verbose:$false | Out-Null
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsApp.DisplayName) not found!" -fLogContentComponent "windowsApps"
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsApps"
            exit 1
        }
        finally {}
    }
    #endregion
    #
    #region :: windowsServices
    if ($($config.windowsServices.enabled) -eq $true) {
        fLogContent -fLogContent "Processing Windows Services." -fLogContentComponent "windowsServices"
        try {
            [array]$windowsServices = $($config.windowsServices.services)
            foreach ($windowsService in $windowsServices) {
                fLogContent -fLogContent "Processing $($windowsService.DisplayName) [$($windowsService.Name)]." -fLogContentComponent "windowsServices"
                [array]$windowsServiceStatus = Get-Service -Name "$($windowsService.Name)" -ErrorAction "SilentlyContinue"
                if ($windowsServiceStatus) {
                    fLogContent -fLogContent "$($windowsServiceStatus.DisplayName) found! | Status: $($windowsServiceStatus.Status) | StartType: $($windowsServiceStatus.StartType)." -fLogContentComponent "windowsServices"
                    if ($($windowsService.StartType) -eq  $($windowsServiceStatus.StartType)) {
                        fLogContent -fLogContent "$($windowsService.Name) already configured." -fLogContentComponent "windowsServices"
                    }
                    else {
                        fLogContent -fLogContent "reconfigure $($windowsService.Name) [($($windowsServiceStatus.StartType) ->  $($windowsService.StartType))]." -fLogContentComponent "windowsServices"
                        Set-Service -Name "$($windowsService.Name)" -StartupType "$($windowsServiceStatus.StartType)"
                    }
                    if ($($windowsService.StopIfRunning) -eq $true -and $($windowsServiceStatus.Status) -eq "Running") {
                        fLogContent -fLogContent "Stopping $($windowsService.DisplayName) [$($windowsService.Name)]." -fLogContentComponent "windowsServices"
                        Stop-Service -Name "$($windowsService.Name)" -Force
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsService.DisplayName) not found!" -fLogContentComponent "windowsServices"
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsServices"
            exit 1
        }
        finally {}
    }
    #endregion
    #
    #region :: windowsRegistry
    if ($($config.windowsRegistry.enabled) -eq $true) {
        fLogContent -fLogContent "Processing Windows Registry items." -fLogContentComponent "windowsRegistry"
        try {
            [array]$windowsRegistryItems = $($config.windowsRegistry.items)
            foreach ($windowsRegistryItem in $windowsRegistryItems) {
                fLogContent -fLogContent "Processing $($windowsRegistryItem.description)." -fLogContentComponent "windowsRegistry"
                if ($([int]$windowsRegistryItem.minOSbuild) -eq 0) {
                    [int]$windowsRegistryItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
                }
                if ($([int]$windowsRegistryItem.maxOSbuild) -eq 0) {
                    [int]$windowsRegistryItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
                }
                if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsRegistryItem.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsRegistryItem.maxOSbuild)) {
                    switch ($($windowsRegistryItem.item).ToUpper()) {
                        "ADD" {
                            fLogContent -fLogContent "adding $($windowsRegistryItem.root):\$($windowsRegistryItem.path) [$($windowsRegistryItem.Type)] $($windowsRegistryItem.name) ""$($windowsRegistryItem.Value)""." -fLogContentComponent "windowsRegistry"
                            fRegistryItem -task "add" -froot "$($windowsRegistryItem.root)" -fpath "$($windowsRegistryItem.path)" -fname "$($windowsRegistryItem.name)" -fpropertyType "$($windowsRegistryItem.Type)" -fvalue "$($windowsRegistryItem.Value)"
                        }
                        "REMOVE" {
                            fLogContent -fLogContent "removing $($windowsRegistryItem.root):\$($windowsRegistryItem.path) ""$($windowsRegistryItem.name)"" setting from registry." -fLogContentComponent "windowsRegistry"
                            fRegistryItem -task "remove" -froot "$($windowsRegistryItem.root)" -fpath "$($windowsRegistryItem.path)" -fname "$($windowsRegistryItem.name)" -fpropertyType "$($windowsRegistryItem.Type)" -fvalue ""
                        }
                        Default {
                            fLogContent -fLogContent "unsupported value for [$($windowsRegistryItem.description)] | [$($windowsRegistryItem.item)]" -fLogContentComponent "windowsRegistry"
                        }
                    }
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsRegistry"
            exit 1
        }
        finally {}
    }
    #endregion
    #
    #region :: metadata
    if ($($config.metadata.enabled) -eq $true) {
        fLogContent -fLogContent "Processing metadata items." -fLogContentComponent "metadata"
        try {
            switch ($($config.metadata.installBehavior).ToUpper()) {
                "SYSTEM" {
                    $metadataRoot = "HKLM"
                }
                "USER" {
                    $metadataRoot = "HKCU"
                }
                Default {
                    fLogContent -fLogContent "ERROR: Processing metadata items failed." -fLogContentComponent "metadata"
                    exit 1
                }
            }
            #metadata entries
            [array]$metadataItems = @(
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "Comments"; Type = "String"; Value = "$($config.metadata.Comments)" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "DisplayName"; Type = "String"; Value = "$($config.metadata.title)" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "DisplayVersion"; Type = "String"; Value = "$($config.metadata.version)" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "InstallBehavior"; Type = "String"; Value = "$($config.metadata.installBehavior)" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "InstallDate"; Type = "String"; Value = "$(Get-Date -Format "yyyyMMdd")" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "Publisher"; Type = "String"; Value = "$($config.metadata.publisher)" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "SystemComponent"; Type = "DWORD"; Value = "1" }
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "Version"; Type = "String"; Value = "$($config.metadata.version)" }
            )
            foreach ($metadataItem in $metadataItems) {
                fLogContent -fLogContent "adding $($metadataItem.root):\$($metadataItem.path) [$($metadataItem.Type)] $($metadataItem.name) ""$($metadataItem.Value)""." -fLogContentComponent "metadata"
                fRegistryItem -task "add" -froot "$($metadataItem.root)" -fpath "$($metadataItem.path)" -fname "$($metadataItem.name)" -fpropertyType "$($metadataItem.Type)" -fvalue "$($metadataItem.Value)"
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "metadata"
            exit 1
        }
        finally {}
    }
    #endregion
}
end {}
