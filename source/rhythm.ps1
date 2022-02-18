<#
.SYNOPSIS
    Windows rhythm device baseline configurator.
.DESCRIPTION
    The goal of Windows rhythm is to provide a consistent baseline configuration to end user devices in Windows Autopilot scenarios.
    Windows rhythm can easily be implemented using more traditionally deployment methods, like OSD or other methods utilized.
    Current features:
    - Enabling and disabling Windows features.
    - Enabling and disabling Windows optional features.
    - Remove Windows In-box Apps and Store Apps.
    - Configure/re-configure Windows Services.
    - Modifying Windows registry entries (add, change and remove).
.PARAMETER configFile
    Start script with the defined configuration file to be used for the task.
    If no configuration file is defined, script will look for .\config.json. If the configuration is not found or invalid, the script will exit.
.PARAMETER logFile
    Start script logging to the desired logfile.
    If no log file is defined, the script will default to log file within '%ProgramData%\Microsoft\IntuneManagementExtension\Logs' folder, file name <config.metadata.title>.log
.PARAMETER exitOnError
    If an error occurs, control if script should exit-on-error. Default value is $false.
.EXAMPLE
    .\rhythm.ps1
.EXAMPLE
    .\rhythm.ps1 -configFile ".\usercfg.json"
.EXAMPLE
    .\rhythm.ps1 -configFile ".\usercfg.json" -logFile ".\usercfg.log" -Verbose
.NOTES
	version: 0.9.6.2
	author: @dotjesper
	date: February 18, 2022
.LINK
    https://github.com/dotjesper/windows-rhythm
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
    [string]$logFile = "",
    [Parameter(Mandatory = $false)]
    [Alias("eoe")]
    [bool]$exitOnError = $false
)
begin {
    #variables :: environment
    #
    #variables :: configuation file
    if (Test-Path -Path $configFile -PathType Leaf) {
        try {
            $config = Get-Content -Path $configFile -Raw
            $config = ConvertFrom-Json $config
        }
        catch {
            Write-Output -InputObject "Error reading [$configFile], script exiting."
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
    if ($($config.metadata.title)) {
        [string]$global:fLogContentpkg = "$($config.metadata.title -replace '[^a-zA-Z0-9]','-')"
        [string]$global:fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    else {
        [string]$global:fLogContentpkg = "$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName -replace '[^a-zA-Z0-9]','-')"
        [string]$global:fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName).log"
    }
    if ($logfile.Length -gt 0) {
        [string]$global:fLogContentFile = $logfile
    }
    #endregion
    #
    #region :: functions
    function fLogContent () {
        <#
        .SYNOPSIS
           Log-file function.
        .DESCRIPTION
            Log-file function, write a single log line every time it’s called.
            Each line in the log can have various attributes, log text, information about the component from which the fumction is called and an option to specify log file name for each entry.
            Formatting echere to the CMTrace and Microsoft Intune log format.
        .PARAMETER fLogContent
            Holds the string to write to the log file. If script is called with the -Verbose, this string will be sent to the console.
        .PARAMETER fLogContentComponent
            Information about the component from which the fumction is called, e.g. a specific section in the script.
        .PARAMETER fLogContentfn
            Option to specify log file name for each entry.
        .EXAMPLE
            fLogContent -fLogContent "This is the log string." -fLogContentComponent "If applicable, add section, or component for log entry."
        #>
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$fLogContent,
            [Parameter(Mandatory = $false)]
            [string]$fLogContentComponent,
            [Parameter(Mandatory = $false)]
            [string]$fLogContentfn = $fLogContentFile
        )
        begin {
            $fdate = $(Get-Date -Format "M-dd-yyyy")
            $ftime = $(Get-Date -Format "HH:mm:ss.fffffff")
        }
        process {
            try {
                if (!(Test-Path -Path "$(Split-Path -Path $fLogContentfn)")) {
                    New-Item -itemType "Directory" -Path "$(Split-Path -Path $fLogContentfn)" | Out-Null
                }
                Add-Content -Path $fLogContentfn -Value "<![LOG[[$fLogContentpkg] $($fLogContent)]LOG]!><time=""$($ftime)"" date=""$($fdate)"" component=""$fLogContentComponent"" context="""" type="""" thread="""" file="""">" | Out-Null
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
        <#
        .SYNOPSIS
            Windows registry function.
        .DESCRIPTION
            This function is used to modify Windows registry entries (add, update or remove).            
        .PARAMETER task
            Parameter will determine if funtion should ADD (Update) or REMOVE the entry defines using the 'froot':\'fpath' fname and fvalue parameters.
        .PARAMETER froot
            Parameter will define registry root, valid values: HKCR, HKCU, HKLM.
        .PARAMETER fpath
            Parameter for assigning registry path, e.g. 'Software\Microsoft\Windows\CurrentVersion'.
        .PARAMETER fname
            Parameter for assigning registry name, e.g. 'sample'.
        .PARAMETER fpropertyType
            Parameter for assigning property type, e.g. 'String', 'DWord' etc. 
        .PARAMETER fvalue
            Parameter for assigning registry value.
        .EXAMPLE
            fRegistryItem -task "add" -froot "HKLM" -fpath "Software\Microsoft\Windows\CurrentVersion" -fname "Sample" -fpropertyType "DWORD" -fvalue "1"
        #>
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
                fLogContent -fLogContent "registry PSDrive $($froot) exists." -fLogContentComponent "fRegistryItem"
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
                        fLogContent -fLogContent "registry PSDrive $($froot) has an unknown or unsupported value, exiting." -fLogContentComponent "fRegistryItem"
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
                            try {
                                New-Item -Path "$($froot):\$($fpath)" -Force | Out-Null
                                fLogContent -fLogContent "registry path [$($froot):\$($fpath)] created." -fLogContentComponent "fRegistryItem"
                            }
                            catch {
                                $errMsg = $_.Exception.Message
                                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem"
                            }
                            finally {}
                        }
                        else {
                            fLogContent -fLogContent "registry path [$($froot):\$($fpath)] exists." -fLogContentComponent "fRegistryItem"
                        }
                        #Get current value if exist.
                        $fcurrentValue = $(Get-ItemProperty -path "$($froot):\$($fpath)" -name $fname -ErrorAction SilentlyContinue)."$fname"
                        if ($fcurrentValue -eq $fvalue) {
                            fLogContent -fLogContent "registry value already configured" -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value not found or different, forcing update: [$fpropertyType] $fname [ '$fcurrentValue' -> '$fvalue' ]" -fLogContentComponent "fRegistryItem"
                        }
                        #Adding registry item.
                        New-ItemProperty -Path "$($froot):\$($fpath)" -Name "$fname" -PropertyType "$fpropertyType" -Value "$fvalue" -Force | Out-Null
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem"
                        exit 1
                    }
                    finally {}
                }
                "remove" {
                    try {
                        #Test if registry key exists and delete if found.
                        if (!(Get-ItemPropertyValue -Path "$($froot):\$($fpath)" -Name "$fname" -ErrorAction "SilentlyContinue")) {
                            fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) not found." -fLogContentComponent "fRegistryItem"
                        }
                        else {
                            fLogContent -fLogContent "registry value [$($froot):\$($fpath)] : $($fname) found." -fLogContentComponent "fRegistryItem"
                            fLogContent -fLogContent "deleting registry value [$($froot):\$($fpath)] : $($fname)." -fLogContentComponent "fRegistryItem"
                            Remove-ItemProperty -Path "$($froot):\$($fpath)" -Name $($fname) -Force | Out-Null
                        }
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "fRegistryItem"
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
    #region :: logfile environment entries
    [array]$logfileItems = @(
        [pscustomobject]@{fLogContent = "## $($config.metadata.title) by $($config.metadata.developer)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Config file: $($configFile)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Config file version: $($config.metadata.version) | $($config.metadata.date)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Config file description: $($config.metadata.description)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Log file: $($fLogContentFile)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Script name: $($MyInvocation.MyCommand.Name)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Command line: $($MyInvocation.Line)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Run script in 64 bit PowerShell: $($config.runConditions.runScriptIn64bitPowerShell)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Running 64 bit PowerShell: $([System.Environment]::Is64BitProcess)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Running elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Detected user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Detected keyboard layout Id: $((Get-Culture).KeyboardLayoutId)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Detected language mode: $($ExecutionContext.SessionState.LanguageMode)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Detected culture name: $((Get-Culture).Name)"; fLogContentComponent = "environment"}
        [pscustomobject]@{fLogContent = "Detected OS build: $($([environment]::OSVersion.Version).Build)"; fLogContentComponent = "environment"}
    )
    foreach ($logfileItem in $logfileItems) {
        fLogContent -fLogContent "$($logfileItem.fLogContent)" -fLogContentComponent "$($logfileItem.fLogContentComponent)"
    }
    #endregion
    #
    #region :: check conditions
    if ($($config.runConditions.runScriptIn64bitPowerShell) -eq $true -and $([System.Environment]::Is64BitProcess) -eq $false) {
        fLogContent -fLogContent "Script must be run using 64-bit PowerShell." -fLogContentComponent "environment"
        exit 1
    }
    #endregion
}
Process {

    #region :: windowsApps
    fLogContent -fLogContent "WINDOWS APPS" -fLogContentComponent "windowsApps"
    if ($($config.windowsApps.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Apps is enabled." -fLogContentComponent "windowsApps"
        try {
            [array]$windowsApps = $($config.windowsApps.apps)
            foreach ($windowsApp in $windowsApps) {
                fLogContent -fLogContent "Processing $($windowsApp.Name)." -fLogContentComponent "windowsApps"
                [array]$AppxPackage = Get-AppxPackage -AllUsers -Name $($windowsApp.DisplayName) -Verbose:$false
                if ($AppxPackage) {
                    fLogContent -fLogContent "found Appx Package $($windowsApp.DisplayName), $($AppxPackage.PackageFullName), $($AppxPackage.Version)." -fLogContentComponent "windowsApps"
                    if ($($windowsApp.Remove) -eq $true) {
                        fLogContent -fLogContent "removing $($windowsApp.DisplayName) app package for all users." -fLogContentComponent "windowsApps"
                        Remove-AppxPackage -AllUsers -Package "$($AppxPackage.PackageFullName)" -Verbose:$false | Out-Null
                    }
                    else {
                        fLogContent -fLogContent "$($windowsApp.DisplayName) not found!" -fLogContentComponent "windowsApps"
                    }
                }
                [array]$AppxProvisionedPackage = Get-AppxProvisionedPackage -Online -Verbose:$false | Where-Object { $_.DisplayName -eq $($windowsApp.DisplayName) } | Select-Object "DisplayName", "Version", "PublisherId", "PackageName"
                if ($AppxProvisionedPackage) {
                    fLogContent -fLogContent "found Appx Provisioned Package $($AppxProvisionedPackage.DisplayName), $($AppxProvisionedPackage.PackageName), $($AppxProvisionedPackage.Version)." -fLogContentComponent "windowsApps"
                    if ($($windowsApp.RemoveProvisionedPackage) -eq $true) {
                        fLogContent -fLogContent "removing $($windowsApp.Name) provisioned app package." -fLogContentComponent "windowsApps"
                        Remove-AppxProvisionedPackage -Online -PackageName "$($AppxProvisionedPackage.PackageName)" -Verbose:$false | Out-Null
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
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
    }
    else {
        fLogContent -fLogContent "Windows Apps is disabled." -fLogContentComponent "windowsApps"
    }
    #endregion
    #
    #region :: windowsFeatures
    fLogContent -fLogContent "WINDOWS FEATURES" -fLogContentComponent "windowsFeatures"
    if ($($config.windowsFeatures.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Features is enabled." -fLogContentComponent "windowsFeatures"
        try {
            [array]$windowsFeatures = $($config.windowsFeatures.features)
            foreach ($windowsFeature in $windowsFeatures) {
                fLogContent -fLogContent "Processing $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
                [string]$featureState = $(Get-WindowsOptionalFeature -Online -FeatureName $($windowsFeature.FeatureName) -Verbose:$false).state
                if ($($windowsFeature.State) -eq $featureState) {
                    fLogContent -fLogContent "$($windowsFeature.DisplayName) configured [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures"
                }
                else {
                    fLogContent -fLogContent "configuring $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -fLogContentComponent "windowsFeatures"
                    switch ($($windowsFeature.State).ToUpper()) {
                        "ENABLED" {
                            fLogContent -fLogContent "enabling $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
                            Enable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -All -NoRestart -Verbose:$false | Out-Null
                        }
                        "DISABLED" {
                            fLogContent -fLogContent "disabling $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
                            Disable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -NoRestart -Verbose:$false | Out-Null
                        }
                        Default {
                            fLogContent -fLogContent "unsupported state $($windowsFeature.DisplayName) [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures"
                        }
                    }
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFeatures"
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
    }
    else {
        fLogContent -fLogContent "Windows Features is disabled." -fLogContentComponent "windowsFeatures"
    }
    #endregion
    #
    #region :: windowsOptionalFeatures
    fLogContent -fLogContent "WINDOWS OPTIONAL FEATURES" -fLogContentComponent "windowsOptionalFeatures"
    if ($($config.windowsOptionalFeatures.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Optional Features is enabled." -fLogContentComponent "windowsOptionalFeatures"
        try {
            [array]$windowsOptionalFeatures = $($config.windowsOptionalFeatures.features)
            foreach ($windowsOptionalFeature in $windowsOptionalFeatures) {
                fLogContent -fLogContent "Processing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
                [string]$featureState = $(Get-WindowsCapability -Online -Name $($windowsOptionalFeature.Name) -Verbose:$false).state
                if ($($windowsOptionalFeature.State) -eq $featureState) {
                    fLogContent -fLogContent "$($windowsOptionalFeature.DisplayName) configured [$($windowsOptionalFeature.State)]." -fLogContentComponent "windowsOptionalFeatures"
                }
                else {
                    fLogContent -fLogContent "configuring $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]" -fLogContentComponent "windowsOptionalFeatures"
                    switch ($($windowsOptionalFeature.State).ToUpper()) {
                        "INSTALLED" {
                            fLogContent -fLogContent "installing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
                            Add-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false | Out-Null
                        }
                        "NOTPRESENT" {
                            fLogContent -fLogContent "removing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
                            Remove-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false | Out-Null
                        }                    
                        Default {
                            fLogContent -fLogContent "unsupported state $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]." -fLogContentComponent "windowsOptionalFeatures"
                        }
                    }
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsOptionalFeatures"
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
    }
    else {
        fLogContent -fLogContent "Windows Optional Features is disabled." -fLogContentComponent "windowsOptionalFeatures"
    }
    #endregion
    #
    #region :: windowsRegistry
    fLogContent -fLogContent "WINDOWS REGISTRY ITEMS" -fLogContentComponent "windowsRegistry"
    if ($($config.windowsRegistry.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Registry items is enabled" -fLogContentComponent "windowsRegistry"
        try {
            [array]$windowsRegistryItems = $($config.windowsRegistry.items)
            foreach ($windowsRegistryItem in $windowsRegistryItems) {
                fLogContent -fLogContent "Processing $($windowsRegistryItem.description)." -fLogContentComponent "windowsRegistry"
                if ($([int]$windowsRegistryItem.minOSbuild) -eq 0) {
                    fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "windowsRegistry"
                    [int]$windowsRegistryItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
                }
                else {
                    fLogContent -fLogContent "minOSbuild: $($windowsRegistryItem.minOSbuild)" -fLogContentComponent "windowsRegistry"
                }
                if ($([int]$windowsRegistryItem.maxOSbuild) -eq 0) {
                    fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "windowsRegistry"
                    [int]$windowsRegistryItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
                }
                else {
                    fLogContent -fLogContent "maxOSbuild: $($windowsRegistryItem.maxOSbuild)" -fLogContentComponent "windowsRegistry"
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
                else {
                    fLogContent -fLogContent "item $($windowsRegistryItem.description) entry not for this OS build." -fLogContentComponent "windowsRegistry"
                }
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsRegistry"
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
    }
    else {
        fLogContent -fLogContent "Windows Registry items is disabled." -fLogContentComponent "windowsRegistry"
    }
    #endregion
    #
    #region :: windowsServices
    fLogContent -fLogContent "WINDOWS SERVICES" -fLogContentComponent "windowsServices"
    if ($($config.windowsServices.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Services is enabled." -fLogContentComponent "windowsServices"
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
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
    }
    else {
        fLogContent -fLogContent "Windows Services is disabled." -fLogContentComponent "windowsServices"
    }
    #endregion
    #
    #region :: metadata
    fLogContent -fLogContent "METADATA ITEMS" -fLogContentComponent "metadata"
    if ($($config.metadata.enabled) -eq $true) {
        fLogContent -fLogContent "Metadata items is enabled." -fLogContentComponent "metadata"
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
                    if ($exitOnError) {
                        exit 1
                    }
                }
            }
            #metadata entries
            [array]$metadataItems = @(
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "Comments"; Type = "String"; Value = "$($config.metadata.Comments)"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "DisplayName"; Type = "String"; Value = "$($config.metadata.title)"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "DisplayVersion"; Type = "String"; Value = "$($config.metadata.version)"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "InstallBehavior"; Type = "String"; Value = "$($config.metadata.installBehavior)"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "InstallDate"; Type = "String"; Value = "$(Get-Date -Format "yyyyMMdd")"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "Publisher"; Type = "String"; Value = "$($config.metadata.publisher)"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "SystemComponent"; Type = "DWORD"; Value = "1"}
                [pscustomobject]@{root = "$($metadataRoot)"; path = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)"; name = "Version"; Type = "String"; Value = "$($config.metadata.version)"}
            )
            foreach ($metadataItem in $metadataItems) {
                fLogContent -fLogContent "adding $($metadataItem.root):\$($metadataItem.path) [$($metadataItem.Type)] $($metadataItem.name) ""$($metadataItem.Value)""." -fLogContentComponent "metadata"
                fRegistryItem -task "add" -froot "$($metadataItem.root)" -fpath "$($metadataItem.path)" -fname "$($metadataItem.name)" -fpropertyType "$($metadataItem.Type)" -fvalue "$($metadataItem.Value)"
            }
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "metadata"
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
    }
    else {
        fLogContent -fLogContent "Metadata items is disabled." -fLogContentComponent "metadata"
    }
    #endregion
}
end {
    #region ckeaning-up
    fLogContent -fLogContent "Finishing up" -fLogContentComponent "clean-up"
    fLogContent -fLogContent "Cleaning up environment" -fLogContentComponent "clean-up"
    try {
        Remove-Variable -Name * -ErrorAction "SilentlyContinue"
        $error.Clear()
        [System.GC]::Collect()
    }
    catch {
        $errMsg = $_.Exception.Message
        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "clean-up"
    }
    finally {}
    #endregion
}
