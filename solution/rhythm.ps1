<# PSScriptInfo
.VERSION 0.9.8.0
.GUID A86971BB-9C5B-4540-B5C7-13CCDDE330EB
.AUTHOR @dotjesper
.COMPANYNAME dotjesper.com
.COPYRIGHT dotjesper.com
.TAGS windows powershell-5 windows-10 windows-11 endpoint-manager branding
.LICENSEURI https://github.com/dotjesper/windows-rhythm/blob/main/LICENSE
.PROJECTURI https://github.com/dotjesper/windows-rhythm
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES https://github.com/dotjesper/windows-rhythm/wiki/release-notes
#>
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
    To download sample configuration files and follow the latest progress, visit the project site.
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
#>
#requires -version 5.1
[CmdletBinding()]
param (
    #variables
    [Parameter(Mandatory = $false)]
    [ValidateScript({Test-Path $_ })]
    [string]$configFile = ".\config.json",
    [Parameter(Mandatory = $false)]
    [string]$logFile = "",
    [Parameter(Mandatory = $false)]
    [switch]$exitOnError,
    [Parameter(Mandatory = $false)]
    [switch]$uninstall
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
        Write-Output -InputObject "> Go to https://github.com/dotjesper/windows-rhythm/ to download sample configuration files."
        exit 1
    }
    #
    #variables :: logfile
    if ($($config.metadata.title)) {
        [string]$fLogContentpkg = "$($config.metadata.title -replace '[^a-zA-Z0-9]','-')"
        [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    else {
        [string]$fLogContentpkg = "$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName -replace '[^a-zA-Z0-9]','-')"
        [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    if ($logfile.Length -gt 0) {
        [string]$fLogContentFile = $logfile
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
                Add-Content -Path $fLogContentfn -Value "<![LOG[[$fLogContentpkg] $($fLogContent)]LOG]!><time=""$($ftime)"" date=""$($fdate)"" component=""$fLogContentComponent"" context="""" type="""" thread="""" file="""">" -Encoding "UTF8" | Out-Null
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
    try {
        fLogContent -fLogContent "## $($config.metadata.title) by $($config.metadata.developer)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Config file: $($configFile)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Config file version: $($config.metadata.version) | $($config.metadata.date)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Config file description: $($config.metadata.description)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Log file: $($fLogContentFile)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Script name: $($MyInvocation.MyCommand.Name)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Command line: $($MyInvocation.Line)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Run script in 64 bit PowerShell: $($config.runConditions.runScriptIn64bitPowerShell)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Running 64 bit PowerShell: $([System.Environment]::Is64BitProcess)" -fLogContentComponent "environment"
        if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
            fLogContent -fLogContent "Running elevated: $(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" -fLogContentComponent "environment"
            fLogContent -fLogContent "Detected user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -fLogContentComponent "environment"
        }
        else {
            fLogContent -fLogContent "Detected user: $($Env:USERNAME)" -fLogContentComponent "environment"
        }
        fLogContent -fLogContent "Detected keyboard layout Id: $((Get-Culture).KeyboardLayoutId)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Detected language mode: $($ExecutionContext.SessionState.LanguageMode)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Detected culture name: $((Get-Culture).Name)" -fLogContentComponent "environment"
        fLogContent -fLogContent "Detected OS build: $($([environment]::OSVersion.Version).Build)" -fLogContentComponent "environment"
    }
    catch {
        $errMsg = $_.Exception.Message
        fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "environment"
        if ($exitOnError) {
            exit 1
        }
    }
    finally {}
    #endregion
    #
    #region :: check conditions
    if ($($config.runConditions.runScriptIn64bitPowerShell) -eq $true -and $([System.Environment]::Is64BitProcess) -eq $false) {
        fLogContent -fLogContent "Script must be run using 64-bit PowerShell." -fLogContentComponent "environment"
        foreach ($key in $MyInvocation.BoundParameters.keys) {
            switch ($MyInvocation.BoundParameters[$key].GetType().Name) {
                "Boolean" {
                    $argsString += "-$key `$$($MyInvocation.BoundParameters[$key]) "
                }
                "Int32" {
                    $argsString += "-$key $($MyInvocation.BoundParameters[$key]) "
                }
                "String" {
                    $argsString += "-$key `"$($MyInvocation.BoundParameters[$key])`" "
                }
                "SwitchParameter" {
                    if ($MyInvocation.BoundParameters[$key].IsPresent) {
                        $argsString += "-$key "
                    }
                }
                Default {}
            }
        }
        try {
            fLogContent -fLogContent "Script relaunching using 64-bit PowerShell." -fLogContentComponent "environment"
            fLogContent -fLogContent $("Command line: .\" + $($myInvocation.myCommand.name) + " " + $($argsString)) -fLogContentComponent "environment"
            Start-Process -FilePath "$env:windir\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -ArgumentList $("-ExecutionPolicy Bypass -File .\" + $($myInvocation.myCommand.name) + " " + $($argsString)) -Wait -NoNewWindow
            exit 0
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "environment"
            if ($exitOnError) {
                exit 1
            }
        }
    }
    #endregion
}
process {
    #region :: windowsApps
    fLogContent -fLogContent "WINDOWS APPS" -fLogContentComponent "windowsApps"
    if ($($config.windowsApps.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Apps is enabled." -fLogContentComponent "windowsApps"
        [array]$windowsApps = $($config.windowsApps.apps)
        foreach ($windowsApp in $windowsApps) {
            fLogContent -fLogContent "Processing $($windowsApp.Name)." -fLogContentComponent "windowsApps"
            #region :: Appx Package
            try {
                [array]$AppxPackage = Get-AppxPackage -AllUsers -Name $($windowsApp.DisplayName) -Verbose:$false
                if ($AppxPackage) {
                    fLogContent -fLogContent "$($windowsApp.Name) is present." -fLogContentComponent "windowsApps"
                    fLogContent -fLogContent "$($windowsApp.Name), $($windowsApp.DisplayName), $($AppxPackage.PackageFullName), $($AppxPackage.Version)." -fLogContentComponent "windowsApps"
                    fLogContent -fLogContent "$($windowsApp.Name) remove: $($windowsApp.Remove)." -fLogContentComponent "windowsApps"
                    if ($($windowsApp.Remove) -eq $true) {
                        fLogContent -fLogContent "$($windowsApp.Name) is being removed from all users." -fLogContentComponent "windowsApps"
                        try {
                            Remove-AppxPackage -AllUsers -Package "$($AppxPackage.PackageFullName)" -Verbose:$false | Out-Null
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
                }
                else {
                    fLogContent -fLogContent "$($windowsApp.Name) not present." -fLogContentComponent "windowsApps"
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
            #endregion
            #region :: Appx Provisioned Package
            try {
                [array]$AppxProvisionedPackage = Get-AppxProvisionedPackage -Online -Verbose:$false | Where-Object { $_.DisplayName -eq $($windowsApp.DisplayName) } | Select-Object "DisplayName", "Version", "PublisherId", "PackageName"
                if ($AppxProvisionedPackage) {
                    fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName) is present as provisioned app." -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName), $($AppxProvisionedPackage.PackageName), $($AppxProvisionedPackage.Version)." -fLogContentComponent "windowsProvisionedApps"
                    fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName) remove: $($windowsApp.RemoveProvisionedPackage)." -fLogContentComponent "windowsProvisionedApps"
                    if ($($windowsApp.RemoveProvisionedPackage) -eq $true) {
                        fLogContent -fLogContent "$($AppxProvisionedPackage.DisplayName) is being removed." -fLogContentComponent "windowsProvisionedApps"
                        try {
                            Remove-AppxProvisionedPackage -Online -PackageName "$($AppxProvisionedPackage.PackageName)" -Verbose:$false | Out-Null
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsProvisionedApps"
                            if ($exitOnError) {
                                exit 1
                            }
                        }
                        finally {}
                    }
                }
                else {
                    fLogContent -fLogContent "$($windowsApp.DisplayName) is not present." -fLogContentComponent "windowsProvisionedApps"
                }
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsProvisionedApps"
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            #endregion
        }
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
        [array]$windowsFeatures = $($config.windowsFeatures.features)
        foreach ($windowsFeature in $windowsFeatures) {
            fLogContent -fLogContent "Processing $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
            try {
                [string]$featureState = $(Get-WindowsOptionalFeature -Online -FeatureName $($windowsFeature.FeatureName) -Verbose:$false).state
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFeatures"
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
            if ($($windowsFeature.State) -eq $featureState) {
                fLogContent -fLogContent "$($windowsFeature.DisplayName) configured [$($windowsFeature.State)]." -fLogContentComponent "windowsFeatures"
            }
            else {
                fLogContent -fLogContent "configuring $($windowsFeature.DisplayName) [$($windowsFeature.State)]" -fLogContentComponent "windowsFeatures"
                try {
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
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFeatures"
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
        }
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
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsOptionalFeatures"
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
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
                        try {
                            Add-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false | Out-Null
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
                    "NOTPRESENT" {
                        fLogContent -fLogContent "removing $($windowsOptionalFeature.DisplayName)." -fLogContentComponent "windowsOptionalFeatures"
                        try {
                            Remove-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false | Out-Null
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
                    Default {
                        fLogContent -fLogContent "unsupported state $($windowsOptionalFeature.DisplayName) [$($windowsOptionalFeature.State)]." -fLogContentComponent "windowsOptionalFeatures"
                    }
                }
            }
        }
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
            try {
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
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsRegistry"
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
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
        [array]$windowsServices = $($config.windowsServices.services)
        foreach ($windowsService in $windowsServices) {
            fLogContent -fLogContent "Processing $($windowsService.DisplayName) [$($windowsService.Name)]." -fLogContentComponent "windowsServices"
            try {
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
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsServices"
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
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
        #region :: metadata entries
        try {
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "Comments" -fpropertyType "String" -fvalue "$($config.metadata.Comments)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "DisplayName" -fpropertyType "String" -fvalue "$($config.metadata.title)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "DisplayVersion" -fpropertyType "String" -fvalue "$($config.metadata.version)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "InstallBehavior" -fpropertyType "String" -fvalue "$($config.metadata.installBehavior)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "InstallDate" -fpropertyType "String" -fvalue "$(Get-Date -Format "yyyyMMdd")"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "Publisher" -fpropertyType "String" -fvalue "$($config.metadata.publisher)"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "SystemComponent" -fpropertyType "DWORD" -fvalue "1"
            fRegistryItem -task "add" -froot "$($metadataRoot)" -fpath "Software\Microsoft\Windows\CurrentVersion\Uninstall\$($config.metadata.guid)" -fname "Version" -fpropertyType "String" -fvalue "$($config.metadata.version)"
        }
        catch {
            $errMsg = $_.Exception.Message
            fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsServices"
            if ($exitOnError) {
                exit 1
            }
        }
        finally {}
        #endregion
    }
    else {
        fLogContent -fLogContent "Metadata items is disabled." -fLogContentComponent "metadata"
    }
    #endregion
}
end {
    #region :: cleaning-up
    fLogContent -fLogContent "Finishing up" -fLogContentComponent "clean-up"
    fLogContent -fLogContent "Cleaning up environment" -fLogContentComponent "clean-up"
    Remove-Variable -Name * -ErrorAction "SilentlyContinue"
    #$error.Clear()
    #[System.GC]::Collect()
    #endregion
}

# SIG # Begin signature block
# MIIkIwYJKoZIhvcNAQcCoIIkFDCCJBACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwSvH+jOKYCmjFsqfiqM1e/0N
# EHGggh47MIIE/jCCA+agAwIBAgIQDUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEw
# NjAwMDAwMFowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMLmYYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQ
# tSYQ/h3Ib5FrDJbnGlxI70Tlv5thzRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4
# bbx9+cdtCT2+anaH6Yq9+IRdHnbJ5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOK
# fF1FLUuxUOZBOjdWhtyTI433UCXoZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlK
# XAwxikqMiMX3MFr5FK8VX2xDSQn9JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYer
# vnpbCiAvSwnJlaeNsvrWY4tOpXIc7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEEGA1UdIAQ6MDgwNgYJYIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAdBgNVHQ4EFgQUNkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0f
# BGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEASBzctemaI7znGucgDo5nRv1CclF0CiNH
# o6uS0iXEcFm+FKDlJ4GlTRQVGQd58NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4
# eTZ6J7fz51Kfk6ftQ55757TdQSKJ+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2h
# F3MN9PNlOXBL85zWenvaDLw9MtAby/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1
# FUL1LTI4gdr0YKK6tFL7XOBhJCVPst/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6X
# t/Q/hOvB46NJofrOp79Wz7pZdmGJX36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZ
# oAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnF
# OVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQA
# OPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhis
# EeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQj
# MF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+f
# MRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW
# /5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAf
# BgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/
# AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYc
# aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafD
# DiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6
# HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4
# H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHK
# eZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIo
# xhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIwggWQMIIDeKADAgECAhAFmxtX
# no4hMuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBa
# Fw0zODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8G
# A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFd
# ZEzfLmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIA
# jeNkaA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvW
# VPjSPMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvI
# XQPK7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6M
# m0eBcg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQj
# YUIp5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A
# 7msgdDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab
# 4vriRbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA7
# 5PQ79ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5Wd
# GaG5nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQ
# zxm3i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyB
# Ia0HEEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67Z
# MA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5
# NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBT
# SEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV
# tC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0
# F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lv
# y0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrM
# xe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vku
# nKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNH
# R7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/r
# JvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i
# 4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyD
# KK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgR
# QRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhF
# MJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIw
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm
# 95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+
# N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE
# 5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4Imh
# vTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KV
# ssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwf
# iThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSc
# hh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3x
# GFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJs
# QfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pK
# HJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52Mb
# OoZWeE4wgge4MIIFoKADAgECAhAILtlw2MZ708ipFCjsiihmMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBT
# SEEzODQgMjAyMSBDQTEwHhcNMjExMDI2MDAwMDAwWhcNMjQxMDI0MjM1OTU5WjCB
# lTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEzARBgsrBgEEAYI3PAIB
# AxMCREsxETAPBgNVBAUTCDQyMDc3ODM2MQswCQYDVQQGEwJESzEPMA0GA1UEBxMG
# VmlieSBKMRYwFAYDVQQKEw1kb3RqZXNwZXIuY29tMRYwFAYDVQQDEw1kb3RqZXNw
# ZXIuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxyFHSy1G6vsn
# 1oT5vB5kAqt8RaaF7TqO8gNYMpB0QpXDTleX6N/B61Byb/OOalDZ/K85t2dDaBJQ
# Cyq4A6+/E+2Oo1XkhJ+ZDsQnhMgswQk810Rg8k4pVja4jyZF3mx+03tISyJ0ANAq
# vN5I6lLW26FhqtaxyG9yVFGw+Q3uX9wkKQ4zrZoXNCLsJHtMkMIAO8g9Vgl3gedX
# kkiwU37ompWmDaBlUoggIXobJE2A/knZ63MjG+aH6qbqgCUzrJhuF7NwEM/JAuz0
# Me12IlSEkipdn5LRiDa+EStm5rPmni/FEX3ePfHvGaw32g7llvkucc2D29lo/uIE
# Ih9BDhZWztyqZYvHK0n+ZZAu8QeAeghtrRdeIqB9n8Tsp/7Wd6NIFKMlbHZk7InN
# DP8H0SzM8qZd4qfufqVPPx6wloNhkYCytp1JXMa2paHtmUIRFC+9kKqVnmfT1gNf
# XUQl8rPGumU2ZTCtZzZwTd/vTbU3FrYFUORYJWKcvE6HwVIY4MYRTNQTqMZYb4i8
# vn87FPOLk0wVKtyitiXMd7yjnfG7M69/szTefkPY8kV62RTcmXYToRc+EVdYFTCW
# aIqW90ORSnPuITYRAR0SGB4tMqE5k8vJ8J7AYEv3Tk5bMBopxISte1DlfBMmYN6O
# xHNEacx5SZknMBFysJb6Rf8x1gROJp8CAwEAAaOCAi0wggIpMB8GA1UdIwQYMBaA
# FGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQ0yIVU8lIB8XoQryBDhweA
# 2U2+DDAmBgNVHREEHzAdoBsGCCsGAQUFBwgDoA8wDQwLREstNDIwNzc4MzYwDgYD
# VR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaow
# U6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRw
# Oi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmlu
# Z1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA9BgNVHSAENjA0MDIGBWeBDAEDMCkw
# JwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYB
# BQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQw
# DAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAEDNVCxePhpxpDHspit8j
# rwvZb+PrJCb1wWjUTlOv1TFMfUAysUk7DiDAB7Z5XZTloY5p6RQwoymHE2Vtsy9x
# jv4bIgGpQz3Savf7pW8wENyiL7GIkVfLIYjSxSoEbiHlnN/4gn2rWQ0STqtmuJVE
# 3uk91HL2raJTRCJpCyUp2gw9BPQmUYYKLanebEOmK0zvW+3IQdWizVRuf9fqbyH8
# nLZhVBSddVelokraexR8a2XWBgIjyrxfjXfo7S5gcNf6Bwmc9G5DOIvPhS7DXkGS
# hzsEn3iP2H69m0T51iS4M7zXyiVtkj0pXMSaytgdedX1D/vI8FT8NHc3pTKQ/301
# LUELbH4hOfA0+ynNg6Znx9MFMAYmx20d+VeFcdv3gI09KctMlzenwTqcoEs0OaAN
# F3nX3CkJ3lbV+8FJrpRX8rcqxPcg4QewV/JRNsFZbO0FlM+QdHi+zz5ES40hfefE
# L0LezG6KO5wWoP6aiogA7CL/Qz3UkLa9foS0cAa8kj09mC9RuwiRdJlfUvX4KwZz
# FaHtrOZJaAUkqwUDQbEPZ3GTCuQt8lLBpNmOu+GKVTyui/lj8+LZmm0el1qMnyzz
# Wa3yU+LbdVjo5p7AaoZtJrySzM4G73UblmY7c8/ark4g9hQa7QKsEF/lwAgJg68p
# 4sDM7R4UrteLSrPvfanIQxIxggVSMIIFTgIBATB9MGkxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEAgu2XDY
# xnvTyKkUKOyKKGYwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKEC
# gAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwG
# CisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFYFJQEO5lSqlee5RoHHXOc55fTE
# MA0GCSqGSIb3DQEBAQUABIICAGnJhgKzI9Cig8J1OrUnuGK+O6bHhKbPbvRq/bc2
# 1mp0GH9NIYKUjfMKZGAxwWni/RMLyNu5bkhMfknxmnAC+DtXGX35ISvKD/vlmuzp
# vlVcQNn2LtCwZ0Ab5NGOclX/NA4xLo9/nk8l0do6DhEHLLA15QkgMsqHABiOQ8zM
# MN4hbx5JpxOu3+ybKScixfMBEH2lnJJ0Wlz1yxotSfr9VH0YXsNNG+i1HhMPkkwX
# FPyv32OhKYvPBefIH/Wa5+IvOWtFazfr1/SilHJlzsj0D5LrTbFHgC2pjKLNAR5n
# 84e8qoXNyfbwO3DNrPaqBkQnv6XD7f6yF4aSV2wVsNOfzd2dNDm3qgZ7NVeQa/WX
# RLU+Jgw/cri9k6Ii9/r012EsETkX3nU0xYIAWNe5XgsZjOIzTPtKByqnKy8EtT2m
# 5Zp4X8Cx1BQxxlgCz3JOfFgdgZVX8zsxS8+EHSb1mH9rbrvk4xSUNrbROStejBvO
# 5cBNGRSsD5af+S4vku+qviPMlDWmNl+TCCYMUSRXKfR9+iInBxosj5ohD+OT6ova
# 0yebUCm5FPkirXr/PisZ57fSgXV7I7OYckdA67LRlmdjyPOcYuNL0AHke+TkFOTo
# GcBchbNtU1dFOq7LgapcMdO8E7l7XL0vRHIXt+Gg0PRg+JVWDijFwO0QBdnVX/iW
# Em8ToYICMDCCAiwGCSqGSIb3DQEJBjGCAh0wggIZAgEBMIGGMHIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3Rh
# bXBpbmcgQ0ECEA1CSuC+Ooj/YEAhzhQA8N0wDQYJYIZIAWUDBAIBBQCgaTAYBgkq
# hkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yMjAzMTUwNzIx
# NTNaMC8GCSqGSIb3DQEJBDEiBCAhixsYUqeY94ma1tIZVxohsA8AGwh734es6ENG
# LeFUczANBgkqhkiG9w0BAQEFAASCAQBfj04GMMfrmkzzIg2cSs6yBPsgN2iDDDBN
# a3Y464iA8j1zmQx5Pjs2il11ZARlciTelAofwCE0F4X1vVcHrvo9myjcKtjUeaid
# 6U7rpG6ND8PX0zbIrlpTfu3mLNW4tYQ6En6beUQ2RqanbLo7YeTqRzIKnH0Q9cU+
# KACuqt4g6NAiAn6zV1DNOYJTSuk9JlZ3KptS3IPYc/u/m1e+09aErn5TD2o1MWhB
# Nsrogz7Ec+RphDsuNgbgjRm209uWBctvu541pu0XF1E6pBRthwkx18/hwsN9tVhu
# oIDGJX2VSBKMoQRh+zs/N83QUnqNZipLuIrzMfs6hl0ifLXM1Y/l
# SIG # End signature block
