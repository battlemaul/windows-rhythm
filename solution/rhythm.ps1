<# PSScriptInfo
.VERSION 0.9.9.0
.GUID A86971BB-9C5B-4540-B5C7-13CCDDE330EB
.AUTHOR @dotjesper
.COMPANYNAME dotjesper.com
.COPYRIGHT dotjesper.com
.TAGS windows powershell-5 windows-10 windows-11 endpoint-manager branding DSC
.LICENSEURI https://github.com/dotjesper/windows-rhythm/blob/main/LICENSE
.PROJECTURI https://github.com/dotjesper/windows-rhythm
.ICONURI
.EXTERNALSCRIPTDEPENDENCIES
.REQUIREDSCRIPTS
.RELEASENOTES https://github.com/dotjesper/windows-rhythm/wiki/release-notes
#>
<#
.SYNOPSIS
    Windows rhythm device baseline configurator (Windows Desired State Configuration).
.DESCRIPTION
    The goal of Windows rhythm is to provide a consistent baseline configuration to end user devices in Windows Autopilot scenarios.
    Windows rhythm can easily be implemented using more traditionally deployment methods, like OSD or other methods utilized.
    Current features:
    - WindowsApps: Remove Windows In-box Apps and Store Apps.
    - WindowsExecutables: Download and/or run executables.
    - WindowsFeatures
        - Enable and/or disable Windows features.
        - Enable and/or disable Windows optional features.
    - WindowsFiles: Copy file(s) to device from payload package.
    - WindowsRegistry: Modifying Windows registry entries (add, change and remove).
    - WindowsServices: Configure/re-configure Windows Services.
    To download sample configuration files and follow the latest progress, visit the project site.
.PARAMETER configFile
    Start script with the defined configuration file to be used for the task.
    If no configuration file is defined, script will look for .\config.json. If the configuration is not found or invalid, the script will exit.
.PARAMETER logFile
    Start script logging to the desired logfile.
    If no log file is defined, the script will default to log file within '%ProgramData%\Microsoft\IntuneManagementExtension\Logs' folder, file name <config.metadata.title>.log
.PARAMETER exitOnError
    If an error occurs, control if script should exit-on-error. Default value is $false.
.PARAMETER runSilent
    Set ProgressPreference to SilentlyContinue, hiding powershell progress bars. Default value is $true.
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
    [ValidateScript({ Test-Path $_ })]
    [string]$configFile = ".\config.json",
    [Parameter(Mandatory = $false)]
    [string]$logFile = "",
    [Parameter(Mandatory = $false)]
    [switch]$exitOnError,
    [Parameter(Mandatory = $false)]
    [bool]$runSilent = $true,
    [Parameter(Mandatory = $false)]
    [switch]$uninstall
)
begin {
    #region :: environment
    #endregion
    #region :: configuation file
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
    #endregion
    #region :: environment configurations
    [bool]$requireReboot = $($config.runConditions.requireReboot)
    [string]$envProgressPreference = $ProgressPreference
    [string]$envWarningPreference = $WarningPreference
    if ($runSilent) {
        $ProgressPreference = "SilentlyContinue"
        $WarningPreference = "SilentlyContinue"
    }
    #endregion
    #region :: logfile
    if ($($config.metadata.title)) {
        [string]$fLogContentpkg = "$($config.metadata.title -replace '[^a-zA-Z0-9]','-')"
        [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    else {
        [string]$fLogContentpkg = "$(([io.fileinfo]$MyInvocation.MyCommand.Definition).BaseName -replace '[^a-zA-Z0-9]','-')"
        [string]$fLogContentFile = "$($Env:ProgramData)\Microsoft\IntuneManagementExtension\Logs\$fLogContentpkg.log"
    }
    if ($logfile.Length -gt 0) {
        $logfileFullPath = Resolve-Path $logfile -ErrorAction SilentlyContinue -ErrorVariable _frperror
        if ($logfileFullPath) {
            [string]$fLogContentFile = $logfileFullPath
        }
        else {
            [string]$fLogContentFile = $_frperror[0].TargetObject
        }
    }
    #
    try {
        $fileChk = $(New-Object -TypeName System.IO.FileInfo -ArgumentList $($fLogContentFile)).OpenWrite();
        Write-Verbose -Message "$fLogContentFile is writeable: $($fileChk.CanWrite)"
        $fileChk.Close();
    }
    catch {
        $fLogContentDisable = $true
        Write-Warning -Message "Unable to write to output file $fLogContentFile"
        Write-Warning -Message $_.Exception.Message
    }
    finally {}
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
            if ($fLogContentDisable) {

            }
            else {
                try {
                    if (-not (Test-Path -Path "$(Split-Path -Path $fLogContentfn)")) {
                        New-Item -itemType "Directory" -Path "$(Split-Path -Path $fLogContentfn)" | Out-Null
                    }
                    Add-Content -Path $fLogContentfn -Value "<![LOG[[$fLogContentpkg] $($fLogContent)]LOG]!><time=""$($ftime)"" date=""$($fdate)"" component=""$fLogContentComponent"" context="""" type="""" thread="""" file="""">" -Encoding "UTF8" | Out-Null
                }
                catch {
                    throw $_.Exception.Message
                    exit 1
                }
                finally {}
            }
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
                        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    "HKCU" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKCU" -PSProvider "Registry" -Root "HKEY_CURRENT_USER" -Scope "Script" -Verbose:$false | Out-Null
                    }
                    "HKLM" {
                        fLogContent -fLogContent "registry PSDrive $($froot) not found, creating PSDrive." -fLogContentComponent "fRegistryItem"
                        New-PSDrive -Name "HKLM" -PSProvider "Registry" -Root "HKEY_LOCAL_MACHINE" -Scope "Script" -Verbose:$false | Out-Null
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
                        if (-not (Test-Path -Path "$($froot):\$($fpath)")) {
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
                        if (-not (Get-ItemPropertyValue -Path "$($froot):\$($fpath)" -Name "$fname" -ErrorAction "SilentlyContinue")) {
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
                    fLogContent -fLogContent "$($windowsApp.Name) is bundle: $($AppxPackage.IsBundle)." -fLogContentComponent "windowsApps"
                    fLogContent -fLogContent "$($windowsApp.Name) is non-removable: $($AppxPackage.NonRemovable)." -fLogContentComponent "windowsApps"
                    if ($($windowsApp.Remove) -eq $true) {
                        fLogContent -fLogContent "$($windowsApp.Name) is being removed from all users." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.Name) :: $($AppxPackage.Name)." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.Name) :: $($AppxPackage.PackageFullName)." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.Name) :: $($AppxPackage.PackageFamilyName)." -fLogContentComponent "windowsApps"
                        fLogContent -fLogContent "$($windowsApp.Name) :: $($AppxPackage.Version)." -fLogContentComponent "windowsApps"
                        try {
                            Remove-AppxPackage -AllUsers -Package "$($AppxPackage.PackageFullName)" -Verbose:$false | Out-Null
                            #Get-AppxPackage -PackageTypeFilter Main, Bundle, Resource | Where-Object {$_.PackageFullName -eq "$($AppxPackage.PackageFullName)"} | Remove-AppxPackage -Allusers -Verbose:$false
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
    #region :: windowsExecutables
    fLogContent -fLogContent "WINDOWS EXECUTABLES" -fLogContentComponent "windowsExecutables"
    if ($($config.windowsExecutables.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Executables is enabled." -fLogContentComponent "windowsExecutables"
        [array]$windowsExecutables = $($config.windowsExecutables.items)
        foreach ($windowsExecutable in $windowsExecutables) {
            fLogContent -fLogContent "Processing $($windowsExecutable.name)" -fLogContentComponent "windowsExecutables"
            fLogContent -fLogContent "$($windowsExecutable.description)" -fLogContentComponent "windowsExecutables"
            #region :: Expanding Windows environment variables
            if ($($windowsExecutable.filePath) -match "%\S+%") {
                #[Environment]::ExpandEnvironmentVariables does not work in Constrained language mode - workaround to be explored.
                if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
                    fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsExecutable.filePath)." -fLogContentComponent "windowsExecutables"
                    $windowsExecutable.filePath = [Environment]::ExpandEnvironmentVariables($windowsExecutable.filePath)
                    fLogContent -fLogContent "Windows Environment Variables resolved to $($windowsExecutable.filePath)." -fLogContentComponent "windowsExecutables"
                }
                else {
                    fLogContent -fLogContent "Windows Environment Variables is curently supported using Full Language mode only." -fLogContentComponent "windowsExecutables"
                    fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsExecutable.filePath) terminated." -fLogContentComponent "windowsExecutables"
                    Continue
                }
            }
            #endregion
            #region :: download item
            if ($($windowsExecutable.downloadUri)) {
                fLogContent -fLogContent "Download Uri $($windowsExecutable.downloadUri)" -fLogContentComponent "windowsExecutables"
                try {
                    Invoke-WebRequest -Uri $($windowsExecutable.downloadUri) -OutFile $($windowsExecutable.filePath)
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsExecutables"
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            #endregion
            #region :: executing item
            if (Test-Path $($windowsExecutable.filePath)) {
                fLogContent -fLogContent "File path $($windowsExecutable.filePath) exists." -fLogContentComponent "windowsExecutables"
                try {
                    if ($($windowsExecutable.ArgumentList)) {
                        fLogContent -fLogContent "Executing $($windowsExecutable.filePath) with arguments $($windowsExecutable.ArgumentList)." -fLogContentComponent "windowsExecutables"
                        Start-Process -FilePath $($windowsExecutable.filePath) -ArgumentList $($windowsExecutable.ArgumentList) -NoNewWindow -Wait

                    }
                    else {
                        fLogContent -fLogContent "Executing $($windowsExecutable.filePath) with no arguments." -fLogContentComponent "windowsExecutables"
                        Start-Process -FilePath $($windowsExecutable.filePath) -NoNewWindow -Wait
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsExecutables"
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
            }
            else {
                fLogContent -fLogContent "File not found [$($windowsExecutable.filePath)]" -fLogContentComponent "windowsExecutables"
            }
            #endregion
        }
    }
    else {
        fLogContent -fLogContent "Windows Executables is disabled." -fLogContentComponent "windowsExecutables"
    }
    #endregion
    #
    #region :: windowsFeatures
    fLogContent -fLogContent "WINDOWS FEATURES" -fLogContentComponent "windowsFeatures"
    if ($($config.windowsFeatures.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Features is enabled." -fLogContentComponent "windowsFeatures"
        #region :: windowsFeatures
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
                            $windowsFeatureResult = Enable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -All -NoRestart -Verbose:$false | Out-Null
                            if ($windowsFeatureResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished enabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
                        }
                        "DISABLED" {
                            fLogContent -fLogContent "disabling $($windowsFeature.DisplayName)." -fLogContentComponent "windowsFeatures"
                            $windowsFeatureResult = Disable-WindowsOptionalFeature -Online -FeatureName "$($windowsFeature.FeatureName)" -NoRestart -Verbose:$false
                            if ($windowsFeatureResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished disabling $($windowsFeature.DisplayName). Restart needed: $($windowsFeatureResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
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
        #endregion
        #region :: windowsOptionalFeatures
        fLogContent -fLogContent "WINDOWS OPTIONAL FEATURES" -fLogContentComponent "windowsOptionalFeatures"
        [array]$windowsOptionalFeatures = $($config.windowsFeatures.optionalFeatures)
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
                            $windowsCapabilityResult = Add-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                            if ($windowsCapabilityResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished installing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
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
                            $windowsCapabilityResult = Remove-WindowsCapability -Online -Name "$($windowsOptionalFeature.Name)" -Verbose:$false
                            if ($windowsCapabilityResult.RestartNeeded) {
                                $requireReboot = $true
                            }
                            fLogContent -fLogContent "finished removing $($windowsOptionalFeature.DisplayName), restart needed: $($windowsCapabilityResult.RestartNeeded)" -fLogContentComponent "windowsFeatures"
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
        #endregion
    }
    else {
        fLogContent -fLogContent "Windows Features is disabled." -fLogContentComponent "windowsFeatures"
    }
    #endregion
    #
    #region :: windowsFiles
    fLogContent -fLogContent "WINDOWS FILES" -fLogContentComponent "windowsFiles"
    if ($($config.windowsFiles.enabled) -eq $true) {
        fLogContent -fLogContent "Windows Files is enabled." -fLogContentComponent "windowsFiles"
        #region :: Expand assets
        [string]$assetFile = $($config.windowsFiles.assetFile)
        if (Test-Path -Path $assetFile -PathType Leaf) {
            fLogContent -fLogContent "Windows Files found $assetFile." -fLogContentComponent "windowsFiles"
            fLogContent -fLogContent "Windows Files is expanding $((Get-Item $assetFile).FullName)." -fLogContentComponent "windowsFiles"
            try {
                Expand-Archive -Path "$assetFile" -DestinationPath "$($Env:TEMP)" -Force
            }
            catch {
                $errMsg = $_.Exception.Message
                fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFiles"
                if ($exitOnError) {
                    exit 1
                }
            }
            finally {}
        }
        else {
            fLogContent -fLogContent "$assetFile ($((Get-Item $assetFile).FullName)) not present." -fLogContentComponent "windowsFiles"
        }
        #endregion
        [array]$windowsFileItems = $($config.windowsFiles.items)
        foreach ($windowsFileItem in $windowsFileItems) {
            fLogContent -fLogContent "Processing $($windowsFileItem.name)." -fLogContentComponent "windowsFiles"
            fLogContent -fLogContent "$($windowsFileItem.description)" -fLogContentComponent "windowsFiles"
            #region :: Build validation
            if ($([int]$windowsFileItem.minOSbuild) -eq 0) {
                fLogContent -fLogContent "minOSbuild: not specified" -fLogContentComponent "windowsFiles"
                [int]$windowsFileItem.minOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "minOSbuild: $($windowsFileItem.minOSbuild)" -fLogContentComponent "windowsFiles"
            }
            if ($([int]$windowsFileItem.maxOSbuild) -eq 0) {
                fLogContent -fLogContent "maxOSbuild: not specified" -fLogContentComponent "windowsFiles"
                [int]$windowsFileItem.maxOSbuild = $($([environment]::OSVersion.Version).Build)
            }
            else {
                fLogContent -fLogContent "maxOSbuild: $($windowsFileItem.maxOSbuild)" -fLogContentComponent "windowsFiles"
            }
            #endregion
            if ($($([environment]::OSVersion.Version).Build) -ge $([int]$windowsFileItem.minOSbuild) -and $($([environment]::OSVersion.Version).Build) -le $([int]$windowsFileItem.maxOSbuild)) {
                #region :: Expanding Windows environment variables
                if ($($windowsFileItem.targetFile) -match "%\S+%") {
                    #[Environment]::ExpandEnvironmentVariables does not work in Constrained language mode - workaround to be explored.
                    if ($($ExecutionContext.SessionState.LanguageMode) -eq "FullLanguage") {
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsFileItem.targetFile)." -fLogContentComponent "windowsExecutables"
                        $windowsFileItem.targetFile = [Environment]::ExpandEnvironmentVariables($windowsFileItem.targetFile)
                        fLogContent -fLogContent "Windows Environment Variables resolved to $($windowsFileItem.targetFile)." -fLogContentComponent "windowsExecutables"
                    }
                    else {
                        fLogContent -fLogContent "Windows Environment Variables is curently supported using Full Language mode only." -fLogContentComponent "windowsExecutables"
                        fLogContent -fLogContent "Windows Environment Variables found, resolving $($windowsFileItem.targetFile) terminated." -fLogContentComponent "windowsExecutables"
                        Continue
                    }
                }
                #endregion
                #region :: File copy process
                try {
                    if (Test-Path -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -PathType Leaf) {
                        fLogContent -fLogContent "$($Env:TEMP)\$($windowsFileItem.sourceFile) exist. Copying file to $($windowsFileItem.targetFile)." -fLogContentComponent "windowsExecutables"
                        Copy-Item -Path "$($Env:TEMP)\$($windowsFileItem.sourceFile)" -Destination "$($windowsFileItem.targetFile)" -Force
                    }
                    else {
                        fLogContent -fLogContent "$($Env:TEMP)\$($windowsFileItem.sourceFile) not found. File copy canceled." -fLogContentComponent "windowsExecutables"
                    }
                }
                catch {
                    $errMsg = $_.Exception.Message
                    fLogContent -fLogContent "ERROR: $errMsg" -fLogContentComponent "windowsFiles"
                    if ($exitOnError) {
                        exit 1
                    }
                }
                finally {}
                #endregion
            }
            else {
                fLogContent -fLogContent "item $($windowsFileItem.description) entry not for this OS build." -fLogContentComponent "windowsFiles"
            }
        }
    }
    else {
        fLogContent -fLogContent "Windows Files is disabled." -fLogContentComponent "windowsFiles"
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
                    if ($($windowsService.StartType) -eq $($windowsServiceStatus.StartType)) {
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
    #region :: resetting run Preference
    $ProgressPreference = $envProgressPreference
    $WarningPreference = $envWarningPreference
    #endregion
    fLogContent -fLogContent "Restart nedded: $requireReboot" -fLogContentComponent "clean-up"
    #region :: cleaning-up
    fLogContent -fLogContent "Finishing up" -fLogContentComponent "clean-up"
    fLogContent -fLogContent "Cleaning up environment" -fLogContentComponent "clean-up"
    #endregion
}

# SIG # Begin signature block
# MIIj9gYJKoZIhvcNAQcCoIIj5zCCI+MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDcXHtgm+41UNPq
# SUz0OOw/XTekYoN39RO8rgNq1ZoIfaCCDnAwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wgge4MIIFoKADAgECAhAILtlw2MZ708ipFCjsiihmMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjExMDI2MDAwMDAwWhcNMjQxMDI0
# MjM1OTU5WjCBlTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEzARBgsr
# BgEEAYI3PAIBAxMCREsxETAPBgNVBAUTCDQyMDc3ODM2MQswCQYDVQQGEwJESzEP
# MA0GA1UEBxMGVmlieSBKMRYwFAYDVQQKEw1kb3RqZXNwZXIuY29tMRYwFAYDVQQD
# Ew1kb3RqZXNwZXIuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# xyFHSy1G6vsn1oT5vB5kAqt8RaaF7TqO8gNYMpB0QpXDTleX6N/B61Byb/OOalDZ
# /K85t2dDaBJQCyq4A6+/E+2Oo1XkhJ+ZDsQnhMgswQk810Rg8k4pVja4jyZF3mx+
# 03tISyJ0ANAqvN5I6lLW26FhqtaxyG9yVFGw+Q3uX9wkKQ4zrZoXNCLsJHtMkMIA
# O8g9Vgl3gedXkkiwU37ompWmDaBlUoggIXobJE2A/knZ63MjG+aH6qbqgCUzrJhu
# F7NwEM/JAuz0Me12IlSEkipdn5LRiDa+EStm5rPmni/FEX3ePfHvGaw32g7llvku
# cc2D29lo/uIEIh9BDhZWztyqZYvHK0n+ZZAu8QeAeghtrRdeIqB9n8Tsp/7Wd6NI
# FKMlbHZk7InNDP8H0SzM8qZd4qfufqVPPx6wloNhkYCytp1JXMa2paHtmUIRFC+9
# kKqVnmfT1gNfXUQl8rPGumU2ZTCtZzZwTd/vTbU3FrYFUORYJWKcvE6HwVIY4MYR
# TNQTqMZYb4i8vn87FPOLk0wVKtyitiXMd7yjnfG7M69/szTefkPY8kV62RTcmXYT
# oRc+EVdYFTCWaIqW90ORSnPuITYRAR0SGB4tMqE5k8vJ8J7AYEv3Tk5bMBopxISt
# e1DlfBMmYN6OxHNEacx5SZknMBFysJb6Rf8x1gROJp8CAwEAAaOCAi0wggIpMB8G
# A1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQ0yIVU8lIB
# 8XoQryBDhweA2U2+DDAmBgNVHREEHzAdoBsGCCsGAQUFBwgDoA8wDQwLREstNDIw
# Nzc4MzYwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNV
# HR8Ega0wgaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOg
# UaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRD
# b2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA9BgNVHSAENjA0MDIG
# BWeBDAEDMCkwJwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
# UzCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
# Z2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAy
# MUNBMS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAEDNVCxeP
# hpxpDHspit8jrwvZb+PrJCb1wWjUTlOv1TFMfUAysUk7DiDAB7Z5XZTloY5p6RQw
# oymHE2Vtsy9xjv4bIgGpQz3Savf7pW8wENyiL7GIkVfLIYjSxSoEbiHlnN/4gn2r
# WQ0STqtmuJVE3uk91HL2raJTRCJpCyUp2gw9BPQmUYYKLanebEOmK0zvW+3IQdWi
# zVRuf9fqbyH8nLZhVBSddVelokraexR8a2XWBgIjyrxfjXfo7S5gcNf6Bwmc9G5D
# OIvPhS7DXkGShzsEn3iP2H69m0T51iS4M7zXyiVtkj0pXMSaytgdedX1D/vI8FT8
# NHc3pTKQ/301LUELbH4hOfA0+ynNg6Znx9MFMAYmx20d+VeFcdv3gI09KctMlzen
# wTqcoEs0OaANF3nX3CkJ3lbV+8FJrpRX8rcqxPcg4QewV/JRNsFZbO0FlM+QdHi+
# zz5ES40hfefEL0LezG6KO5wWoP6aiogA7CL/Qz3UkLa9foS0cAa8kj09mC9RuwiR
# dJlfUvX4KwZzFaHtrOZJaAUkqwUDQbEPZ3GTCuQt8lLBpNmOu+GKVTyui/lj8+LZ
# mm0el1qMnyzzWa3yU+LbdVjo5p7AaoZtJrySzM4G73UblmY7c8/ark4g9hQa7QKs
# EF/lwAgJg68p4sDM7R4UrteLSrPvfanIQxIxghTcMIIU2AIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBD
# QTECEAgu2XDYxnvTyKkUKOyKKGYwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3
# AgEMMQIwADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgEL
# MQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgmI+U3xsA+t3HbRutcB8Z
# V5iZzepyBnm6JNawMV9nGsEwDQYJKoZIhvcNAQEBBQAEggIAaDQ652ZTZmueHoGq
# e2EohyVdc3yPJLq1op8m39EPzrzRgLiP14x2TNiAjv1pTfo9P+gMJEgAglfvdnAD
# w+/mf5VUkBP3fBatRjfIJ0eGUZafGDTxK+6HD+hpd00CsC5/yeXfpJuyuNb5mBr3
# GVOqmbVjYqKJMyiyJCuq0XVsv5s7HrzN9PPk49eTNEaIyPM0weZ3RmoGGAKZsCr6
# HHZkaGI8Y/H5ch6mHFX76FHyMWPrnoGANvr6TSKFdXKuPZmLphvGz5PH1ZhGZYtk
# /qKSymkbZQnohkRXfJB8wc6OzSX0VhRESk2jZjhcGhhWstWMJQla/X4bA5J+vk3m
# qR15MD6SQfEimuOi+EgSggUEtOSpO/+7JKC1la+Cuu/dciyoauANimT7aA3ZnP53
# m3ASncW5sHbyeGDCg5lVf4ySK7xIKAx4eSxePl1OqfBFUowj9AqOYi7iAoqtWlsQ
# g9BZ6c8OF4715z+a7C1rJCIrthXCTczWA6iM0jfQWYYPvjUe3YX9ygUDgvUurM/O
# rpdL+DBfQ/PknxwORWLL7v+cZF71jzibyd2fY+ZjYCh54xqoJkViA96YWkUUfwHQ
# XvBeUm/xRIewCA16wGrHBOfif026+cw1jtEarPYI8p5Brb/JMhir8X0qeLnjIwJL
# fDgfb/0pmK4/FoLLG644gv9Ge32hghGyMIIRrgYKKwYBBAGCNwMDATGCEZ4wghGa
# BgkqhkiG9w0BBwKgghGLMIIRhwIBAzEPMA0GCWCGSAFlAwQCAQUAMHcGCyqGSIb3
# DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEFAAQgVzis
# yHr29bOTctFOcJZPmemI74kS/rEq/XCn1Biw558CEAS7Svky9GBSnDJML6g2XZAY
# DzIwMjIwNTA4MTIyOTM4WqCCDXwwggbGMIIErqADAgECAhAKekqInsmZQpAGYzhN
# hpedMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwMzI5MDAwMDAwWhcNMzMwMzE0
# MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# JDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALkqliOmXLxf1knwFYIY9DPuzFxs4+AlLtIx
# 5DxArvurxON4XX5cNur1JY1Do4HrOGP5PIhp3jzSMFENMQe6Rm7po0tI6IlBfw2y
# 1vmE8Zg+C78KhBJxbKFiJgHTzsNs/aw7ftwqHKm9MMYW2Nq867Lxg9GfzQnFuUFq
# RUIjQVr4YNNlLD5+Xr2Wp/D8sfT0KM9CeR87x5MHaGjlRDRSXw9Q3tRZLER0wDJH
# GVvimC6P0Mo//8ZnzzyTlU6E6XYYmJkRFMUrDKAz200kheiClOEvA+5/hQLJhuHV
# GBS3BEXz4Di9or16cZjsFef9LuzSmwCKrB2NO4Bo/tBZmCbO4O2ufyguwp7gC0vI
# CNEyu4P6IzzZ/9KMu/dDI9/nw1oFYn5wLOUrsj1j6siugSBrQ4nIfl+wGt0ZvZ90
# QQqvuY4J03ShL7BUdsGQT5TshmH/2xEvkgMwzjC3iw9dRLNDHSNQzZHXL537/M2x
# wafEDsTvQD4ZOgLUMalpoEn5deGb6GjkagyP6+SxIXuGZ1h+fx/oK+QUshbWgaHK
# 2jCQa+5vdcCwNiayCDv/vb5/bBMY38ZtpHlJrYt/YYcFaPfUcONCleieu5tLsuK2
# QT3nr6caKMmtYbCgQRgZTu1Hm2GV7T4LYVrqPnqYklHNP8lE54CLKUJy93my3YTq
# J+7+fXprAgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw
# ADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxqII+eyG8wHQYD
# VR0OBBYEFI1kt4kh/lZYRIRhp+pvHDaP3a8NMFoGA1UdHwRTMFEwT6BNoEuGSWh0
# dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQwOTZT
# SEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGDMIGAMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYBBQUHMAKGTGh0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFJTQTQw
# OTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggIBAA0t
# I3Sm0fX46kuZPwHk9gzkrxad2bOMl4IpnENvAS2rOLVwEb+EGYs/XeWGT76TOt4q
# OVo5TtiEWaW8G5iq6Gzv0UhpGThbz4k5HXBw2U7fIyJs1d/2WcuhwupMdsqh3KEr
# lribVakaa33R9QIJT4LWpXOIxJiA3+5JlbezzMWn7g7h7x44ip/vEckxSli23zh8
# y/pc9+RTv24KfH7X3pjVKWWJD6KcwGX0ASJlx+pedKZbNZJQfPQXpodkTz5GiRZj
# IGvL8nvQNeNKcEiptucdYL0EIhUlcAZyqUQ7aUcR0+7px6A+TxC5MDbk86ppCaiL
# fmSiZZQR+24y8fW7OK3NwJMR1TJ4Sks3KkzzXNy2hcC7cDBVeNaY/lRtf3GpSBp4
# 3UZ3Lht6wDOK+EoojBKoc88t+dMj8p4Z4A2UKKDr2xpRoJWCjihrpM6ddt6pc6pI
# allDrl/q+A8GQp3fBmiW/iqgdFtjZt5rLLh4qk1wbfAs8QcVfjW05rUMopml1xVr
# NQ6F1uAszOAMJLh8UgsemXzvyMjFjFhpr6s94c/MfRWuFL+Kcd/Kl7HYR+ocheBF
# ThIcFClYzG/Tf8u+wQ5KbyCcrtlzMlkI5y2SoRoR/jKYpl0rl+CL05zMbbUNrkdj
# OEcXW28T2moQbh9Jt0RbtAgKh1pZBHYRoad3AhMcMIIGrjCCBJagAwIBAgIQBzY3
# tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIwMzIzMDAwMDAw
# WhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBT
# SEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCwzIP5WvYRoUQV
# Ql+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFzsbPuK4CEiiIY
# 3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ7Gnf2ZCHRgB7
# 20RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7QKxfst5Kfc71
# ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/tePc5OsLDnipUjW
# 8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCYOjgRs/b2nuY7
# W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9KoRxrOMUp88qq
# lnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6dSgkQe1CvwWc
# ZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM1+mYSlg+0wOI
# /rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbCdLI/Hgl27Ktd
# RnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbECAwEAAaOCAV0w
# ggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1NhS9zKXaaL3WM
# aiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7ZvmKlEIgF+ZtbY
# IULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI2AvlXFvXbYf6
# hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/tydBTX/6tPiix6
# q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVPulr3qRCyXen/
# KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmBo1aGqwpFyd/E
# jaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc6UsCUqc3fpNT
# rDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3cHXg65J6t5TRx
# ktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0dKNPH+ejxmF/7
# K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZPJ/tgZxahZrrd
# VcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLeMt8EifAAzV3C
# +dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDyDivl1vupL0QV
# SucTDh3bNzgaoSv27dZ8/DGCA3YwggNyAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQCnpKiJ7JmUKQBmM4
# TYaXnTANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQ
# AQQwHAYJKoZIhvcNAQkFMQ8XDTIyMDUwODEyMjkzOFowKwYLKoZIhvcNAQkQAgwx
# HDAaMBgwFgQUhQjzhlFcs9MHfba0t8B/G0peQd4wLwYJKoZIhvcNAQkEMSIEIPmf
# zZwcSiqAhFnjfVh51aJlrI1R4RATz17xZovS9So5MDcGCyqGSIb3DQEJEAIvMSgw
# JjAkMCIEIJ2mkBXDScbBiXhFujWCrXDIj6QpO9tqvpwr0lOSeeY7MA0GCSqGSIb3
# DQEBAQUABIICAKsedKlX1WbVdbmBDMJSIcuG/1dwzHTp6OGh4TS5edZr1qdKVJgV
# St+Li4VsvEgZMcZw+xvOpOFSTlKU36EQwgzuwwLOs9i7D/n0y9qanpvwgFTQmwj0
# zw9BN1mHXjOXUUq2El6319oqgBn6wABq2Klxzv8gq5dpp+auJ6n07x8AfKDUbD0Z
# ZaKgOBl5KU5FhXwDTCxFVN3LdObQoWYzjSUfbr7oFdLCwnjhbjlXX7ZCVLZP1v7z
# vgRQQbhr9BQtkBLclHzAMyMuu1znpZv905OGDCIQF0btdvyqNsaA5ym0AdALEIMc
# VZjJ8K5lrhSJerUT4OHRouawrtE/mRaYcIuOJe3Z/CLA0bkaKCFGhEBPWZGJODn3
# 5NCKzje20jliG3SeLSu212zSiW0a2dRAncwFkvKVKOUlUmKpA2SvLvnmouQANB0A
# nq1HRnxgRWRmNogiOqMplun6N6jMty5xhN/mmy2BrEdTlQxgRJG2WQmTaWURaxwr
# ggWnVBUaEkEYreKOTiLaESdZtsDfKMeG0T3vePzvPcKJSvvI7RAdxUNK8OT3XFqb
# f65jxoz5sxM5C0aedsSwIn5jaVOrO3irWrlBukojQxx6p1g8lHjyzYIAVrc05+oA
# svEV/d20S46T9vn9M/mgP2SM9CpgzjNZ162CmvPu5Odtey5HC6qnaFMl
# SIG # End signature block
