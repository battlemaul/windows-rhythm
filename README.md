---
Title: README
Date: April 8, 2022
Author: dotjesper
Status: In development
---

# Windows rhythm

[![Built with Visual Studio Code](https://img.shields.io/badge/Built%20with-Visual%20Studio%20Code-blue?style=flat)](https://code.visualstudio.com/ "Built with Visual Studio Code")
[![Built for Windows 11](https://img.shields.io/badge/Buidt%20for-Windows%2011-blue?style=flat)](https://windows.com/ "Built for Windows 11")
[![Built for Windows 10](https://img.shields.io/badge/Built%20for-Windows%2010-blue?style=flat)](https://windows.com/ "Built for Windows 10")

[![PSScriptAnalyzer verified](https://img.shields.io/badge/PowerShell%20Script%20Analyzer%20verified-Yes-green?style=flat)](https://www.powershellgallery.com/packages/PSScriptAnalyzer/ "PowerShell Script Analyzer")
[![PowerShell Constrained Language mode verified](https://img.shields.io/badge/PowerShell%20Constrained%20Language%20mode%20verified-Yes-green?style=flat)](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes/ "PowerShell Language mode")

This repository contains the source code for Windows rhythm.
According to Wikipedia, Rhythm means a *"movement marked by the regulated succession of strong and weak elements, or of opposite or different conditions"*.

> Rhythm is related to and distinguished from pulse, meter, and beats.

Windows rhythm is exactly that, a multifunctional script designed to add pulse to Windows management beats.

This repository is under development and alive and for the most, kicking - I welcome any feedback or suggestions for improvement. Reach out on [Twitter](https://twitter.com/dotjesper "dotjesper"), I read Direct Messages (DMs) and allow them from people I do not follow. For other means of contact, please visit [https://dotjesper.com/contact/](https://dotjesper.com/contact/ "Contact")

Do not hesitate to reach out if issues arise or new functionality and improvement comes to mind.

Feel free to fork and build.

This is a personal development, please respect the community sharing philosophy and be nice!

## Goal

The goal of Windows rhythm is to provide a consistent desired state configuration to end user devices in Windows Autopilot scenarios.

Windows rhythm can easily be implemented using more traditionally deployment methods, e.g., Operating System Deployment (OSD), Task Sequences deployment or similar methods utilized.

## Synopsis

Windows rhythm was built to remove a few Windows features from Windows devices, managed using Microsoft Endpoint Manager and evolved into a tool to aligning Windows feature configuration, allowing to disable and enable Windows features. While building the key features, additional requirements surfaced, and being able to baseline Windows In-box App was added, allowing administrators to easily remove unwanted apps as part of the initially configuration, e.g., when enforcing corporate defaults as part of Windows Autopilot scenarios.

Further improvements were added, baseline conditions were requested, and Windows Service configuration and Windows Registry configuration options has been included.

There as several ways to achieve a Windows desired state configuration baseline and several approaches. Windows rhythm is built upon the requirement to provide a default configuration baseline, ot a desired state configuration, and is not meant to stop the end user to install a previously removed app, or circumvent a desired setting, purely to allow device administrators to provide a default baseline, or corporate baseline, to the end user as part of a Windows Autopilot scenario.

The mindset of the solution will aim to allow to limit and/or combine the functionalities best suited for the task, meaning if Windows feature configuration were to be applied, this should be achievable without the Windows Registry configuration. Also, very important, is to be able to apply Windows baselines configuration in one or multiple packages in either system or user context, without changing the code – which is why all configurations is achievable using configuration files (json). This will help ensure minimal effort to create a new Windows desired state configuration, being easily completed without any code changes or re-signing the provided code.

## Current features

- WindowsApps: Remove Windows In-box Apps and Store Apps.
- WindowsExecutables: Download and/or run executables.
- WindowsFeatures: Enabling and disabling Windows features.
- WindowsOptionalFeature: Enabling and disabling Windows optional features.
- WindowsRegistry: Modifying Windows registry entries (add, change and remove).
- WindowsServices: Configure/re-configure Windows Services.

## Requirements

Windows rhythm is developed and tested for Windows 10 21H1 Pro and Enterprise 64-bit and newer and require PowerShell 5.1.

**NOTE** Applying Windows desired state configurationn, **Windows rhythm** should be configured to run in either SYSTEM or USER context. Applying device Baseline in SYSTEM context, will be required to run with local administrative rights (Local administrator or System). Combining device Baseline across SYSTEM and USER is highly unadvisable and can cause undesired results.

## Repository content

```
├── samples
│  ├─ baselineAppsC.json
│  ├─ baselineFeaturesC.json
│  ├─ baselineFileOpenBehaviorC.json
│  ├─ baselineSettingsC.json
│  ├─ baselineSettingsU.json
│  ├─ baselineServicesC.json
│  ├─ baselineOfficeSettingsC.json
│  ├─ baselineOfficeSettingsU.json
├─ solution
│  ├─ configC.json
│  ├─ configU.json
│  ├─ rhythm.ps1
```

## Usage

**Windows rhythm** require a configuration file to work. The configuration file should be a valid json file, and the encoding should be UTF-8. The benefit using external configuration files, makes the solution more versatile and you can code sign the script once, and reuse the script for multiply deployment/tasks.

> I highly recommend code signing any script used in a deployment scenario. If you are unable to sign the script yourself, feel free to download a signed version from the [releases](https://github.com/dotjesper/windows-rhythm/releases/).

### Parameters

***-configFile***

*Type: String*

Start **Windows rhythm** with the defined configuration file to be used for the task. If no configuration file is defined, the script will look for .\config.json. If the configuration is not found or invalid, the script will exit.

***-logFile***

*Type: String*

Start **Windows rhythm** logging to the desired logfile. If no log file is defined, the script will default to **Windows rhythm** log file within %ProgramData%\Microsoft\IntuneManagementExtension\Logs\ folder.

***-exitOnError***

*Type: Switch*

If an error occurs, *exitOnError* control if the script should exit-on-error. Default value is $false.

***-uninstall***

*Type: Switch*

Future parameter for use in Micrsoft Intune package deployment scenarios. Default value is $false.

***-Verbose***

Displays detailed information about the operation performed by **Windows rhythm**. Without the -Verbose parameter, the script will run completely silent and will write output to the log file only.

### Examples
```powershell
.\rhythm.ps1 -Verbose

.\rhythm.ps1 -configFile ".\configC.json" -Verbose

.\rhythm.ps1 -configFile ".\configU.json" -logFile ".\logfile.log"

powershell.exe -NoLogo -ExecutionPolicy "AllSigned" -File ".\rhythm.ps1" -configFile ".\configC.json"
```

## Disclaimer

This is not an official repository, and is not affiliated with Microsoft, the **Windows rhythm** repository is not affiliated with or endorsed by Microsoft. The names of actual companies and products mentioned herein may be the trademarks of their respective owners. All trademarks are the property of their respective companies.

## Legal and Licensing

**Windows rhythm** is licensed under the [MIT license](./license 'MIT license').

The information and data of this repository and its contents are subject to change at any time without notice to you. This repository and its contents are provided AS IS without warranty of any kind and should not be interpreted as an offer or commitment on the part of the author(s). The descriptions are intended as brief highlights to aid understanding, rather than as thorough coverage.

## Change log

<details>
<summary>Click to expand change log</summary>

---

*Version 0.9.8.5 | April 16. 2022*

*Version 0.9.8.2 | April 8. 2022*

*Version 0.9.8.0 | March 14. 2022*

*Version 0.9.7.0 | March 9. 2022*

*Version 0.9.6.5 | March 6. 2022*

*Version 0.9.6.2 | February 18. 2022*

*Version 0.9.5.8 | February 18. 2022*

*Version 0.9.5.0 | February 17, 2022*

*Version 0.9.5.0 | January 23. 2022*

*Version 0.9.4.5 | January 7. 2022*

*Version 0.9.4.1 | October 9, 2021*

*Version 0.9.3.2 | October 8, 2021*

*Version 0.9.2.5 | October 5, 2021*

*Version 0.9.1.0 | September 12, 2021*

*Version 0.8.2.0 | September 10. 2022*

*Version 0.6.2.8 | September 6. 2022*

---

</details>
