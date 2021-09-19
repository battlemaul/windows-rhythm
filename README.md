---
Title: README 
Date: September 19, 2021
Author: dotjesper
Status: In development
---
# Windows rhythm

This repository contains the source code for Windows rhythm.
According to Wikipedia, Rhythm means a *"movement marked by the regulated succession of strong and weak elements, or of opposite or different conditions"*.

> Rhythm is related to and distinguished from pulse, meter, and beats.

Windows rhythm is exactly that, a multifunctional script designed to add pulse to Windows management beats.

Do not hesitate to reach out if issues arise or new functionality and improvement comes to mind. Feel free to fork and build.

Windows rhythm is under development and alive - I welcome any feedback or suggestions for improvement. Reach out on Twitter, I read Direct Messages (DMs) and allow them from people I do not follow. For other means of contact, please visit [https://dotjesper.com/contact/](https://dotjesper.com/contact/ "Contact")

This is a personal development, please respect the community sharing philosophy and be nice!

## Goal

The goal is to provide a consistent experience to end user devices using Windows Autopilot but can easily be implemented using more traditionally deployment methods, like OSD or other methods utilized.

## Synopsis

Windows rhythm was built to remove a few Windows features from Windows devices, managed using Microsoft Endpoint Manager and evolved into a tool to aligning Windows feature configuration, allowing to disable and enable Windows features. While building the key features, additional requirements surfaced, and being able to baseline Windows In-box App was added, allowing administrators to easily remove unwanted apps as part of the initially configuration, e.g., when enforcing corporate defaults as part of Windows Autopilot scenarios.

Further improvements were added, baseline conditions were requested, and Windows Service configuration and Windows Registry configuration options has been included.
There as several ways to achieve a Windows configuration baseline and several approaches. Windows rhythm is built upon the requirement to provide a default configuration baseline and is not meant to stop the end user to install a previously removed app, or circumvent a desired setting, purely to allow device administrators to provide a default baseline, or corporate baseline, to the end user as part of a Windows Autopilot scenario.

The mindset of the solution will aim to allow to limit and/or combine the functionalities best suited for the task, meaning if Windows feature configuration were to be applied, this should be achievable without the Windows Registry configuration. Also, very important, is to be able to apply Windows baselines configuration in one or multiple packages in either system or user context, without changing the code – which is why all configurations is achievable using configuration files (json). This will help ensure minimal effort to create a new Windows baselines configuration, being easily completed without any code changes or re-signing the provided code.

## Current features

- Enabling and disabling Windows features.
- Remove Windows In-box Apps and Store Apps.
- Configure/re-configure Windows Services.
- Modifying Windows registry entries (add and remove).

## Requirements

Windows rhythm is developed and tested for Windows 10 21H1 Pro and Enterprise 64-bit and newer and require PowerShell 5.1.

**NOTE** Applying required device Baseline configuration, **Windows rhythm** should be configured to run in either SYSTEM or USER context. Applying device Baseline in SYSTEM context, will be required to run with local administrative rights (Local administrator or System). Combining device Baseline across SYSTEM and USER is highly unadvisable and can cause undesired results.

## Content

```
|- samples
|--- baselineAppsC.json
|--- baselineFeaturesC.json
|--- baselineSettingsC.json
|--- baselineSettingsU.json
|--- baselineServicesC.json
|--- baselineOfficeSettingsC.json
|--- baselineOfficeSettingsU.json
|- source
|--- configC.json
|--- configU.json
|--- rhythm.ps1
```

## Usage

...

### Parameters

***-configFile***

 Start **Windows rhythm** with the defined configuration file to be used for the task. If no configuration file is defined, the script will look for .\config.json. If the configuration is not found or invalid, the script will exit.

***-logFile***

 Start **Windows rhythm** logging to the desired logfile. If no log file is defined, the script will default to **Windows rhythm** log file within %ProgramData%\Microsoft\IntuneManagementExtension\Logs\ folder.

***-Verbose***

Displays detailed information about the operation performed by **Windows rhythm**. Whitout the -Verbose parameter, the script i completely silent and will write output to the log file only.

### Examples
```powershell
.\rhythm.ps1 -Verbose

.\rhythm.ps1 -configFile ".\configC.json" -Verbose

.\rhythm.ps1 -configFile ".\configU.json" -logFile ".\logfile.log"

powershell.exe -NoLogo -ExecutionPolicy RemoteSigned -File ".\rhythm.ps1" -logFile "%temp%\output.log"
```

## Disclaimer

This is not an official repository, and is not affiliated with Microsoft, the **Windows rhythm** repository is not affiliated with or endorsed by Microsoft. The names of actual companies and products mentioned herein may be the trademarks of their respective owners. All trademarks are the property of their respective companies.

## Legal and Licensing
**Windows rhythm** is licensed under the [MIT license](./license 'MIT license').

The information and data of this repository and its contents are subject to change at any time without notice to you. This repository and its contents are provided AS IS without warranty of any kind and should not be interpreted as an offer or commitment on the part of the author(s). The descriptions are intended as brief highlights to aid understanding, rather than as thorough coverage.
