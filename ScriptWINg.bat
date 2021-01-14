@echo off

title Welcome to ScriptWINg by Lazerl0rd and Lyceris-chan

cls

rem Check if the script is being ran as Administrator
goto check_Permissions

:check_Permissions
	fsutil dirty query %systemdrive% >nul

    if %errorLevel%==0 (
        goto :warning
    ) else (
        goto :elevate_Permissions
    )

    pause >nul

:elevate_Permissions
echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
echo UAC.ShellExecute "cmd.exe", "/c %~s0 %~1", "", "runas", 1 >> "%temp%\getadmin.vbs"
"%temp%\getadmin.vbs"
del "%temp%\getadmin.vbs"
exit /B`

:warning
cls
echo Hello %username%,
echo this script changes specific registry values and enables hidden (unstable) Windows features. 
echo proceed at your own risk.
pause
goto menu


:menu
cls
echo Options:
echo -----------------------------------------------------------------

echo 1. Improve Performance 
echo 2. Fix VPN
echo 3. Enable hidden features
echo 4. Disable recent documents in File Explorer
echo 5. Expanded power Options
echo 6. Remove Graphics card control center entries from context menu
echo 7. Kill trackers / Debloat Windows 10
echo 8. Add DoH entries for AdGuard
echo -----------------------------------------------------------------

SET /P M=Enter your option:
IF %M%==1 GOTO perf
IF %M%==2 GOTO vpn
IF %M%==3 GOTO hidden
IF %M%==4 GOTO recent
IF %M%==5 GOTO power
IF %M%==6 GOTO gfx
IF %M%==7 GOTO debloat
IF %M%==8 GOTO adguard

:perf
cls
echo "    - Beginning registry changes"
1>NUL reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d 100 /f
rem ColdStartPerformanceImprovement1: 28556341
1>NUL "%~dp0ViVeTool.exe" addconfig 28556341
rem ColdStartPerformanceImprovement2: 28556372
1>NUL "%~dp0ViVeTool.exe" addconfig 28556372
rem InputAppPerfOptimizationUndocked: 28554502
1>NUL "%~dp0ViVeTool.exe" addconfig 28554502
rem ImproveTaskFlowLogonPerf: 27074523
1>NUL "%~dp0ViVeTool.exe" addconfig 27074523
rem InputAppPerfOptimizationDocked: 24106681
1>NUL "%~dp0ViVeTool.exe" addconfig 24106681
rem LogonPerfImprovements: 28362217 
1>NUL "%~dp0ViVeTool.exe" addconfig 28362217
rem LockReliability_PerformanceBoost: 9073709
1>NUL "%~dp0ViVeTool.exe" addconfig 9073709
rem SearchPerfOptimizations: 23755289
1>NUL "%~dp0ViVeTool.exe" addconfig 23755289
rem XAMLCandidateListPerfImprovements: 16281572
1>NUL "%~dp0ViVeTool.exe" addconfig 16281572
cls
echo Improve Performance has executed succesfully
pause
goto menu

:vpn
cls
echo "    - Beginning registry changes"
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PolicyAgent" /v "AssumeUDPEncapsulationContextOnSendRule" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v "DisableIKENameEkuCheck" /t REG_DWORD /d 1 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" /v "NegotiateDH2048_AES256" /t REG_DWORD /d 2 /f
cls
echo Fix VPN has executed succesfully
pause
goto menu

:hidden
cls

rem New bootanimation found by NTDEV_ source: https://twitter.com/NTDEV_/status/1351986340993368066
1>NUL reg import "%~dp0Win10XBootscreenWin10.reg"

rem Modern_Disk_Management_Link: 23257398
1>NUL "%~dp0ViVeTool.exe" addconfig 23257398 2

rem SuggestionUIOnDesktop: 20438551
1>NUL "%~dp0ViVeTool.exe" addconfig 20438551 2

rem ThemeAwareAndFluentTiles: 23615618
1>NUL "%~dp0ViVeTool.exe" addconfig 23615618 2

rem DesktopUVCMTC: 23403403
1>NUL "%~dp0ViVeTool.exe" addconfig 23403403 2

rem TryShellActivateApplicationFallback: 23674478
1>NUL "%~dp0ViVeTool.exe" addconfig 23674478 2

rem RedirectSystemControlPanel: 25175482
1>NUL "%~dp0ViVeTool.exe" addconfig 25175482 2

rem ThemeAwareSplashScreens: 25936164
1>NUL "%~dp0ViVeTool.exe" addconfig 25936164 2

rem MeetNow_Selfhost: 28582629
1>NUL "%~dp0ViVeTool.exe" addconfig 28582629 2

rem MeetNow_CreateButtonText: 28758888
1>NUL "%~dp0ViVeTool.exe" addconfig 28758888 2

rem MeetNow_Description: 28622680
1>NUL "%~dp0ViVeTool.exe" addconfig 28622680 2

rem MeetNow_SkypeLaunchPolicyCheck: 28622690
1>NUL "%~dp0ViVeTool.exe" addconfig 28622690 2

rem GraphicsCardInAbout: 27974039
1>NUL "%~dp0ViVeTool.exe" addconfig 27974039 2

rem SplitLayoutOnModernUX: 23881110
1>NUL "%~dp0ViVeTool.exe" addconfig 23881110 2

rem MeetNow: 28170999
1>NUL "%~dp0ViVeTool.exe" addconfig 28170999 2

rem EnableValueBanner: 18299130
1>NUL "%~dp0ViVeTool.exe" addconfig 18299130 2

rem DesktopUVCMTC: 23403403
1>NUL "%~dp0ViVeTool.exe" addconfig 23403403 2

rem TryShellActivateApplicationFallback: 23674478
1>NUL "%~dp0ViVeTool.exe" addconfig 23674478 2

rem DesktopLiteOobe: 26336822
1>NUL "%~dp0ViVeTool.exe" addconfig 26336822 2

rem Stubification: 21206371
1>NUL "%~dp0ViVeTool.exe" addconfig 21206371 2

rem Stubification|mach2.warning.duplicate0: 28384772
1>NUL "%~dp0ViVeTool.exe" addconfig 28384772 2

echo Do you want to enable News and interests as well? 
echo (requires Chromium based Edge [stable] to be installed)
SET /P M=Y or N:
IF %M%==y GOTO news
IF %M%==Y GOTO news
IF %M%==N GOTO ARM64X64EMULATIONSUPPORT
IF %M%==n GOTO ARM64X64EMULATIONSUPPORT

:news
cls
rem FeedsBackgroundWebViewRefresh: 29947361
1>NUL "%~dp0ViVeTool.exe" addconfig 29947361 2
rem FeedsContentRotationServerControl: 27833282
1>NUL "%~dp0ViVeTool.exe" addconfig 27833282 2
rem FeedsCore: 27368843
1>NUL "%~dp0ViVeTool.exe" addconfig 27368843 2
rem FeedsDataRefreshRateServerControl: 28247353
1>NUL "%~dp0ViVeTool.exe" addconfig 28247353 2
rem FeedsDynamicSearchBox: 27371092
1>NUL "%~dp0ViVeTool.exe" addconfig 27371092 2
rem FeedsTaskbarHeadline: 27371152
1>NUL "%~dp0ViVeTool.exe" addconfig 27371152 2
rem FeedsTaskbarHeadlineWidthThreshold: 30803283
1>NUL "%~dp0ViVeTool.exe" addconfig 30803283 2
rem FeedsTouchOpensFlyout: 30213886
1>NUL "%~dp0ViVeTool.exe" addconfig 30213886 2
echo News and interests has been enabled
goto ARM64X64EMULATIONSUPPORT

:ARM64X64EMULATIONSUPPORT
cls
if "%PROCESSOR_ARCHITECTURE%" == "ARM64" (
    rem   x64StoreAppsOnArm64: 24819336
	1>NUL "%~dp0ViVeTool.exe" addconfig 24819336 2
    rem   Arm64XProcessSupport: 29359153
	1>NUL "%~dp0ViVeTool.exe" addconfig 29359153 2
)

echo "    - Beginning registry changes"
1>NUL reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search\Flighting" /v ImmersiveSearch /t REG_DWORD /d "1" /f
1>NUL reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search\Flighting\Override" /v ImmersiveSearchFull /t REG_DWORD /d "1" /f
1>NUL reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search\Flighting\Override" /v CenterScreenRoundedCornerRadius /t REG_DWORD /d "9" /f

cls
echo Enable hidden features has executed succesfully
pause
goto menu


:recent
cls
echo "    - Beginning registry changes"
1>NUL reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f
1>NUL reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocs"			 /t REG_DWORD /d 0 /f
1>NUL reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory"	 /t REG_DWORD /d 0 /f
cls
echo Disable recent documents in File Explorer has executed succesfully
pause
goto menu

:power
cls
echo "    - Adding missing Intel Dynamic Tuning menus"
echo "If these already exist for you, adding them may overwrite the default settings."
set /P c="Type 'Y' to continue, or 'N' to skip: "
if /I "%c%" EQU "N" goto NoDynaTuning
1>NUL reg import "%~dp0IntelDPTF.reg"

:NoDynaTuning
echo "    - Beginning registry changes"
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\80e3c60e-bb94-4ad8-bbe0-0d3195efc663" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\0b2d69d7-a2a1-449c-9680-f91c70521c60" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\dab60367-53fe-4fbc-825e-521d069d2456" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\d639518a-e56d-4345-8af2-b9f32fb26109" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\fc95af4d-40e7-4b6d-835a-56d131dbc80e" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442\d3d55efd-c1ff-424e-9dc3-441be7833010" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238c9fa8-0aad-41ed-83f4-97be242c8f20\25dfa149-5dd1-4736-b5ab-e8a37b5b8187" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238c9fa8-0aad-41ed-83f4-97be242c8f20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238c9fa8-0aad-41ed-83f4-97be242c8f20\a4b195f5-8225-47d8-8012-9d41369786e2" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238c9fa8-0aad-41ed-83f4-97be242c8f20\abfc2519-3608-4c2a-94ea-171b0ed546ab" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238c9fa8-0aad-41ed-83f4-97be242c8f20\d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238c9fa8-0aad-41ed-83f4-97be242c8f20\94ac6d29-73ce-41a6-809f-6363ba21b47e" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\07029cd8-4664-4698-95d8-43b2e9666596" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\4a44b800-4f72-11dc-8314-0800200c9a66" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\63c39116-4f72-11dc-8314-0800200c9a66" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\b29c73e0-1a8b-46fd-b4ae-1ce5a3d6d871" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\48df9d60-4f68-11dc-8314-0800200c9a66\e6902942-b0cf-41f2-9225-20839490eb8c" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\4faab71a-92e5-4726-b531-224559672d19"									  /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc418" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35d" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35e" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318584" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4bdaf4e9-d103-46d7-a5f0-6280121616ef" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4e4450b3-6179-4e91-b8f1-5bb9938f81a1" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6c2993b0-8f48-481f-bcc6-00dd2742aa06" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\71021b41-c749-4d21-be74-a00f335d582b" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\75b0ae3f-bce0-45a7-8c89-c9611c25e100" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7d24baa7-0b84-480f-840c-1b0743c00f5f" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028" /v "Attributes" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7" /v "Attributes" /t REG_DWORD /d 2 /f

cls
echo Expanded power Options has executed succesfully
pause
goto menu

:gfx
cls
echo "    - Beginning registry changes"
1>NUL reg delete "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\ACE" /f
1>NUL reg delete "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\igfxcui" /f
1>NUL reg delete "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\igfxDTCM" /f
1>NUL reg delete "HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\NvCplDesktopContext" /f

cls
echo Remove Graphics card control center entries from context menu has executed succesfully
pause
goto menu

:debloat
cls
echo "    - Blocking malicious hosts in Windows Defender Firewall"
1>NUL netsh advfirewall firewall add rule name="telemetry_vortex.data.microsoft.com" dir=out action=block remoteip=191.232.139.254 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_telecommand.telemetry.microsoft.com" dir=out action=block remoteip=65.55.252.92 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_oca.telemetry.microsoft.com" dir=out action=block remoteip=65.55.252.63 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_sqm.telemetry.microsoft.com" dir=out action=block remoteip=65.55.252.93 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_watson.telemetry.microsoft.com" dir=out action=block remoteip=65.55.252.43,65.52.108.29 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_redir.metaservices.microsoft.com" dir=out action=block remoteip=194.44.4.200,194.44.4.208 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_choice.microsoft.com" dir=out action=block remoteip=157.56.91.77 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.7 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_reports.wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.91 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.93 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_services.wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.92 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_sqm.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.94 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.9 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_watson.ppe.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.11 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_telemetry.appex.bing.net" dir=out action=block remoteip=168.63.108.233 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_telemetry.urs.microsoft.com" dir=out action=block remoteip=157.56.74.250 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_settings-sandbox.data.microsoft.com" dir=out action=block remoteip=111.221.29.177 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_vortex-sandbox.data.microsoft.com" dir=out action=block remoteip=64.4.54.32 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_survey.watson.microsoft.com" dir=out action=block remoteip=207.68.166.254 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_watson.live.com" dir=out action=block remoteip=207.46.223.94 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_watson.microsoft.com" dir=out action=block remoteip=65.55.252.71 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_statsfe2.ws.microsoft.com" dir=out action=block remoteip=64.4.54.22 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_corpext.msitadfs.glbdns2.microsoft.com" dir=out action=block remoteip=131.107.113.238 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_compatexchange.cloudapp.net" dir=out action=block remoteip=23.99.10.11 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_cs1.wpc.v0cdn.net" dir=out action=block remoteip=68.232.34.200 enable=no
1>NUL netsh advfirewall firewall add rule name="telemetry_a-0001.a-msedge.net" dir=out action=block remoteip=204.79.197.200 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_statsfe2.update.microsoft.com.akadns.net" dir=out action=block remoteip=64.4.54.22 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_sls.update.microsoft.com.akadns.net" dir=out action=block remoteip=157.56.77.139 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_fe2.update.microsoft.com.akadns.net" dir=out action=block remoteip=134.170.58.121,134.170.58.123,134.170.53.29,66.119.144.190,134.170.58.189,134.170.58.118,134.170.53.30,134.170.51.190 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_diagnostics.support.microsoft.com" dir=out action=block remoteip=157.56.121.89 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_corp.sts.microsoft.com" dir=out action=block remoteip=131.107.113.238 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_statsfe1.ws.microsoft.com" dir=out action=block remoteip=134.170.115.60 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_pre.footprintpredict.com" dir=out action=block remoteip=204.79.197.200 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_i1.services.social.microsoft.com" dir=out action=block remoteip=104.82.22.249 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_feedback.windows.com" dir=out action=block remoteip=134.170.185.70 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_feedback.microsoft-hohm.com" dir=out action=block remoteip=64.4.6.100,65.55.39.10 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_feedback.search.microsoft.com" dir=out action=block remoteip=157.55.129.21 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_rad.msn.com" dir=out action=block remoteip=207.46.194.25 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_preview.msn.com" dir=out action=block remoteip=23.102.21.4 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_dart.l.doubleclick.net" dir=out action=block remoteip=173.194.113.220,173.194.113.219,216.58.209.166 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_ads.msn.com" dir=out action=block remoteip=157.56.91.82,157.56.23.91,104.82.14.146,207.123.56.252,185.13.160.61,8.254.209.254 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_a.ads1.msn.com" dir=out action=block remoteip=198.78.208.254,185.13.160.61 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_global.msads.net.c.footprint.net" dir=out action=block remoteip=185.13.160.61,8.254.209.254,207.123.56.252 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_az361816.vo.msecnd.net" dir=out action=block remoteip=68.232.34.200 enable=no
1>NUL netsh advfirewall firewall add rule name="telemetry_oca.telemetry.microsoft.com.nsatc.net" dir=out action=block remoteip=65.55.252.63 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_reports.wes.df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.91 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_df.telemetry.microsoft.com" dir=out action=block remoteip=65.52.100.7 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_cs1.wpc.v0cdn.net" dir=out action=block remoteip=68.232.34.200 enable=no
1>NUL netsh advfirewall firewall add rule name="telemetry_vortex-sandbox.data.microsoft.com" dir=out action=block remoteip=64.4.54.32 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_pre.footprintpredict.com" dir=out action=block remoteip=204.79.197.200 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_i1.services.social.microsoft.com" dir=out action=block remoteip=104.82.22.249 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_ssw.live.com" dir=out action=block remoteip=207.46.101.29 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_statsfe1.ws.microsoft.com" dir=out action=block remoteip=134.170.115.60 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_msnbot-65-55-108-23.search.msn.com" dir=out action=block remoteip=65.55.108.23 enable=yes
1>NUL netsh advfirewall firewall add rule name="telemetry_a23-218-212-69.deploy.static.akamaitechnologies.com" dir=out action=block remoteip=23.218.212.69 enable=yes

echo "    - Beginning registry changes"
1>NUL reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
1>NUL reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
1>NUL reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d "2" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d "1" /f
1>NUL reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
1>NUL reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\1>NUL taskkill.exe" /f
1>NUL reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\1>NUL taskkill.exe" /f
1>NUL reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
1>NUL reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d "1" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
1>NUL reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
1>NUL reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
echo "Blocking NTLM requests breaks Remote Desktop and Samba."
set /P c="Type 'Y' to continue blocking them, or 'N' to skip: "
if /I "%c%" EQU "Y" goto NTLMBlock
goto TaskRemoval

:NTLMBlock
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictReceivingNTLMTraffic" /t REG_DWORD /d 2 /f
1>NUL reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "RestrictSendingNTLMTraffic" /t REG_DWORD /d 2 /f
goto TaskRemoval

:TaskRemoval
echo "    - Removing malicious scheduled tasks"
1>NUL schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
1>NUL schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\AgentFallBack2016" /disable
1>NUL schtasks /Change /TN "Microsoft\Office\OfficeTelemetry\OfficeTelemetryAgentLogOn2016" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
1>NUL schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
1>NUL schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
1>NUL schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
1>NUL del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*"

echo "    - Removing OneDrive"
set /P c="Type 'Y' to remove OneDrive, or 'N' to skip this section: "
if /I "%c%" EQU "Y" goto OneDriveRemoval
goto ServiceRemoval

:OneDriveRemoval
1>NUL taskkill /F /IM onedrive.exe
1>NUL "%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe" /uninstall
1>NUL rd "%USERPROFILE%\OneDrive" /Q /S
1>NUL rd "C:\OneDriveTemp" /Q /S
1>NUL rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S
1>NUL rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S
1>NUL reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
1>NUL reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
1>NUL del /F /Q "%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe"

:ServiceRemoval
echo "    - Disabling malicious services"
1>NUL sc config "DiagTrack" start=disabled
1>NUL sc config "dmwappushservice" start=disabled
1>NUL sc config "diagsvc" start=disabled
1>NUL sc config "wlidsvc" start=demand

echo "    - Removing Microsoft Edge"
echo "Make sure to have installed another browser beforehand."
set /P c="Type 'Y' to continue removing Edge, or 'N' to skip this section: "
if /I "%c%" EQU "Y" goto EdgeRemoval
goto End

:EdgeRemoval
1>NUL taskkill /F /IM "browser_broker.exe"
1>NUL taskkill /F /IM "RuntimeBroker.exe"
1>NUL taskkill /F /IM "MicrosoftEdge.exe"
1>NUL taskkill /F /IM "MicrosoftEdgeCP.exe"
1>NUL taskkill /F /IM "MicrosoftEdgeSH.exe"
1>NUL move "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK"
1>NUL del /F /Q "C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK"
1>NUL reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\1>NUL taskkill.exe" /f

:End
cls
echo Kill trackers / Debloat Windows 10 has executed succesfully
pause
goto menu

:adguard
cls
echo "    - Adding DoH entries for AdGuard"
1>NUL netsh dns add encryption server=94.140.14.14 dohtemplate=https://dns.adguard.com/dns-query
1>NUL netsh dns add encryption server=94.140.15.15 dohtemplate=https://dns.adguard.com/dns-query
1>NUL netsh dns add encryption server=2a10:50c0::ad1:ff dohtemplate=https://dns.adguard.com/dns-query
1>NUL netsh dns add encryption server=2a10:50c0::ad2:ff dohtemplate=https://dns.adguard.com/dns-query

1>NUL netsh dns add encryption server=94.140.14.15 dohtemplate=https://dns-family.adguard.com/dns-query
1>NUL netsh dns add encryption server=94.140.15.16 dohtemplate=https://dns-family.adguard.com/dns-query
1>NUL netsh dns add encryption server=2a10:50c0::bad1:ff dohtemplate=https://dns-family.adguard.com/dns-query
1>NUL netsh dns add encryption server=2a10:50c0::bad2:ff dohtemplate=https://dns-family.adguard.com/dns-query

1>NUL netsh dns add encryption server=94.140.14.140 dohtemplate=https://dns-unfiltered.adguard.com/dns-query
1>NUL netsh dns add encryption server=94.140.14.141 dohtemplate=https://dns-unfiltered.adguard.com/dns-query
1>NUL netsh dns add encryption server=2a10:50c0::1:ff dohtemplate=https://dns-unfiltered.adguard.com/dns-query
1>NUL netsh dns add encryption server=2a10:50c0::2:ff dohtemplate=https://dns-unfiltered.adguard.com/dns-query
cls
echo Adding DoH entries for AdGuard has executed succesfully
pause
goto menu