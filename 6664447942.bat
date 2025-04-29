@echo off

echo Checking for Administrative Privelages...
timeout /t 3 /nobreak > NUL
IF "%PROCESSOR_ARCHITECTURE%" EQU "amd64" (
>nul 2>&1 "%SYSTEMROOT%\SysWOW64\cacls.exe" "%SYSTEMROOT%\SysWOW64\config\system"
) ELSE (
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
)

if '%errorlevel%' NEQ '0' (
    goto UACPrompt
) else ( goto GotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params= %*
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %params:"=""%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:GotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

echo Adding Tweaks!
cls
echo Adding Games Priority
echo Setting VRChat.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VRChat.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting Cs2.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cs2.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting Roblox.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\roblox.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting RobloxPlayerBeta.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RobloxPlayerBeta.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting ZenlessZoneZero.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ZenlessZoneZero.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting GenshinImpact.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\GenshinImpact.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting WutheringWave.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WutheringWave.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting Client-Win64-Shipping.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Client-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting hl2.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\hl2.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting Fragsurf.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Fragsurf.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting Hoi4.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\hoi4.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting ReadyOrNot-Win64-Shipping.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ReadyOrNot-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting javaw.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\javaw.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting LethalCompany.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Lethal Company.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LethalCompany.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting ContentWarning.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Content Warning.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ContentWarning.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Setting Valorant.exe as High Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Adding Games Priority
echo Adding CS:Source Priority
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cstrike_win64.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cstrike.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
timeout /t 1 /nobreak > NUL
cls
echo Done!
timeout /t 5 /nobreak > NUL
pause

exit