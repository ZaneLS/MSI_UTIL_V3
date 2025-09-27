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

cls
echo Goodluck! 
timeout /t 1 /nobreak > NUL
taskkill /f /im explorer.exe
taskkill /f /im TextInputHost.exe
taskkill /f /im TabTip.exe
taskkill /f /im CompPkgSrv.exe
taskkill /f /im ShellExperienceHost.exe
taskkill /f /im smartscreen.exe
taskkill /f /im TrustedInstaller.exe
taskkill /f /im unsecapp.exe
taskkill /f /im MicrosoftEdgeUpdate.exe
timeout /t 1 /nobreak > NUL
echo Disabling Services
sc config WpnService start= Disabled
sc stop WpnService
sc config UsoSvc start= Disabled
sc stop UsoSvc
sc config TrustedInstaller start= Disabled
sc stop TrustedInstaller
sc config Themes start= disabled
sc stop Themes


echo When you're done playing, write in the opened cmd tab "start explorer.exe"
pause
timeout /t 3 /nobreak > NUL
echo Now starting an explorer tab, start your game/launcher with It
start explorer.exe c:
start cmd.exe

timeout /t 1 /nobreak > NUL

echo Done! 
timeout /t 3 /nobreak > NUL
exit