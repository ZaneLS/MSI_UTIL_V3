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
echo Reverting !
timeout /t 1 /nobreak > NUL
start explorer.exe
start TextInputHost.exe
start TabTip.exe
start CompPkgSrv.exe
start ShellExperienceHost.exe
start smartscreen.exe
start TrustedInstaller.exe
start unsecapp.exe
timeout /t 1 /nobreak > NUL
echo Reverting Services
sc config WpnService start= Auto
sc start WpnService
sc config UsoSvc start= delayed-auto
sc start UsoSvc
sc config TrustedInstaller start= demand
sc start TrustedInstaller
sc config Themes start= auto
sc start Themes

timeout /t 1 /nobreak > NUL

echo Done! 
timeout /t 3 /nobreak > NUL
exit