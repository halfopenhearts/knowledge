UAC _ SYSINTERNALS
================

General Info
------------

  Host:
  -
  MATTHEW_WILLIS
  -
  IP:
  -
  10.50.15.85  
  -

Task:
- 
-

Focus:
- process validity
- UAC



masquerading malware as a legit service such as svchost, lsass

always investigate parent pid


process' = running thing
-  a running instance of a program with its own memory space and PID

DLL (dynamic link library)
-  a shared library loaded by a proces to provide functionality

service / daemon = long running thing
-  a long-running background process mananged by the OS, often start at boot


Get-Process | select-Ojbect Name, Id, CPU, WorkingGet
Get-Process smss, csrss, ksass
Get-Process *chrome*


Get-Process chrome | foreach {$_.modules} | more
  - > will find .dll for chrome

C:\windows\system32 - any .dll outside of this DLL is sus

powershell started by word or excel is sus

Get-CimInstance Win32_process - "pretty helpful"

cheat sheet:
tasklist /svc - services to pid
tasklist /m - show loaded DLL' for each process
tasklist / /fi "IMAGENAME eq chrome.exe" - emumerate DLL' for specific process

taskmgr: ctrol + shift + esc
switch todetails tab
sort by pid

peocexp (if available)
view parent/chind tree
ununsial parent process path
dll' tab

services enumeration commands 
_____________________________
sc query
sc queryex type-service
net start

schtasks - persistence ?

Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more

Pipe in ft -wrap to see full file name/path



run keys execute programs at logon
HKLM\software\microsoft\windows\currentversion\run
HKCU\..same..path..

RunOnce keys execute once, then delete

HKLM\...\RunOnce
HKCU\..,\RunOnce

services persist via registry=nacked configuration
HKLM\SYSTEM\CurrentControlSet\Services

per-user persistence via individual hives
HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Run

-*HKU DOES NOT NEED ADMIN RIGHTS*-

Get-NetTCPConnection -State Established
- State Listen
- Select LocalPort, RemoteAddress, State, OwningProcess

- Get-Process -Id <PID>

netstat -anob
-a all conections + listenings ports
-n numerical ips and ports
-o owning pid
-b executable responsible for connnection



TCPView (gui tool)




start of UAC (USER ACCOUNT CONTROL) - gatekeeping
required interactive concent

Registry key is located at "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


RISK CONTEXT
Red - Application or publisher blocked by group policy
Blue & gold - Administrative application
Blue - Trusted and Authenticode signed application
Yellow - Unsigned or signed but not trusted application


sigcheck -m C:\Windows\System32\slui.exe
strings -s C:\Windows\System32\*.exe | findstr /i autoelevate

UAC bypass with fodhelper.exe
  - > autoelevate binary
    > user registry lookups
    > exploits HKCU write acess


is not created by default
HKCU:\Software\Classes\ms-settings\shell\open\command




start of SysIntenrals
_____________________
shows live execution vs local installation
net use *
New-PSDrive

AUTORUNS identifies programs that automatically execute during boot
- system boot
- userl ogon

- common persistence locations include
- wubkigin
- services
- scheduled tasks
- appinit
- logon
- driver


tcpview tip
view -> update speed -> 5 seconds

  PsExec 
  - secure lightweight execution , similiar to telnet but misleading

  PsLoggedon
  - view logged on users on another device

  LogonSessions
  - display how users authenticated onto the system

  PsList - command-line utility for listing running processes
  can be run: locally, remotely and proviceds a gui
  supports timed refresh, unblike tasklist or Get-Process

  PsInfo - rapid host fingerprinting - good for determing things about like what os and kernel build and etc that youre running

  strings - static anaylsis
  - a (ascii) 

  handle - data structure representing an open instance of an os object
  example: files , registry keys, dlls, shared memory
  if a file cant be deleted its probably because of a handle
- without a handle there is no application


autorun -> how persistence surivives reboot
procmom 0> how systems behave over time
procexp -> whats running in the backgrorund








