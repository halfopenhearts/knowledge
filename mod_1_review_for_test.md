
Quick-reference checklist
Focus on disciplined enumeration and core persistence locations.

------------------------------------------------------------

1. Initial Triage

Windows
whoami
whoami /groups
hostname
ipconfig /all

Linux
whoami
id
hostname
ip a

Confirm:
- Current privilege level
- Group membership
- System context

------------------------------------------------------------

2. Privilege Escalation

Windows
whoami /groups
net localgroup administrators
Get-LocalGroupMember administrators

Look for:
- Nested groups inside Administrators
- Service accounts with unexpected privilege

Linux
id
cat /etc/group

Check:
- sudo access
- Unexpected group membership

------------------------------------------------------------

3. Windows Persistence

Run Keys
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKU\<SID>\Software\Microsoft\Windows\CurrentVersion\Run

Look for:
- Executables in user directories
- Obscure or non-Microsoft filenames
- Suspicious paths

Services
sc query
sc qc <service>
Get-CimInstance win32_service

Check:
- ImagePath
- ServiceDll
- Binary location
- Service running as SYSTEM

Reminder:
DisplayName is not always the same as ServiceName.

Scheduled Tasks
schtasks /query /fo LIST /v

Look for:
- SYSTEM tasks
- Tasks executing from user directories
- Suspicious arguments

PowerShell Profiles
$PROFILE

Check all:
- AllUsersAllHosts
- AllUsersCurrentHost
- CurrentUserCurrentHost
- CurrentUserAllHosts

Profiles can contain hidden persistence scripts.

------------------------------------------------------------

4. Linux Persistence

systemd
systemctl list-units --type=service
systemctl list-timers --all

Check:
 /etc/systemd/system/
 /lib/systemd/system/
 /run/systemd/generator/

Cron
crontab -l
cat /etc/crontab

GRUB / Boot
cat /boot/grub/grub.cfg

Look for:
- Modified boot parameters
- Suspicious modules

------------------------------------------------------------

5. Network Correlation

Windows
netstat -anob
Get-NetTCPConnection
Get-Process -Id <PID>

Correlate:
Port → PID → Process → Binary path

Linux
netstat -tulpn
ss -tulpn
lsof -i

------------------------------------------------------------

6. Event Logs

Windows
Get-WinEvent
Get-EventLog

Important PowerShell Event IDs:
4103
4104
4105
4106

Linux
journalctl -e
journalctl -u <service>

------------------------------------------------------------

7. Artifacts

Windows

Prefetch
C:\Windows\Prefetch

Jump Lists
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations

Alternate Data Streams
dir /R

------------------------------------------------------------

8. DLL and Process Investigation

List DLLs
tasklist /m
listdlls.exe <process>

Check signature
sigcheck -m <file>

Parent process relationship
Get-Process | Select Name, Id, ParentProcessId

Parent-child relationships matter.

------------------------------------------------------------

9. Boot Configuration (Windows)

bcdedit
bcdedit | findstr winload

Look for:
- Test signing
- Debug flags
- Modified loader entries

------------------------------------------------------------

Standard Investigation Order

1. Validate privilege
2. Check Run keys
3. Check Services
4. Check Scheduled Tasks
5. Check PowerShell profiles
6. Correlate network connections
7. Check artifacts
8. Check boot persistence

Follow structure every time.

------------------------------------------------------------

Core Mental Model

If something:
- Runs from a user-writable directory
- Executes as SYSTEM
- Persists across reboot
- Communicates externally

It is likely relevant.
