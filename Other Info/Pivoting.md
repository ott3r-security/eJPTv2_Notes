![](<Images/Pasted image 20240121132113.png>)
![](<Images/Pasted image 20240121132405.png>)
![](</Images/Pasted image 20240121132443.png>)

For eJPT only metasploit is available for this. Other tools to look at chisel and ligolo-ng for later use

1. gain access to victim 1 first
2. use ipconfig or ifconfig
3. add new route inside meterpreter via below

>network output from victim 1
```
IPv4 Address : 10.0.29.148
IPv4 Netmask : 255.255.240.0
```

>run autoroute from metasploit via CIDR notation from above info
```
run autoroute -s 10.0.29.0/20
```

4. background the session to run port scanning since route is only inside metasploit
5. search `portscan` or type `auxiliary/scanner/portscan/tcp`
6. set options aka scan victim 2 address. doesn't return great info like versions. Need actual nmap which requires port forwarding
7. reactivate meterpreter session and run `portfwd add -l 1234 -p <remote port> -r <victim 2 IP>`
8. That will forward victim 2 to kali port 1234. now run nmap on kali
9. Run nmap like normal `nmap -sV -p 1234 localhost`
10. Exploit like normal just need to remember it's localhost and port 1234 or whatever specified in step 7. i.e. set options in metasploit
	- `set PAYLOAD windows/meterpreter/bind_tcp`
	- `set RHOSTS <viictim 2>`

post/multi/gather/ping_sweep\

### Broadcast Ping

```bash
ping 192.168.1.255
``` 

>add `-b` for linux