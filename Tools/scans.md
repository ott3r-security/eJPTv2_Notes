# scanning info

use #searchsploit to search exploitdb database. Usage `searchsploit <service name>`

## nmap
- #nmap -sn don't scan ports. This scans for systems only. WIll just show discoverable hosts

To find scripts use `--script-help`

- netdiscover can also discover hosts. formats into nice table ex. netdiscover -i eth0 -r 10.35.35.0/24
 
-p- scans all ports (65k!)
-p and port number will scan specific port
-F scans top 100 ports
-sU does UDP. Default is TCP
	--top-port x and --open wil only can x ports and open ones. Much faster
-sV will detail check the services running this takes longer, should run after intial scans
-O might provide the operating system. Not always accurate
-sC does script scan. provides more details on open ports
-A does agressive scan which combines -sV, O, sC
Timing opitions. -T can use 1-5 lower is slower and helps keep scans hidden.
-Pn no port scan, Useul for windows to ignore ping
-iL can take in file/list of IP'a


## ARP scan
`arp-scan -I <interface> -g <ip range>`
that will scan out for connected devices and also return MAC addresses

`fping` can do similar but with ping only. So some Windows and other machines might miss ping. Same switches as `arp-scan`

## Notes
Windows usually blocks ICMP scans (like default nmap) so results will show nothing. To get around this use the switch -Pn. This bypasses checking if the host is up via ping

# other stuff

## scan with hidden type and scripts
```
nmap --randomize-hosts --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36 Edge/12.0i" --script-timeout 1
```

## scan all ports quickly with Rustscan
```
rustscan -a $ip --ulimit 5000  
```

## initial stealth scan
```
nmap -sS 
```

## secondary indepth scan
```
nmap -sV -O -oN scan_notes.txt
```


[Web app scanning with WMAP](obsidian://open?vault=cheatsheet&file=Tools%2FWMAP)
