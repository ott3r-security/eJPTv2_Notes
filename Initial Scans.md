Initial nmap scans

```bash
sudo nmap -Pn -n $IP -sC -sV -p- --open -oX scan.xml
```

>sudo as it defaults to the faster half-open SYN scan, then -Pn to ignore ping and assume it is up, -n to ignore DNS, the IP address, -sC for default scripts, -sV for version information, -p- to scan all ports, and MOST importantly the — open argument to apply scripts and version scans to found open ports _only_ along with output to xml to use with metasploit


```bash
sudo nmap -Pn -n $IP -sU --top-ports=100 --reason
```

>Limit to top 100 ports as UDP scans take a while. --reason to see why ports are open|closed|filtered


Gobuster scans. These are more for THM and HTB as only dirbuster is available for eJPT

```bash
gobuster dir -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://$IP -t 42 -b 400,401,403,404 --no-error
```

>42 threads (-t 42),  exclude 400 response codes to reduce noise(-b 400,401,403,404) and suppressing error messages ( — no-error).

Fuzzing for file extensions txt, html, pdp
```bash
gobuster dir -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://$IP -x txt,html,php -o gobuster.log
```
