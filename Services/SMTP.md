![](</Images/Pasted image 20231217182033.png>)

## metasploit

SMTP Version
```
scanner/smtp/smtp_version
```

SMTP User enum
```
scanner/smtp/smtp_enum
```

#haraka versions prior to v2.8.9 vulnerable to command injection
```
/exploit/linux/smtp/haraka
## nmap
```

## nmap 
Enumerate users
```bash
smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t $IP
```

Get banner:
```bash
nmap -sV -script banner $IP
```


## Netcat

Fetch hostname:
```bash
nc $IP 25
```

```bash
220 openmailbox.xyz ESMTP Postfix: Welcome to our mail server.
```

## smtp-user-enum
A tool for enumerating OS-level user account via the SMTP service

```bash
smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t $IP
```

## Sending email with telnet

```bash
telnet $IP 25
```

Send email to root user using **`sendemail`** command
```bash
sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s $IP -u Fakemail -m "Hello, world! A fake email" -o tls=no$
```

