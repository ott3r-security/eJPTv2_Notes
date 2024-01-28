Two tools available #zaproxy and #nikito
[THM walkthough using both tools](https://ratiros01.medium.com/tryhackme-rp-web-scanning-45a949788f9f)

### Scanning Web Application with ZAProxy

>The OWASP Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications.

Usage:
```bash
root@kali:~# zaproxy -h
```

Open GUI, use quick start, enable "HUD". Once open has a tutorial option or HUD. Captures info as site is browsed.

### Scanning Web Application with Nikto

Help menu:
```bash
nikito -H
```

Simple scan:
```bash
nikto -h $IP
```

File retrieval in verbose mode:
```bash
nikto -h http://$IP$/index.php?page=arbitrary-file-inclusion.php -Tuning 5 -Display V
```

Output scan to html file for viewing later:
```bash
nikto -h http://$IP$/index.php?page=arbitrary-file-inclusion.php -Tuning 5 -o nikto.html -Format htm
```

