Two main tools. Gobuster and Dirb (dirbuster GUI)

# Gobuster

Simple example using wordlist
```bash
gobuster -e -u http://$IP -w /usr/share/wordlists/dirb/common.txt
```


More examples with customization.

>42 threads (-t 42),  exclude 400 response codes to reduce noise(-b 400,401,403,404) and suppressing error messages ( — no-error)

```bash
gobuster dir -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://$IP -t 42 -b 400,401,403,404 --no-error
```


>Fuzzing for file extensions txt, html, pdp

```bash
gobuster dir -w '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://$IP -x txt,html,php -o gobuster.log
```

# Dirb

Default wordlist is `/usr/share/dirb/wordlists/common.txt` to change use --wordlist=x

Simple usage: 

```bash
dirb http://$URL
```

Can be done via Burpsuite as well.  [INE link if needed:](https://assets.ine.com/labs/ad-manuals/walkthrough-1886.pdf)


Search via extension
```bash
dirb http://$IP/ -X .txt
```


