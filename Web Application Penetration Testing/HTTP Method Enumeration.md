

Send GET request via cURL will return the html code from the site.
```bash
curl -X GET $IP
```


Sending HEAD request
```bash
curl -I $IP
```

Returns HEAD info from site. Ex:
```bash
root@attackdefense:~# curl -I 192.242.237.3
HTTP/1.1 200 OK
Date: Tue, 23 Jan 2024 03:42:56 GMT
Server: Apache
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Set-Cookie: PHPSESSID=ha9onk9jonl9j6fdno3qa57534; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html

```

Sending OPTIONS request to get options of course:
```bash
curl -X OPTIONS $IP -v
```

Return will shows different options allowed. Add -v for verbose
```bash
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Tue, 23 Jan 2024 03:45:39 GMT
< Server: Apache
< X-Powered-By: PHP/5.5.9-1ubuntu4.25
< Set-Cookie: PHPSESSID=p0anitd2pp1mfng9sctuakik93; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
< Pragma: no-cache
< Allow: GET,HEAD,OPTIONS
< Content-Length: 0
< Content-Type: text/html
```

Can use POST request type and send log in information.
```bash
curl -X POST $IP/login.php -d "name=john&password=password" -v
```

If there is an upload page run options to see if PUT is allowed. 
```bash
curl -X OPTIONS $IP/uploads/ -v

Allow: OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK
```

Then use PUT to upload a document. 

```bash
echo "Hello World" > hello.txt 
curl $IP/uploads/ --upload-file hello.txt
```

To delete:
```bash
curl -XDELETE $IP/uploads/hello.txt
```

