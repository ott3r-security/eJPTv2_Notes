
## Passive
```bash
host $HOST
whatweb $HOST
whois $HOST
whois $IP

dnsrecon -d $HOST

wafw00f -l
wafw00f $HOST -a

sublist3r -d $HOST
theHarvester -d $HOST
theHarvester -d $HOST -b all
```
# Google Dorks
```bash
site:
inurl:
site:*.sitename.com
intitle:
filetype:
intitle:index of
cache:
inurl:auth_user_file.txt
inurl:passwd.txt
inurl:wp-config.bak
```

## DNS
```bash
sudo nano /etc/hosts
dnsenum $HOST
# e.g. dnsenum zonetransfer.me

dig $HOST
dig axfr @DNS-server-name $HOST

fierce --domain $HOST
```