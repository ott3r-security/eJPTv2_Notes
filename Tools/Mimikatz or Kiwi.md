#NTML hash format
username:UID:LM hash:NTML hash
### modules (can also use #Kiwi via load in meterpreter)
win_privs
> enumerate current user privs

enum_logged_on_users
> numerate users that are logged on

checkvm
> check to see if system is vm or not. Useful to see if breaking out of vm is possible

enum_applicaitons
> see what programs are installed along with versions

enum_av_exluded
> will show folders that are excluded from AV program. If there is one exploits can be hidden here

enum_computers
>enumerate connected machines

enum_patches
> enumerate applied patches

All of this info is stored locally. if created in a workspace `loot` command will list out these files

### Mimikatz
This is Kiwi running Mimikatz in memory. Due to Mimikatz needing to be uploaded to target system. Can be found here:

From meterpreter: `upload /.usr/share/windows-resources/mimikatz/` then find correct version and file. Execute once on system. Commands are different. ie `privilege::debug` format

