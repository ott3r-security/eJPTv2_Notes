![](</Images/Pasted image 20231226191114.png>)

Scanning
`db_nmap` utilizes nmap inside metasploit

### linux
`sysinfo` shows system/session info
`getuid` user ID logged in as
`background` puts session in background
`sessions` list out active sessions
`search` works like find
`shell` opens native shell
`ps` list processes
`migrate <pid>` migrates into pid

Run command on background session
`sessions -C <command> -i <session>`

Rename sessions
`sessions -n <new name> -i <interface>`

### upgrade shell to meterpreter

Post exploitation method of using shell_to_meterpreter can be faster via:
`sessions -u <session ID>`
