## commonly exploited windows services

highest account is Administrator as nt authority\system 

MS #IIS TCP ports 80/443 proprietary webservers developed by MS. Supoorted file extensions: .asp, .aspx, .config, .php

#WebDAV ports 80/443 has webserver act as file share server. Runs on top of IIS or Apache

#SMB #CIFS 445 network file sharing protocol "net-bios" also shares printers

#RDP port 3389 remote access protocol

#WinRM ports 5986/443 Windows remote access managemetn system

## WebDAV
#webdav
#davtest
use to check what files can be uploaded

using hydra to brute force -L for users -P passwords IP http-get (type) and folder /webdav/

metasploit common wordlists

#nmap script http-enum to find interesting folders

#cadaver
upload files