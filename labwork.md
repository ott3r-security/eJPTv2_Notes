10.3.26.175   demo.ine.local

local: 10.10.9.3 
tasks

## IIS FTP
10.3.29.101  21     tcp    ftp                   open   Microsoft ftpd
No anon. Brute time!
[21][ftp] host: 10.3.29.101   login: administrator   password: vagrant
 WATCH VIDEO ON THIS


## Open SSH
10.3.29.101  22     tcp    ssh                   open   OpenSSH 7.1 protocol 2.0

ms_x86.exe
ms_x64.exe


## SMB
10.3.29.101  139    tcp    netbios-ssn           open   Microsoft Windows netbios-ssn
10.3.29.101  445    tcp    microsoft-ds          open   Windows Server 2008 R2 Standard 7601 Service Pa


## MySQL
10.3.29.101  3306   tcp    mysql                 open   MySQL 5.5.20-log


## Other
10.3.29.101  4848   tcp    ssl/http              open   Oracle Glassfish Application Server
10.3.29.101  5985   tcp    http                  open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.3.29.101  7676   tcp    java-message-service  open   Java Message Service 301
10.3.29.101  8080   tcp    http                  open   Sun GlassFish Open Source Edition  4.0
10.3.29.101  8181   tcp    ssl/http              open   Oracle GlassFish 4.0 Servlet 3.1; JSP 2.3; Java
10.3.29.101  8484   tcp    http                  open   Jetty winstone-2.8
10.3.29.101  8585   tcp    http                  open   Apache httpd 2.2.21 (Win64) PHP/5.3.10 DAV/2


\