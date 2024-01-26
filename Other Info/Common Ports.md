Port Numbers ---

Description
1	TCP Port Service Multiplexer (TCPMUX)
5	Remote Job Entry (RJE)
7	ECHO
18	Message Send Protocol (MSP)
20	FTP -- Data  -- File Transfer Protocol (FTP): used for uploading and downloading files to and from a server.
21	FTP -- Control -- File Transfer Protocol (FTP): used for uploading and downloading files to and from a server.
22	SSH Remote Login Protocol ****
23	Telnet
25	Simple Mail Transfer Protocol (SMTP): used for sending emails through a server. *****
29	MSG ICP
37	Time
42	Host Name Server (Nameserv)
43	WhoIs
49	Login Host Protocol (Login)
53	Domain Name System (DNS): Used for the translation of domain names to the IP addresses they are assigned to, employing the use of Name Servers. ***
69	Trivial File Transfer Protocol (TFTP)
70	Gopher Services
79	Finger
80	Hyper-Text Transfer Protocol (HTTP): used for (HTML) based web pages, and other types of web site files, such as Active Server Pages (ASP). 
103	X.400 Standard
108	SNA Gateway Access Server
109	POP2
110	POP3 Post Office Protocol (POP): Used for receiving emails from a server.
115	Simple File Transfer Protocol (SFTP)
118	SQL Services
119	Newsgroup (NNTP)
137	NetBIOS Name Service Network Basic Input/Output System NetBIOS allows applications on separate computers to communicate over a local area network.
139 smb
143	Interim Mail Access Protocol (IMAP) Alternate method used for receiving emails from a server, similar to the POP protocol.
150	NetBIOS Session Service
156	SQL Server
161	SNMP
179	Border Gateway Protocol (BGP)
190	Gateway Access Control Protocol (GACP)
194	Internet Relay Chat (IRC)
197	Directory Location Service (DLS)
389	Lightweight Directory Access Protocol (LDAP)
396	Novell Netware over IP
443	HTTPS Secure Socket Layer (SSL): 
444	Simple Network Paging Protocol (SNPP)
445	Microsoft-DS -- Server Message Block (SMB): Used for Microsoft Windows Networking communication.
458	Apple QuickTime
546	DHCP Client
547	DHCP Server
563	SNEWS
569	MSN
587 Alternate SMTP: Commonly used as a viable alternative to port 25, as some Internet Service Providers choose to block connectivity on port 25.
1080 Socks
1167 Continuous Data Protection (CDP): Used for the R1Soft Backup Agent for processing automated off-site server backups.

2433 – Microsoft Structured Query Language Server (SQL Server): Used for database connectivity between server and client computers. The port historically used for SQL communications is 1433, however port 1433 is often the subject of brute-force attacks, thus, we at Server Intellect choose to alter the SQL port to 2433 in an effort to reduce the amount of attacks against our servers.

3389 Remote Desktop Protocol (RDP): Used for connecting remotely to a server or client computer via Windows Remote Desktop.


Well-known ports range from 0 through 1023.
Registered ports are 1024 to 49151.
Dynamic ports (also called private ports) are 49152 to 65535.