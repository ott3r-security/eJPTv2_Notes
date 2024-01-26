![](</Images/Pasted image 20240106152027.png>)
When running post exploit modules note where executables are stored

Ex.using `exploit(windows/local/persistence_service)`
 Metasploit will identity where file is written
 ```bash
[+] Meterpreter service exe written to C:\Users\ADMINI~1\AppData\Local\Temp\yMmMPlm.exe
```

As well as provide a cleanup file:
```bash
[*] Cleanup Meterpreter RC File: /root/.msf4/logs/persistence/ATTACKDEFENSE_20240122.0121/ATTACKDEFENSE_20240122.0121.rc
```

To run cleanup file:
```bash
/root/.msf4/logs/persistence/ATTACKDEFENSE_20240122.0121/ATTACKDEFENSE_20240122.0121.rc
```

This will stop service, delete service, and delete upload