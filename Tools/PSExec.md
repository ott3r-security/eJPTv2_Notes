#passthehash
#psexec 

>**PsExec is based on SMB and RPC connections**, which require ports 445, 139, and 135. However, Lazar added that there is an RPC implementation on top of HTTP, meaning that PsExec could potentially work over port 80, too
### Pass the Hash

Once NTLM hashes #hashdump have been collected they can be used to login normally using psexec

Inside msf use `/exploit/windows/smb/psexec`

Or running psexec directly via ex:
```
psexec.py Administrator:qwertyuiop@10.3.27.230

```

