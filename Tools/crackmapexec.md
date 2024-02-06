This package is a swiss army knife for pentesting Windows/Active Directory environments.

From enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.

The biggest improvements over the above tools are:

- Pure Python script, no external tools required
- Fully concurrent threading
- Uses **ONLY** native WinAPI calls for discovering sessions, users, dumping SAM hashes etc…
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject shellcode etc…)

Additionally, a database is used to store used/dumped credentals. It also automatically correlates Admin credentials to hosts and vice-versa allowing you to easily keep track of credential sets and gain additional situational awareness in large environments

Note: tool seems to be retired and replaced with https://github.com/Pennyw0rth/NetExec

Using new version:
NetExec
nxcdb