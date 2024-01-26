The first step needed to improve this is to use Python to start an interactive shell. This can be done with Python’s PTY module, and works as follows:


### python
doesn't work in metasploit
```bash
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm
Ctrl z
stty raw -echo; fg
```
### pearl
```bash
pearl -e 'exec "/bin/bash";')
```
### ruby
```bash
ruby: -e exec "/bin/bash"

Create PATH if not founr
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
