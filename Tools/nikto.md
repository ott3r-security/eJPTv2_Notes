Nikto is a simple, open-source web server scanner that examines a website and reports back vulnerabilities that it found which could be used to exploit or hack the site. Also, it's one of the most widely used website vulnerabilities tools in the industry, and in many circles, considered the industry standard.

Note: nikto is not stealthy and will likely be noticed by an IDS. 

Usage:

Simple scan
```bah
nikto -h $IP or $HOST
```

If site uses SSL add `-ssl` to parameters

Can output to a metasploit format:

```bash
nikto -h $IP or $HOST -Format msf+
```

