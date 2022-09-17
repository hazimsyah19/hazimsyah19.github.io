---
title: Bolt Hackthebox
date: 11-10-2021
categories: [hackthebox,writeup]
tags: [subdomain,crack,sqlite,SSTI,pgp]
---

# Bolt
![Bolt infor card](/assets/img/bolt/bolt.png)

Bolt is a medium machine on Hackthebox. Start with an archive that we need to download and in the archive got credentials that we need to crack. Vhost is found and we can log in with the credentials that we crack before. The vhost is vulnerable to SSTI and from there we can craft our own SSTI payload to get reverse shell. From there with enumeration we found pgp private key block where it can crack. A message need is engrypted with pgp and then decrypt the message with gpg. From there we can get the root password and gain root.

## **Recon**

Nmap scan

```bash
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                                       
|   3072 4d:20:8a:b2:c2:8c:f5:3e:be:d2:e8:18:16:28:6e:8e (RSA)    
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDkj3wwSWqzkYHp9SbRMcsp8vHlgm5tTmUs0fgeuMCowimWCqCWdN358ha6zCdtC6kHBD9JjW+3puk65zr2xpd/Iq2w+UZzwVR070b3eMYn78xq+Xn6ZrJg25e5vH8+N23olPkHicT6tmYxPFp+pGo/FDZTsRkdkDWn4T2xzWLjdq4Ylq+RlXmQCmEsDtWvNSp3P
G7JJaY5Nc+gFAd67OgkH5TVKyUWu2FYrBc4KEWvt7Bs52UftoUTjodRYbOevX+WlieLHXk86OR9WjlPk8z40qs1MckPJi926adEHjlvxdtq72nY25BhxAjmLIjck5nTNX+11a9i8KSNQ23Fjs4LiEOtlOozCFYy47+2NJzFi1iGj8J72r4EsEY+UMTLN9GW29Oz+10nLU1M+G6DQDKxoc1phz/D0GShJeQw8JhO0L+m
I6AQKbn0pIo3r9/hLmZQkdXruJUn7U/7q7BDEjajVK3gPaskU/vPJRj3to8g+w+aX6IVSuVsJ6ya9x6XexE=
|   256 7b:0e:c7:5f:5a:4c:7a:11:7f:dd:58:5a:17:2f:cd:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF5my/tCLImcznAL+8z7XV5zgW5TMMIyf0ASrvxJ1mnfUYRSOGPKhT8vfnpuqAxdc5WjXQjehfiRGV6qUjoJ3I4=
|   256 a7:22:4e:45:19:8e:7d:3c:bc:df:6e:1d:6c:4f:41:56 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxr2nNJEycZEgdIxL1zHLHfh+IBORxIXLX1ciHymxLO
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 76362BB7970721417C5F484705E5045D
| http-methods:        
|_  Supported Methods: HEAD GET OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 82C6406C68D91356C9A729ED456EECF4
| http-methods:                                                                                                      
|_  Supported Methods: GET HEAD POST                                                                                 
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                          
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Issuer: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
```

Found the domain name of the IP and the subdomain of the IP. Add it inside /etc/hosts

Cannot register to the page since it return 500 internal error.

![Untitled](/assets/img/bolt/Untitled.png)

```bash
root@Rav3nCLaW [05:49:49 PM] [~/Documents/htb/bolt] 
-> # ffuf -c -u http://bolt.htb/ -H 'Host:FUZZ.bolt.htb' -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -ic -o subdomain-80 -fs 0,30347

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://bolt.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.bolt.htb
 :: Output file      : subdomain-80
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 0,30347
________________________________________________

mail                    [Status: 200, Size: 4943, Words: 345, Lines: 99]
demo                    [Status: 302, Size: 219, Words: 22, Lines: 4]
MAIL                    [Status: 200, Size: 4943, Words: 345, Lines: 99]
```

Found new subdomain and will enum to the subdomain.

```bash
root@Rav3nCLaW [05:46:27 PM] [~/Documents/htb/bolt] 
-> # ffuf -c -u http://bolt.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic -o 80-scan

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://bolt.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Output file      : 80-scan
 :: File format      : json
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

download                [Status: 200, Size: 18570, Words: 5374, Lines: 346]
                        [Status: 200, Size: 30347, Words: 10870, Lines: 505]
login                   [Status: 200, Size: 9287, Words: 2135, Lines: 173]
contact                 [Status: 200, Size: 26293, Words: 10060, Lines: 468]
services                [Status: 200, Size: 22443, Words: 7170, Lines: 405]
register                [Status: 200, Size: 11038, Words: 3053, Lines: 199]
pricing                 [Status: 200, Size: 31731, Words: 11055, Lines: 549]
logout                  [Status: 302, Size: 209, Words: 22, Lines: 4]
sign-in                 [Status: 200, Size: 9287, Words: 2135, Lines: 173]
sign-up                 [Status: 200, Size: 11038, Words: 3053, Lines: 199]
```

A download directory make us to download an image.tar. Download it and got  many directory.

![Untitled](/assets/img/bolt//Untitled%201.png)

Enumeration of demo vhost. A register form that different from the passbolt.bolt.htb/register. Form of the demo vhost need an invitation code.

![Untitled](/assets/img/bolt//Untitled%202.png)

Fuzz result of mail.bolt.htb

```bash
root@Rav3nCLaW [09:05:41 AM] [~/Documents/htb/bolt]                
-> # ffuf -c -u http://mail.bolt.htb/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -e .txt,.php,.js -t 50 -fs 162 -fw 345
                                                                   
        /'___\  /'___\           /'___\                            
       /\ \__/ /\ \__/  __  __  /\ \__/                            
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                           
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                           
         \ \_\   \ \_\  \ \____/  \ \_\                            
          \/_/    \/_/   \/___/    \/_/                            
                                                                   
       v1.3.1 Kali Exclusive <3                                    
________________________________________________                   
                                                                   
 :: Method           : GET                                                                                                            
 :: URL              : http://mail.bolt.htb/FUZZ                   
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt                                           
 :: Extensions       : .txt .php .js                               
 :: Follow redirects : false                                       
 :: Calibration      : false                                       
 :: Timeout          : 10                                                                                                             
 :: Threads          : 50                                          
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405                                                               
 :: Filter           : Response size: 162                          
 :: Filter           : Response words: 345                         
________________________________________________                                                                                      

Documents and Settings  [Status: 200, Size: 4973, Words: 347, Lines: 99]                                                              
Documents and Settings.js [Status: 200, Size: 4976, Words: 347, Lines: 99]                                                            
Documents and Settings.txt [Status: 200, Size: 4977, Words: 347, Lines: 99]                                                           
Program Files           [Status: 200, Size: 4964, Words: 346, Lines: 99]                                                              
Program Files.txt       [Status: 200, Size: 4968, Words: 346, Lines: 99]                                                              
Program Files.js        [Status: 200, Size: 4967, Words: 346, Lines: 99]                                                              
SQL                     [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
bin                     [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
config                  [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
installer               [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
logs                    [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
plugins                 [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
program                 [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
public_html             [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
reports list.txt        [Status: 200, Size: 4967, Words: 346, Lines: 99]                                                              
reports list.js         [Status: 200, Size: 4966, Words: 346, Lines: 99]                                                              
reports list            [Status: 200, Size: 4963, Words: 346, Lines: 99]                                                              
skins                   [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
temp                    [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
vendor                  [Status: 301, Size: 178, Words: 6, Lines: 8]                                                                  
tell_a_friend.txt       [Status: 200, Size: 0, Words: 1, Lines: 1]                                                                    
urls.js                 [Status: 200, Size: 0, Words: 1, Lines: 1]                                                                    
webim.txt               [Status: 200, Size: 0, Words: 1, Lines: 1]                                                                    
:: Progress: [18632/18632] :: Job [1/1] :: 384 req/sec :: Duration: [0:02:02] :: Errors: 0 ::
```

The result shows a lot of directory but need to pass the login page first.

As we got and image from `/download` we enumerate of the directory and check one by one does it have any informative file. 

```bash
root@Rav3nCLaW [10:56:55 AM] [~/Documents/htb/bolt/download/a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2/layer] 
-> # sqlite3 db.sqlite3 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .table
User
sqlite> Select * from User;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||
```

Got the admin password

```bash
root@Rav3nCLaW [10:58:14 AM] [~/Documents/htb/bolt] 
-> # john -w=/usr/share/wordlists/rockyou.txt johnhashadmin 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
deadbolt         (?)
1g 0:00:00:02 DONE (2021-12-24 10:58) 0.4739g/s 81850p/s 81850c/s 81850C/s debie..danee
Use the "--show" option to display all of the cracked passwords reliably
Session completed
root@Rav3nCLaW [10:58:38 AM] [~/Documents/htb/bolt] 
-> # john --show johnhashadmin 
?:deadbolt

1 password hash cracked, 0 left
```

![Untitled](/assets/img/bolt//Untitled%203.png)

![Untitled](/assets/img/bolt//Untitled%204.png)

There is a chat where it says that the demo is restricted to invite only so its mean that demo have the invite code and other register page do not have it. Since sarah says that docker image need to be scrubbed then it must have somthing inside it.

Found code where the id need is invite code so it must be somewhere inside the directory.

 

![Untitled](/assets/img/bolt//Untitled%205.png)

Explore the grep command to search about the invite_code that i found in the code above.

```bash
grep -iR 'invite_code' -A 2 2>/dev/null

i - ignore all the case letter
R - recursively read all the files and follow the symblinks 
A - print all the trailing match line 
```

## **Foothold**

After login as the user that already been created it redirect to the profile page. The page have the function to change the username of the account.

![Untitled](/assets/img/bolt//Untitled%206.png)

Try to put XXS payload but got nothing also the SSTI payload but got nothing changes at the page. Then login into the bolt webmail with the credential that have been created. At the page of the webmail got many email that says the email have Please confirm the email changes.

![Untitled](/assets/img/bolt//Untitled%207.png)

Check inside of the email and see that the username is change to 16.

![Untitled](/assets/img/bolt//Untitled%208.png)

SSTI is the vulnerability.

![Untitled](/assets/img/bolt//Untitled%209.png)

Put the reverse shell in the name input form and and click the link at the email and got the reverse shell.

Then in shell as www-data, www-data have its group directory which is /etc/passbolt. Found db creds inside it.

```php
//passbolt.php
return [
    'App' => [
        // A base URL to use for absolute links.
        // The url where the passbolt instance will be reachable to your end users.
        // This information is need to render images in emails for example
        'fullBaseUrl' => 'https://passbolt.bolt.htb',
    ],

    // Database configuration.
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'port' => '3306',
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',
        ],
    ],

    // Email configuration.
    'EmailTransport' => [
        'default' => [
            'host' => 'localhost',
            'port' => 587,
            'username' => null,
            'password' => null,
            // Is this a secure connection? true if yes, null if no.
            'tls' => true,
            //'timeout' => 30,
            //'client' => null,
            //'url' => null,
        ],
    ],
    'Email' => [
        'default' => [
            // Defines the default name and email of the sender of the emails.
            'from' => ['localhost@bolt.htb' => 'localhost'],
            //'charset' => 'utf-8',
            //'headerCharset' => 'utf-8',
        ],
    ],
    'passbolt' => [
        // GPG Configuration.
        // The keyring must to be owned and accessible by the webserver user.
        // Example: www-data user on Debian
        'gpg' => [
            // Main server key.
            'serverKey' => [
                // Server private key fingerprint.
                'fingerprint' => '59860A269E803FA094416753AB8E2EFB56A16C84',
                'public' => CONFIG . DS . 'gpg' . DS . 'serverkey.asc',
                'private' => CONFIG . DS . 'gpg' . DS . 'serverkey_private.asc',
            ],
        ],
        'registration' => [
            'public' => false,
        ],
        'ssl' => [
            'force' => true,
        ]
    ],
];
```

## **Privelege Escalation**

With linpeas find a directory email where it contents of an email between eddie and clark.

```bash
eddie@bolt:/var/mail$ cat eddie
cat eddie
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
        id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark
```

Find pgp private key block `~/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf$` then turn it into hash with gpg2john and crack it with john.

```bash
root@Rav3nCLaW [01:48:31 PM] [~/Documents/htb/bolt] 
-> # cat pgp.hash 
Eddie Johnson:$gpg$*1*668*2048*2b518595f971db147efe739e2716523786988fb0ee243e5981659a314dfd0779dbba8e14e6649ba4e00cc515b9b4055a9783be133817763e161b9a8d2f2741aba80bceef6024465cba02af3bccd372297a90e078aa95579afbd60b6171cd82fd1b32a9dd016175c088e7bef9b883041eaffe933383434752686688f9d235f1d26c006a698dd6cc132d8acb94c4eceebf010845d69cd9e114873538712f2cd50c8b9ca3bcb9bbc3d83e32564f99031776ac986195e643880483ac80d3f7f1b9143563418ddea7bb71d114c4f24e41134dcdac4662e934d955aeccae92038dbed32f300ac5abed65960e26486c5da59f0d17b71ad9a8fe7a5e6bb77b8c31b68b56e7f4025f01d534be45ab36a7c0818febe23fa577ca346023feefa2bfef0899dd860e05a54d8b3e8bd430f40791a52a20067fde1861d977adf222725658a4661927d65b877cb8ac977601990cfbdb27413f5acc25ff1f691556bc8e5264cffaebbea7e7b9d73de6c719e0a7b004d331eaada86e812e3db60904eaf73a1b79c6e68e74beb6b71f6d644afbf591426418976d68c4e580cbc60b6fdd113f239ae2acd1e1dc51cb74b96b3c2f082bc0214886e1c3cebb3611311d9112d61194df22fb3ceb5783ee7d4a61b544886b389f638fc85d5139f64997014ec38ac59e65b842d92afb50184ccc3549a57dcdb3fc8720cc394912aed931007b53da1c635d302e840da2e6342803831891ab1ccc1669f3cc3240b8d31eded96696d7ad1525c4d277a4d3123abecafdbdde207714539c2e546cd45c4452051394e5d00e711fa5353f817be4fa6827aa0f1428dfb93a918e93975fb4baf3297aa3b7fec33470cf2741237a629b869a762684602057f3e3e6df9c97631caa7589dc4b26653162dfb2f2cf508cbe375496ba735830c2c00f151cdd50c522afe33dbe4265d2*3*254*8*9*16*b81f0847e01fb836c8cc7c8a2af31f19*16777216*34af9ef3956d5ad8:::Eddie Johnson <eddie@bolt.htb>::pgp
```

```bash
#the password of the hash
john -w=/usr/share/wordlists/rockyou.txt pgp.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
merrychristmas   (Eddie Johnson)
1g 0:00:28:22 DONE (2021-12-26 14:17) 0.000587g/s 25.17p/s 25.17c/s 25.17C/s merrychristmas..menudo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

In database there is PGP Message.

```bash
-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQgAkS/2GvYLxglAIQpzFCydAPOj6QwdVV5BR17W5psc
g/ajGlQbkE6wgmpoV7HuyABUjgrNYwZGN7ak2Pkb+/3LZgtpV/PJCAD030kY
pCLSEEzPBiIGQ9VauHpATf8YZnwK1JwO/BQnpJUJV71YOon6PNV71T2zFr3H
oAFbR/wPyF6Lpkwy56u3A2A6lbDb3sRl/SVIj6xtXn+fICeHjvYEm2IrE4Px
l+DjN5Nf4aqxEheWzmJwcyYqTsZLMtw+rnBlLYOaGRaa8nWmcUlMrLYD218R
zyL8zZw0AEo6aOToteDPchiIMqjuExsqjG71CO1ohIIlnlK602+x7/8b7nQp
edLA7wF8tR9g8Tpy+ToQOozGKBy/auqOHO66vA1EKJkYSZzMXxnp45XA38+u
l0/OwtBNuNHreOIH090dHXx69IsyrYXt9dAbFhvbWr6eP/MIgh5I0RkYwGCt
oPeQehKMPkCzyQl6Ren4iKS+F+L207kwqZ+jP8uEn3nauCmm64pcvy/RZJp7
FUlT7Sc0hmZRIRQJ2U9vK2V63Yre0hfAj0f8F50cRR+v+BMLFNJVQ6Ck3Nov
8fG5otsEteRjkc58itOGQ38EsnH3sJ3WuDw8ifeR/+K72r39WiBEiE2WHVey
5nOF6WEnUOz0j0CKoFzQgri9YyK6CZ3519x3amBTgITmKPfgRsMy2OWU/7tY
NdLxO3vh2Eht7tqqpzJwW0CkniTLcfrzP++0cHgAKF2tkTQtLO6QOdpzIH5a
Iebmi/MVUAw3a9J+qeVvjdtvb2fKCSgEYY4ny992ov5nTKSH9Hi1ny2vrBhs
nO9/aqEQ+2tE60QFsa2dbAAn7QKk8VE2B05jBGSLa0H7xQxshwSQYnHaJCE6
TQtOIti4o2sKEAFQnf7RDgpWeugbn/vphihSA984
=P38i
-----END PGP MESSAGE-----
```

Need to decrypt the message and the previous password maybe is the password to decrypt it.

```bash
gpg --decrypt -a --pinentry-mode=loopback --passphrase="merrychristmas" pgp.asc

--pinentry-mode=loopback => Redirect Pinentry queries to the caller.  Note that in contrast to Pinentry the user is not prompted again if he enters a bad password.
```

Command to decrypt the PGP message with the passphrase that we get from the hash.

![Untitled](/assets/img/bolt//Untitled%2010.png)

Get into the root.

References:

[https://stackoverflow.com/questions/55780390/how-to-pass-encrypted-message-and-passphrase-when-using-os-system-to-call-gpg](https://stackoverflow.com/questions/55780390/how-to-pass-encrypted-message-and-passphrase-when-using-os-system-to-call-gpg)