# Author: Panagiotis Fiskilis/Neuro

# Challenge name: Defcon DFIR 2019:Memory Forensics

## Description: ##

```
The challenge has 16 questions with 16 flags:
```

Download link:

```
https://drive.google.com/drive/folders/1JwK8duNnrh12fo9J_02oQCz8HlILKAdW
```

# Questions:

1. Get your Volatility on

	- What is the SHA1 hash of triage.mem?

2. pr0file

	- What profile is the most appropriate for this machine?

3. hey, write this down

	- What was the process ID of notepad.exe?

4. wscript can haz children

	- Name the child processes of wscript.exe

5. tcpip settings

	- What was the IP address of the machine at the time the RAM dump was created?

6. intel

	- Based on the answer regarding to the infected PID, can you determine what the IP of the attacker was.

7. i <3 windows dependencies

	-  What process name is VCRUNTIME140.dll associated with?

8. mal ware are you

	- What is the md5 hash value the potential malware on the system?

9. Im get bobs hash

	- What is the LM hash of bobs account?

10. vad the impaler

	- What protections does the VAD node at 0xfffffa800577ba10 have?

11. more vads?!

	- What protections did the VAD starting at 0x00000000033c0000 and ending at 0x00000000033dffff have?

12. vacation bible school

	- There was a VBS script run on the machine. What is the name of the script? (submit without file extension) 

13. thx microsoft

	- An application was run at 2019–03–07 23:06:58 UTC, what is the name of the program? (Include extension)

14. ligghtbulb moment

	- What was written in notepad.exe in the time of the memory dump? 

15. 8675309
	
	- What is the shortname of the file at file record 59045?

16. whats a metasploit

	- This box was exploited and is running meterpreter. What PID was infected? 

# Solution:

```bash
sha1sum Triage-Memory.mem
```

**1st Flag**

```bash
volatility -f Triage-Memory.mem imageinfo
```

**2nd Flag**

**Note:**

```--profile=Win7SP1x64```

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 pslist |grep -i "notepad"
```

0xfffffa80054f9060 notepad.exe            3032   1432      1       60      1      0 2019-03-22 05:32:22 UTC+0000

**3rd Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 pstree |tee pstree.log
cat pstree.log |grep -A 1 "wscript"
```

**4th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 netscan
```

**5th Flag**

From the <code>netscan</code> plugin we find this log:

```
0x13e397190        TCPv4    10.0.0.101:49217               10.0.0.106:4444      ESTABLISHED      3496     UWkpjFjDzM.exe 
```

**6th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 dlllist |tee dlllist.log
```

We open the dlllist.log file in sublime text and search for the dll file and get:

```
OfficeClickToR pid:   1136
Command line : "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" /service
Service Pack 1
```

**7th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 malfind |tee malfind.log
mkdir dump
volatility -f Triage-Memory.mem --profile=Win7SP1x64 procdump -p 3496 -D dump
```

**8th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 hashdump
```

**9th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 vadinfo |tee vadinfo.log
cat vadinfo.log |grep -A 10 "0xfffffa800577ba10" |grep -i "protection"
```

**10th Flag**

```bash
cat vadinfo.log |grep -A 10 "Start 0x00000000033c0000 End 0x00000000033dffff" |grep -i "protection"
```

**11th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 filescan |tee filescan.log
volatility -f Triage-Memory.mem --profile=Win7SP1x64 mftparser |tee mftparser.log
cat mftparser.log|grep "vbs"
```

**12th Flag**

```bash
volatility -f Triage-Memory.mem --profile=Win7SP1x64 cmdline |tee cmdline.log
volatility -f Triage-Memory.mem --profile=Win7SP1x64 cmdscan |tee cmdscan.log
volatility -f Triage-Memory.mem --profile=Win7SP1x64 consoles |tee consoles.log
volatility -f Triage-Memory.mem --profile=Win7SP1x64 shimcache |tee shimcache.log
cat shimcache.log |grep "2019–03–07"
```

**13th Flag**

```
https://www.andreafortuna.org/2017/07/10/volatility-my-own-cheatsheet-part-3-process-memory/
```

```bash
cat pstree.log |grep -i "notepad"
volatility -f Triage-Memory.mem --profile=Win7SP1x64 memdump -p 3032 -D dump
volatility -f Triage-Memory.mem --profile=Win7SP1x64 memmap -p 3032 |tee 3032_memmap.log
volatility -f Triage-Memory.mem --profile=Win7SP1x64 vadtree -p 3032 --output=dot --output-file=graph.dot
mkdir Vad_dump_dir
volatility -f Triage-Memory.mem --profile=Win7SP1x64 vaddump -p 3032 -D Vad_dump_dir
```

After some enumeration on the Vads we find the flag

**14th Flag**

```bash
cat mftparser.log |grep -A 20 "Record Number: 59045"
```

**15th Flag**

```
0xfffffa8005a1d9e0:UWkpjFjDzM.exe                3496   5116      5    109 2019-03-22 05:35:33 UTC+0000
```

**16th Flag**

# Flags:

1. ```FLAG<c95e8cc8c946f95a109ea8e47a6800de10a27abd>```
2. ```FLAG<Win7SP1x64>```
3. ```FLAG<3032>```
4. ```FLAG<UWkpjFjDzM.exe>```
5. ```FLAG<10.0.0.101>```
6. ```FLAG<10.0.0.106>```
7. ```FLAG<OfficeClickToR>```
8. ```FLAG<690ea20bc3bdfb328e23005d9a80c290>```
9. ```FLAG<aad3b435b51404eeaad3b435b51404ee>```
10. ```FLAG<PAGE_READONLY>```
11. ```FLAG<PAGE_NOACCESS>```
12. ```FLAG<vhjReUDEuumrX>```
13. ```FLAG<Skype.exe>```
14. ```FLAG<REDBULL_IS_LIFE>```
15. ```FLAG<EMPLOY~1.XLS>```
16. ```FLAG<3496>```
