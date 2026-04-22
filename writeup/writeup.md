# Kernel Sanders
AArch Rootkit Killchain  
Team : Alice & Bob  
CY-4973/7790 -- Linux Kernel Security Writeup

## Table of Contents
 
1. [Project Overview](#1-project-overview)
2. [Attack Chain](#2-attack-chain)
3. [Component Breakdown](#3-component-breakdown)
   - [3.1 Beachhead - Initial Access](#31-beachhead-initial-access)
   - [3.2 Stager - In-Memory Delivery](#32-stager-in-memory-delivery)
   - [3.3 Local Privilege Escalation](#33-local-privilege-escalation)
   - [3.4 Reflective Rootkit Loader](#34-reflective-rootkit-loader)
   - [3.5 The Rootkit](#35-the-rootkit)
   - [3.6 Covert C2 Channel](#36-covert-c2-channel)
   - [3.7 Shellcode Injection](#37-shellcode-injection)
4. [Design Choices](#4-design-choices)
5. [Special Feature - Kernel Log Sanitization](#5-special-feature--kernel-log-sanitization)
6. [Indicators of Compromise](#6-indicators-of-compromise)
7. [Gaps](#7-gaps)
8. [Blockers](#8-blockers)
9. [Building and Running](#10-building-and-running)
---

## 1. Project Overview
 
KERNEL SANDERS is a fully automated, multi-stage kernel exploitation chain targeting a Linux AArch64 system. Nothing touches disk on the target. No manual intervention required beyond running one command on the attacker machine.
 
The chain delivers the rootkit entirely in memory, escalates privileges from analyst to root, loads the rootkit kernel module reflectively, exfiltrates classified PIR files, and leaves a covert control interface, while trying to wipe out some forensic evidence in the process. 

---

## 2. Attack Chain

The entire chain runs over a single inherited file descriptor (fd 3). This is created once by the stager, pinned via `dup2`, and inherited across every `execve` call. There are no new network connections after this initial callback.

| Stage | Disk writes | New network connections | Privilege |
|---|---|---|---|
| beachhead | none | none (reuses MERIDIAN's process) | analyst |
| stager | none | 1 (callback to Python) | analyst |
| exploit_privesc | none | none (inherits fd 3) | analyst --+ root |
| loader | none | none (inherits fd 3) | root |
| rootkit | none | none | ring 0 |

---
## 3. Component Breakdown
 
### 3.1 Beachhead - Initial Access
**The vulnerability :** The MERIDIAN service accepts a submit command that takes a length followed by raw bytes and executes them in the service's process space with no validation. This gives us code execution as an analyst and hence the foothold of our exploit. 

**What the beachhead does :**
The beachhead is 544 bytes of position-independent AArch64 shellcode delivered to the MERIDIAN service via the vulnerable submit command. It executes directly in MERIDIAN's process space with analyst-level privileges.  

Upon execution the beachhead forks the service process via ```clone()```. The parent continues serving requests normally, while the child proceeds with the attack. The child immediately calls ```setsid()``` to detach from MERIDIAN's session, so that it survives independently if the service is restarted or killed.  

The child opens a TCP socket and connects back to the attacker on port 4444. It receives an 8-byte header and validates the magic value ```0xDEADB17D``` before accepting any payload (rejecting random scanners and unsolicited connections). The payload bytes are received into an anonymous mmap buffer, written into a memfd_create file descriptor, and executed via ```execve("/proc/self/fd/N")```. The payload at this stage is the stager binary.  

The only artifact is a single outbound TCP connection and a short-lived child process that replaces itself with the stager via execve.

---

### 3.2 Stager - In-Memory Delivery

The stager is a statically linked AArch64 ELF binary delivered and executed in memory by the beachhead. Its primary purpose is to establish the persistent chain connection and deliver exploit_privesc to the target.  

The stager connects back to the attacker on port 4445 and receives ```exploit_privesc``` as a delivery frame over the same ```[magic][size][bytes]``` wire protocol established by the beachhead. The payload is received into an anonymous ```mmap``` buffer and written into a ```memfd_create``` file descriptor.  

The stager also performs a critical chain operation. ```dup2(sock, CHAIN_FD)``` pins the socket to file descriptor 3. Since open file descriptors survive across execve unless marked CLOEXEC, every subsequent binary in the chain inherits fd 3 and can read and write the attacker's connection without creating any new network connections. The original socket fd is closed after pinning.  

The stager then executes exploit_privesc and is replaced entirely by it. From this point forward the chain runs entirely over the inherited fd 3 connection with no new network events.  

---

### 3.3 Local Privilege Escalation

**The vulnerability :** ```vuln_rw``` is a vulnerable kernel driver that exposes two ioctl commands : ```VULN_KREAD``` and ```VULN_KWRITE```. These accept a kernel virtual address, a userspace buffer, and a length with no address validation and permission checks. The device is created with ```0666``` permissions making it accessible to the analyst as well.

**How the exploit works :** The strategy is to zero out our process's cred struct so that the kernel assumes that we are root.  

Every Linux process is represented in the kernel as a ```task_struct```. All task_structs are linked in a circular doubly-linked list via the ```tasks``` field. The kernel checks current->cred->uid for privilege decisions. If the uid is 0, we are root.

**Step 1** - ```init_task``` is the kernel's first process, always named "swapper/0". Its address is hardcoded from /proc/kallsyms on the target VM. The exploit reads 4KB from ```init_task``` and scans for the string "swapper/0" to locate the comm field. The cred pointer is then derived as :
```
cred_ptr_off = comm_off - 16;
```  
**Step 2** - The exploit walks the init_task.tasks circular linked list, reading each task's pid field until it finds its own PID obtained via getpid(). The tasks field stores a pointer to the tasks field of the next struct. The base is recovered by subtracting the tasks offset.  

**Step 3** - After our process's task_struct is located, it reads the cred pointer and zeroes all eight uid/gid fields. 

---

### 3.4 Reflective Rootkit Loader (and more)

**What it does :** It inherits fd 3 and has four responsibilities - load the rootkit reflectively, evade snitch, exfiltrate the PIR files, and hand off a root shell.

**Reflective Loading**
The loader receives ```rootkit.ko``` as a delivery frame over fd 3 into an anonymous ```mmap``` buffer. The bytes are written into a ```memfd_create``` file descriptor and loaded directly into the kernel via ```finit_module```

**Exfiltration** 
After the rootkit loads, the loader reads the three PIR files and sends them back over fd 3 using the same ```[magic][size][bytes]``` framing used throughout the chain

**Root Shell**
After exfil completes the loader redirects stdin, stdout, and stderr to fd 3 and execve's /bin/sh -i

**Snitch Evasion** 
Before loading the rootkit, the loader neutralises snitch. It scans ```/proc``` for a process named ```snitch_watcher``` that is the process responsible for receiving and reporting snitch's detections and kills it. Then it unloads the snitch kernel module using the ```delete_module``` syscall.

---

## 4. Design Choices
**1. Single inherited socket over multiple connections**  
We decide dto pin the socket to fd 3 in the stager via dup2 so all the subsequent binary inherits the same live TCP connection across execve. So we would have one outbound network event for the entire chain. The alternative approach was each stage opening its own connection, but that would means multiple detectable network events and socket code in every binary.

**2. Two ports -- 4444 and 4445**  
We used two ports because they serve fundamentally different purposes. Port 4444 is fire-and-forget with its purpose being that beachhead connects, tager is served and that connection closes. Port 4445 is the persistent chain connection that becomes fd 3. The practical reason for the split was a race condition we encountered. So we pre-bind 4445 before phase 1 starts so the stager can connect the instant it executes without getting a connection refused error.

**3. Separate stager to keep the beachhead minimal**
We could technically have the stager code as a part of the beachhead, but writing the full chain infrastructure in assembly was not something we were comfortable with, so we pushed everything beyond the basic functionality of the beachhead into the stager where we could work in C.

---
## 6. Indicators of Compromise
1. Single outbound TCP connection on port 4445
2. ioctl calls to `/dev/vuln_rw`
3. snitch.ko detectors before unloading
4. rootkit module visible (no module hiding)
5. Syscall hooks detectable via kernel integrity checkers
