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
---

## 1. Project Overview
 
KERNEL SANDERS is a fully automated, multi-stage kernel exploitation chain targeting a Linux AArch64 system. Nothing touches disk on the target. No manual intervention required beyond running one command on the attacker machine.
 
The chain delivers the rootkit entirely in memory, escalates privileges from analyst to root, loads the rootkit kernel module reflectively, exfiltrates classified PIR files, and leaves a covert control interface, while trying to wipe out some forensic evidence in the process. 

---
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

### 3.5 The Rootkit

Just like it's definition, the rootkit's purpose here is to actively hide our payloads and activity which may lead to disruption on our operation or getting caught.

When the rootkit.ko is loaded, it's very first entry point is the `rootkit_init` function inside `rootkit.c`. We will start our explanation from there.

#### 3.5.1 rootkit.c

**What it does:** `rootkit.c` is responsible for a few things. By definition it does the init/exit of all our other modules but the functionality of access blocking for our secret vaults (`/dev/sh/secret` and `/tmp/secret`) is also written inside it. 

`rootkit_init()` starts by calling the init blocks of all the other modules while also processing each and every module's return value. If any of the modules returns an error, the program jumps to the goto based error winding section at the end which gracefull calls the exit functions of all the successful module initializations (if any).

When the blocking_init() is called, this is where the blocking hook functionality comes in. it first takes a `unsigned long target_func_addr` and does what is called the kprobe lookup trick (written in `rootkit.h`) to get the address of the required symbol, which is `do_sys_openat2`. Since `register_kprobe`calls kallsyms internally, whenever a kprobe is registred on a symbol, it looks up that symbol and writes the address in the addr member of kprobe struct. This trick is helpful to resolve addresses of unexported symbols. Just as we get the target address we call `ftrace_set_filter_ip()` (with reset set to 0), which blocks all operations that do not match the target's address so that our ftrace does not hook all the functions of the kernel. Only after this do we call the `register_ftrace_function()`, and now our execution goes to blocking_callback().

`blocking_callback()` handles the main blocking logic. It first takes the filename from openat call's x1 register (2nd argument) into a userland character string, which we then copy to a kernel buffer using `strncpy_from_user()`. Since we cannot use a function like `kern_path()` which would automatically resolve our string in case it contains any traversal path, because the `kern_path()` tends to sleep and we are in a atomic context, we made a function called `normalize_path()` which would take a buffer and give us an absolute path solely by doing string manipulation. This function takes a path such as `/mnt/shared/capstone/../../../../tmp/secret/flag.txt` and keep track of the `/` to do necessary actions. Example walkthrough: for the input `/mnt/shared/capstone/../../../../tmp/secret/flag.txt`

| Step | Component | Action                | Stack depth | Output so far        |
|------|-----------|----------------------|-------------|----------------------|
| 0    | /         | write root           | 1           | /                    |
| 1    | mnt       | push & copy          | 2           | /mnt/                |
| 2    | shared    | push & copy          | 3           | /mnt/shared/         |
| 3    | capstone  | push & copy          | 4           | /mnt/shared/capstone/|
| 4    | ..        | pop (remove capstone) | 3           | /mnt/shared/         |
| 5    | ..        | pop (remove shared)  | 2           | /mnt/                |
| 6    | ..        | pop (remove mnt)     | 1           | /                    |
| 7    | ..        | already at root, stay | 1           | /                    |
| 8    | tmp       | push & copy          | 2           | /tmp/                |
| 9    | secret    | push & copy          | 3           | /tmp/secret/         |
| 10   | flag.txt  | push & copy          | 4           | /tmp/secret/flag.txt |

this results into an absolute path such as `/tmp/secret/flag.txt` which then is blocked.

Now coming to the actual blocking pattern, it goes like this: we take the now resolved path and see if matches with any of the secret vaults, if yes it also checks if it has a trailing null value or a `/` so that we do not block access to files like /tmp/secret123/. After this, we check if the caller (who ever did something like `cat`) has the `MAGIC_GID`, if they do not, e zero out the regs[0] field hence giving a bad address error (filename is now just `0`). 

Though this approach works here, it has a major flaw. This does not handle/block symlinks made to hidden directories (which `kern_path()` would have), hence symlinks would pass this blocking -+ Our remediation: A hook on do_symlinkat.

#### 3.5.2 slink_block.c

This is again a hook using the ftrace functionality, with the exact same blocking pattern (`inner_regs->regs[0] = 0;` //zero the old path) and again has the same normalize_path() to remove the possibility of bypass using traversal paths. The only difference here is that we now hook on `__arm64_sys_symlinkat` symbol. We started out by doing a hook on do_symlinkat (kernel land symbol) but for some reason the cpu wasn't allowing a hook on it so we shifted to this userland counterpart of the same syscall. The only new thing to implement here would to get the filename using the double pt_regs shenanigans.

On ARM64, when a function tracer (ftrace) hook intercepts a syscall, the hook's own callback receives a `pt_regs` structure representing the register state at the point of instrumentation. However, this outer `pt_regs` does not directly contain the syscall arguments as passed by userspace. Instead, the kernel's syscall wrapper convention on ARM64 means the wrapper function itself receives a single argument, a pointer to a second, inner `pt_regs`, which is stored in `regs[0]` of the outer structure. This inner pt_regs holds the actual CPU register state captured at the syscall entry boundary, and it is there that the original userspace arguments (such as filenames or flags passed in `x0`, `x1`, etc.) can be found. The result is a two level indirection: the ftrace provided registers point to the wrapper's argument, which is itself a pointer to the real saved user registers.

This will now enable us to block any symlinks being created on our secret vaults!

#### 3.5.3 file_hide.c

Moving on to the functionality where we hide our secret vaults from being shown if a non operator user does ls (list out directory entries). As we go from one functionality to another we hope these description become shorter since most use snippets from one another.

Here we are doing a Kretprobe on the `__arm64_sys_getdents64` syscall.

---
---

## 4. Design Choices
**1. Single inherited socket over multiple connections**  
We decide dto pin the socket to fd 3 in the stager via dup2 so all the subsequent binary inherits the same live TCP connection across execve. So we would have one outbound network event for the entire chain. The alternative approach was each stage opening its own connection, but that would means multiple detectable network events and socket code in every binary.

**2. Two ports -- 4444 and 4445**  
We used two ports because they serve fundamentally different purposes. Port 4444 is fire-and-forget with its purpose being that beachhead connects, tager is served and that connection closes. Port 4445 is the persistent chain connection that becomes fd 3. The practical reason for the split was a race condition we encountered. So we pre-bind 4445 before phase 1 starts so the stager can connect the instant it executes without getting a connection refused error.

**3. Separate stager to keep the beachhead minimal**
We could technically have the stager code as a part of the beachhead, but writing the full chain infrastructure in assembly was not something we were comfortable with, so we pushed everything beyond the basic functionality of the beachhead into the stager where we could work in C.

---
## 6. Indicators of Compromise (IoCs)
1. Single outbound TCP connection on port 4445
2. ioctl calls to `/dev/vuln_rw`
3. snitch.ko detectors before unloading
4. rootkit module visible (no module hiding)
5. Syscall hooks detectable via kernel integrity checkers
