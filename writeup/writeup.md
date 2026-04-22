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

Here we are doing a Kretprobe on the `__arm64_sys_getdents64` syscall. Kretprobe allows us to hook onto a symbol call on return. We switched from ftrace because even though ftrace has a similar on return hooking functionality using IP redirect, this (kretprobe technique) came more intuitively to us. 

On init we do a simple `register_kretprobe()` to register our kprobe and resolve our symbol. Then before the execution goes to `file_hide_return()` for the actual hiding logic we get a entry handler first where we do the same double pt_regs thing described in 3.5.2, dereferencing the outer ftrace registers to reach the inner syscall entry registers, to get the filename on which getdents64 was called on. 

Now, on finally reaching return handler of our kretprobe, we first filter the call ona few baselines starting from the check with least over head to higher one. We start with checking if getdents return nothing, we return since there is nothing to filter. Then we check if the caller is operator or not using the `caller_has_magic_gid()` function (written in `rootkit.h`). Next we check if the call is even on our secret vault's parent directory or not (`/dev/shm` & `/tmp`). Once we pass all these filters, all we need to do now is to walk the dirent buffer and remove any occurance of "secret".

For each entry, we compare its name against our hidden filename. If it doesn't match, we simply move on to the next entry. If it does match and it's not the first entry in the buffer, we make the previous entry absorb the hidden one by adding the hidden entry's record length to the previous entry's `d_reclen`, effectively making the kernel skip over it. If the match happens to be the very first entry, there is no previous entry to expand, so instead we `memmove` the entire remaining buffer forward to overwrite it and shrink `total_bytes` accordingly, without advancing the offset since new data now sits at the same position.

Once the hiding is done, we write filtered buffer back to userspace (using `copy_to_user()`) and also send the new total bytes count in the `0` register.

#### 3.5.4 proc_hide.c

Moving on to the other kretprobe hook on the same symbol, `getdents64`, here we hide any and all processes that has the `MAGIC_GID` as a part of their supplementary groups. The rest of the filtering stays the same as `file_hide.c` we first do some no-op checks like if `getdents64` return `0`, or if the file being listed is `/proc` and then walk the dirent buffer to find entries with `MAGIC_GID` in their supplementary groups.

Now the main question is how do we check if process has `MAGIC_GID`. Also how does a process get this `MAGIC_GID` in their supplementary groups. For these two questions, we implement `process_has_magic_gid()` and `proc_hide_add_pid()` respectively.

Starting with `proc_hide_add_pid()`. `proc_hide_add_pid()` is how we grant a process the operator status. It takes a pid, looks up its task_struct under RCU protection, and then calls `prepare_kernel_cred()` to get a mutable copy of that task's credentials. From there, we allocate a `new group_info` that is one slot larger than the original, copy over all the existing supplementary groups, and append our `MAGIC_GID` at the end. After sorting the group list with `groups_sort()` (which the kernel expects), we swap the new credentials onto the target task by replacing both `real_cred` (how the kernel acts upon the task) and `cred` (how the task acts upon other objects) using `rcu_assign_pointer()`. The old credentials are then released. At the end of this, the process now carries our magic group and will pass all the operator checks across our rootkit's hooks.

`process_has_magic_gid()` is the counterpart that lets us check if a given process is one of ours. It takes a directory name from `/proc` (which is just the pid as a string), converts it to an integer using `kstrtoint()`, and looks up the corresponding `task_struct` under RCU (cause we are in a atmoic context). Once we have the task, we grab its credentials and iterate over its supplementary group list, checking each gid against our `MAGIC_GID`. If we find a match, we know this process belongs to an operator and return true, which tells the caller (our getdents64 hook) to not hide this entry from `/proc`. If the name isn't a valid pid or the task doesn't carry our magic group, we simply return false.

Hence hiding all the operator used/owned processes.

## 3.6 Covert C2 Channel
kprobe on __arm64_sys_kill

## 3.7 Shellcode Injection



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
---

## 6. Indicators of Compromise (IoCs)
1. Single outbound TCP connection on port 4445
2. ioctl calls to `/dev/vuln_rw`
3. snitch.ko detectors before unloading
4. rootkit module visible (no module hiding)
5. Syscall hooks detectable via kernel integrity checkers

---
---

## 8. Blockers

### C2 Kill Syscall Swallow
When our C2 channel intercepts a kill syscall and finishes processing the hidden signal, it needs to swallow the call so the original target never actually receives it. The way we did this was by rewriting the arguments to `kill(current->pid, 0)`, essentially turning it into a harmless "am I alive?" check on itself. The problem was that this returned a negative value in certain cases, which our `test_lkm` framework interpreted as a failure. The fix was simple: instead of targeting the current process, we rewrite it to `kill(1, 0)`, which just checks if the init process is alive, and init is always alive. One edge case worth noting is that a user could technically boot the kernel with `init=/bin/bash` or some other program, which might change pid 1's behavior, but we have not tested this.

### Scheduling While Atomic
Our access blocking hook fires inside `do_sys_openat2` via ftrace, which means we are in an atomic context with preemption disabled. We originally used `kern_path()` to resolve file paths (so we could catch traversal tricks like `/../../../tmp/secret)`, but kern_path() internally sleeps, and sleeping in a non preemptible context gave us the `BUG: scheduling while atomic` crash. Our first attempt at fixing this was to check `if (!preemptible())` and just fall back to using the raw unresolved path, but this immediately turned out to be a terrible idea since ftrace callbacks always fire with preemption disabled, meaning we would never resolve traversal paths at all. So we wrote `normalize_path()`, a pure string manipulation function that resolves `..` components by tracking slash positions like a stack, giving us a clean absolute path without ever needing to sleep.

The tradeoff is that `normalize_path()` only does textual resolution, it has no knowledge of symlinks. A symlink pointing into our hidden directory would sail right through the check. To cover this gap, we added a second ftrace hook on `__arm64_sys_symlinkat` to block symlink creation to our secret vaults entirely. We originally tried hooking `do_symlinkat` directly but the CPU would not allow it, so we went with the syscall wrapper instead, which meant dealing with the double pt_regs indirection. We chose ftrace over kprobe here because ftrace lets us sabotage the registers before the function actually executes, guaranteeing the symlink never gets written to disk, whereas a kprobe can only observe or change the return value after the fact.

### Clone Trampoline Fix
Initially `inject` was not creating `/tmp/pwned` at all because the injecting process did not have the MAGIC_GID, so our own rootkit was blocking it. After granting the magic group via `add_gid`, injection worked but the target process would die immediately after. The issue was in the clone trampoline inside inject.c: both the parent and child were returning to the same `br x28` address, which corrupted the parent's execution flow. The fix was to separate the return paths so the parent resumes first and the child returns cleanly with an `exit(0)`.