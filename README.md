# kernel-sanders 🐔
## TEAM - Alice and Bob

A security capstone project designing a rootkit that demonstrates a full attack chain from initial exploitation to persistent kernel-level compromise with an encrypted C2 channel.

<img width="1066" height="792" alt="image" src="https://github.com/user-attachments/assets/b95cda4e-ea02-4ec7-929f-d510cb509304" />

---
### Architecture
The attack chain runs in four stages:
```
Stage 0: Exploit MERIDIAN (TCP :1337)  →  userland code execution
Stage 1: Privilege escalation via vuln_rwx.ko or vuln_rw.ko  →  EL1 (kernel)
Stage 2: Deploy rootkit (librootkit.so + rootkit.ko)  →  persistence + hiding
Stage 3: Encrypted beacon  →  C2 server issues commands
```

Two components work together:

| Component | Layer | Purpose |
|---|---|---|
| `rootkit.ko` | Kernel (EL1) | kretprobe hooks, module self-hiding, code injection, kernel backdoor |

---

## Features

### Kernel (`rootkit.ko`)
- **Kernel-level hiding** — kretprobe on `sys_getdents64` filters directory entries for all processes
- **Module self-hiding** — removes itself from the kernel module list (`list_del_init`)
- **Process code injection** — writes shellcode into arbitrary processes via `access_process_vm`
- **Kernel network backdoor** — kernel-space TCP listener, invisible to `ss`/`netstat`
- **Privilege escalation** — grants root credentials on demand via `prepare_creds`/`commit_creds`

### SPECIAL FEATURE : Encrypted C2 Channel
---
