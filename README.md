# kernel-sanders 🐔
## TEAM - Alice and Bob

**kernel-sanders** is a security capstone project implementing a full, automated attack chain against a hardened AArch64 Linux target — from initial code execution via a vulnerable network service, through kernel privilege escalation, to persistent kernel-level compromise via a custom loadable rootkit with a covert C2 channel, process/file hiding, shellcode injection, and encrypted exfiltration.

---

## Documentation

- **[How to Run](documentation/how-to-run.md)** — build instructions, VM setup, running the exploit chain, and C2 usage
- **[Writeup](writeup/writeup.md)** — full technical writeup covering design decisions, implementation details, and attack chain walkthrough
- **[Key Bugs & Fixes](documentation/imp_bugs.md)** — notable bugs encountered during development
- **[Design Changes](documentation/design-changes-made-to-tackle-bugs.md)** — design-level changes made to resolve bugs (scheduling-while-atomic, path normalization, symlink blocking)
- **Poster** — coming soon (to be added to root)

---

## Attack Chain Overview

kernel-sanders implements a 4-stage attack chain against MERIDIAN Defense Group's "Secure Terminal Service":

```
                    ┌─────────────────────┐
  nc :11337 ───────►│  MERIDIAN Terminal  │
                    │  submit → mmap RWX  │
                    │  clone → exec code  │
                    └────────┬────────────┘
                             │ analyst (uid 1001)
                    ┌────────▼────────────┐
                    │  /dev/vuln_rwx      │  the JIT thing
                    │  /dev/vuln_rw       │  the debug thing
                    └────────┬────────────┘
                             │ root (uid 0)
                    ┌────────▼────────────┐
                    │  load rootkit.ko    │
                    │  (without insmod)   │
                    └────────┬────────────┘
                             │
                    ┌────────▼────────────┐
                    │  /home/director/    │
                    │  classified/        │
                    │  (the spicy stuff)  │
                    └─────────────────────┘
```

```
    ┌─────────────┐     ┌──────────────────┐     ┌──────────────┐     ┌──────────────┐
    │   Stage 1   │     │     Stage 2      │     │   Stage 3    │     │   Stage 4    │
    │   Initial   │────>│    Privilege     │────>│   Rootkit    │────>│     C2 +     │
    │   Access    │     │   Escalation     │     │  Deployment  │     │ Exfiltration │
    └─────────────┘     └──────────────────┘     └──────────────┘     └──────────────┘
     nc target:1337      /dev/vuln_rwx or         load rootkit         covert C2
     submit shellcode    /dev/vuln_rw              hide everything     read classified/
     → code exec as      → root                   register hooks      exfil PIRs
       analyst
```
