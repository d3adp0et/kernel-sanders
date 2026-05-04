# kernel-sanders 🐔
## TEAM - Alice and Bob

**kernel-sanders** is a security capstone project implementing a full, automated attack chain against a hardened AArch64 Linux target, from initial code execution via a vulnerable network service, through kernel privilege escalation, to persistent kernel-level compromise via a custom loadable rootkit with a covert C2 channel, process/file hiding, shellcode injection, and encrypted exfiltration.

---

## Documentation

- **[How to Run](documentation/how-to-run.md)** -+ build instructions, VM setup, running the exploit chain, and C2 usage
- **[Writeup](writeup/writeup.md)** -+ full technical writeup covering design decisions, implementation details, and attack chain walkthrough
- **[Key Bugs & Fixes](documentation/imp_bugs.md)** -+ notable bugs encountered during development
- **[Design Changes](documentation/design-changes-made-to-tackle-bugs.md)** -+ design-level changes made to resolve bugs (scheduling-while-atomic, path normalization, symlink blocking)
- **Poster** -+ poster that was shown during the poster session.
- **[COLDSPARK](COLDSPARK.md)** -+ Mission briefing from instructor.

---

## Attack Chain Overview

kernel-sanders implements a 4-stage attack chain against MERIDIAN Defense Group's "Secure Terminal Service":

<img width="1186" height="793" alt="image" src="https://github.com/user-attachments/assets/a4f37c41-2948-46f6-9f74-968b56dc6ef0" />
