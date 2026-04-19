# Capstone Deliverables & Old Assignment Mapping

> Each deliverable is mapped to old assignments in `old_assignments/`. The **Reuse Level** indicates how much of the old code can be carried over.

---

## Legend

| Reuse Level | Meaning |
|---|---|
| **Copy & Paste** | Old code can be dropped in with minimal changes (renames, header swaps) |
| **Partial Reuse** | Core logic/pattern transfers, but significant adaptation needed |
| **Reference Only** | Old code demonstrates the concept, but implementation is substantially different |
| **Entirely New** | No prior assignment covers this; must be written from scratch |

---

## Stage 1 — Initial Access

### Deliverable 1: Beachhead Shellcode — `shellcode/beachhead.S`

**Points:** 8 pts (Rubric item 1)
**What:** AArch64 PIC shellcode sent via MERIDIAN `submit` command. Runs as `analyst`, must not crash the service.

**Old Assignment:** `old_assignments/LDPRELOAD-fileio-0/start.S`
**Reuse Level:** Reference Only

`start.S` is an x86-64 bootstrap stub for a userland LD_PRELOAD hook — completely different architecture (x86 vs AArch64) and context (userland hooking vs network-delivered shellcode). The only transferable concept is "writing raw assembly that sets up syscall args and invokes `svc`/`syscall`." The actual shellcode (AArch64 PIC, connect-back or exec shell, position-independent) must be written from scratch.

---

## Stage 2 — Privilege Escalation

### Deliverable 2: LPE Exploit — `exploit/exploit_rwx.c` (undergrad) or `exploit/exploit_privesc.c` (grad)

**Points:** 12 pts (Rubric item 2)
**What:**
- **Undergrad:** Kernel shellcode via `/dev/vuln_rwx` — `prepare_creds`/`commit_creds` or direct cred zeroing
- **Grad:** Arbitrary R/W via `/dev/vuln_rw` — walk `init_task.tasks`, locate cred, modify uid/gid

**Old Assignment:** None
**Reuse Level:** Entirely New

Per `INTEGRATION.md`: "exploit/exploit_*.c → (new material)". No prior assignment covers privilege escalation via vulnerable kernel drivers. The `ioctl` wrappers and symbol lookup scaffolding are provided in the stub files, but the actual exploit logic is entirely new.

### Deliverable 3: Bonus LPE — `exploit/exploit_modprobe.c`

**Points:** +10 bonus (Rubric item B3)
**What:** Second LPE technique (e.g., `modprobe_path` overwrite, `core_pattern` overwrite, ROP chain)

**Old Assignment:** None
**Reuse Level:** Entirely New

---

## Stage 3 — Rootkit Deployment

### Deliverable 4: Reflective Loader — `loader/`

**Points:** 10 pts (Rubric item 3)
**What:** Load `rootkit.ko` without `insmod`. Options: `memfd_create` + `finit_module`, raw syscall, or manual ELF relocation.

**Old Assignment:** `old_assignments/reflective-loader/loader.c` (+ `elfsym.h`, `procfsutil.h`)
**Reuse Level:** Reference Only

The old `loader.c` is a **userland** reflective loader that:
- Finds its own ELF base
- Creates a `memfd`, writes itself in, and calls `dlopen()` on `/proc/self/fd/N`
- Resolves libc symbols (`dlopen`, `sprintf`) via ELF symbol table walking

The capstone loader needs to load a **kernel module** (`.ko`), not a shared library. The `memfd_create` concept transfers directly, but instead of `dlopen()`, the capstone calls `finit_module()` or the `__NR_finit_module` syscall. The ELF parsing helpers in `elfsym.h` and process map parsing in `procfsutil.h` may be partially reusable if you take the manual ELF relocation approach, but the core logic must be rewritten for the kernel module loading context.

---

### Deliverable 5: File Hiding — `lkm/src/file_hide.c`

**Points:** 7 pts (Rubric item 4)
**What:** Hide `secret/` from `/tmp` and `/dev/shm` directory listings using a kretprobe on `getdents64`. Operator bypass via GID 1337.

**Old Assignment:** `old_assignments/kernel-hooking/kernel-hook-kprobe/cloak_kp.c`
**Reuse Level:** Copy & Paste (with minor changes)

The capstone `file_hide.c` stub is **almost identical** to `cloak_kp.c`. The same pattern is used:
- `kretprobe` on `__arm64_sys_getdents64`
- Entry handler saves `dirp` via double `pt_regs`
- Return handler walks the `linux_dirent64` buffer and removes matching entries

**Changes needed:**
1. Replace `#include "guardian_kprobe.h"` → `#include "rootkit.h"`
2. Replace `PROTECTED_BASENAME` → `HIDDEN_PREFIX` / `"secret"` (or define in `rootkit.h`)
3. Replace `guardian_has_magic_gid()` with a local implementation that walks `cred->group_info` directly (the old one uses `in_group_p()` which returns true for root — capstone requires `group_info` walking)
4. Add toggle state (`active` flag, `enable`/`disable` wrappers) — already scaffolded in the stub
5. Use `d_path()` instead of `d_iname()` for mount-point directories (the stub comments mention this)

> **Note:** The stub file already has most of this done — the return handler and entry handler are already ported from `cloak_kp.c`. The main TODO is implementing `guardian_has_magic_gid()` as a `group_info` walker.

---

### Deliverable 6: Path Protection / Access Blocking — `lkm/src/rootkit.c` (blocking section)

**Points:** 10 pts (Rubric item 5)
**What:** Block `openat` on `/tmp/secret/*` and `/dev/shm/secret/*`, including traversal paths like `../../../tmp/secret/flag.txt`. Operator bypass.

**Old Assignment:** `old_assignments/kernel-hooking/kernel-hook-ftrace/bouncer_ft.c`
**Reuse Level:** Partial Reuse

The old `bouncer_ft.c` uses ftrace on `do_sys_openat2` with `ftrace_regs_get_argument()` to pull the filename and zero it to cause `EFAULT`. The capstone needs:
- Same ftrace hook pattern on `do_sys_openat2` — **reusable**
- Same deny mechanism (zero the filename pointer) — **reusable**
- `kprobe_lookup()` for symbol resolution — **reusable** (already in `rootkit.h`)
- `ftrace_ops` setup with `FL_IPMODIFY | FL_RECURSION` — **reusable**

**Changes needed:**
1. Replace simple prefix matching with **traversal-aware path resolution** (e.g., use `kern_path()` to resolve the path and then check if it falls under the protected dirs). The old code only does `strncmp(path, PROTECTED_PATH, pp_len)` which doesn't handle `../../../tmp/secret`
2. Check against **two** protected paths (`HIDDEN_DIR_1` and `HIDDEN_DIR_2`) instead of one
3. Replace `guardian_has_magic_gid()` with `cred->group_info` walker
4. Replace `guardian_log_event()` — not needed in capstone

The **ftrace boilerplate** (init/exit, callback signature, register/unregister) can be copied directly. The **path checking logic** must be rewritten for traversal handling.

---

### Deliverable 7: Process Hiding — `lkm/src/proc_hide.c`

**Points:** 8 pts (Rubric item 6)
**What:** Hide processes with GID 1337 from `/proc` listings. Uses kretprobe on `getdents64` for `/proc`, filtering numeric PID entries.

**Old Assignment:** `old_assignments/kernel-hooking/kernel-hook-kprobe/cloak_kp.c`
**Reuse Level:** Partial Reuse

The dirent-filtering pattern (kretprobe entry/return, copy_from_user, walk buffer, remove entries, copy_to_user) is **identical** to `cloak_kp.c` and `file_hide.c`. However, the filtering logic is substantially different:
- Instead of matching by filename (`strcmp(d_name, "secret")`), you must check if each numeric directory entry corresponds to a PID that has `MAGIC_GID` in its `group_info`
- Need to use `d_path()` to confirm the directory being listed is `/proc` (not `/tmp` or `/dev/shm`)
- Need `proc_hide_add_pid()` to inject GID 1337 into a target process's supplementary groups — this is a **new** mechanism similar to `grant_magic_gid()` in `guardian_kprobe_main.c` but targeting a different process (not `current`)

**What's reusable:** The kretprobe skeleton, double pt_regs entry handler, dirent buffer walking, and entry removal logic.
**What's new:** PID-to-GID lookup, `/proc` directory identification, cross-process credential modification.

---

### Deliverable 8: Operator Bypass — (integrated across `file_hide.c`, `proc_hide.c`, `rootkit.c`)

**Points:** 4 pts (Rubric item 7)
**What:** Processes with GID 1337 can read protected files and see hidden processes. Implemented via `cred->group_info` walking.

**Old Assignment:** `old_assignments/kernel-hooking/kernel-hook-kprobe/guardian_kprobe_main.c` (function `guardian_has_magic_gid()` and `grant_magic_gid()`)
**Reuse Level:** Partial Reuse

The old `guardian_has_magic_gid()` uses `in_group_p()` which returns true for root — **this breaks the capstone requirement**. The capstone needs you to walk `cred->group_info` directly. The `grant_magic_gid()` function shows how to allocate a new `group_info`, copy existing GIDs, append GID 1337, and commit — this pattern is **directly reusable** for `proc_hide_add_pid()` but must be adapted to modify a **different process's** credentials (not `current`).

---

### Deliverable 9: Module Self-Hiding — `lkm/src/rootkit.c` (hide/show section)

**Points:** +10 bonus (Rubric item B1)
**What:** Hide from `lsmod` and `/proc/modules` using `list_del_init` / `list_add`.

**Old Assignment:** None directly in `old_assignments/`, but referenced as `ghostmod` lab module in `INTEGRATION.md`
**Reuse Level:** Reference Only (ghostmod not present in `old_assignments/`)

The `ghostmod` lab module is referenced in `INTEGRATION.md` as the source for the `list_del_init` + save `->prev` + restore with `list_add` pattern, but **it is not present in the `old_assignments/` directory**. The stub already provides the `saved_prev` and `module_hidden` variables. The pattern is simple and well-documented: `list_del_init(&THIS_MODULE->list)` to hide, `list_add(&THIS_MODULE->list, saved_prev)` to show. Must be written from the concept.

---

## Stage 4 — C2 & Exfiltration

### Deliverable 10: Covert C2 Channel — `lkm/src/c2.c`

**Points:** 8 pts (Rubric item 8)
**What:** Kprobe on `__arm64_sys_kill`. When signal == 62, intercept and dispatch rootkit commands. Uses double `pt_regs` indirection to read `x0`–`x7` registers.

**Old Assignment:** `old_assignments/kernel-hooking/kernel-hook-kprobe/bouncer_kp.c`
**Reuse Level:** Partial Reuse

The kprobe registration and double `pt_regs` indirection pattern (`regs->regs[0]` → inner `pt_regs` → `regs[N]`) is the same as `bouncer_kp.c`. However:
- The **target function** is different: `__arm64_sys_kill` instead of `__arm64_sys_openat`
- Instead of checking a filename, you check if the signal number == `MAGIC_SIGNAL` (62)
- Instead of zeroing a pointer, you **dispatch commands** based on `x0` with arguments from `x2`–`x7`
- Must **swallow the signal** (return success without delivering it) for magic signals
- Toggle commands must be **deferred to workqueue** (already scaffolded in stub)

**What's reusable:** Kprobe setup, double pt_regs indirection, pre_handler signature.
**What's new:** Signal interception logic, command dispatch table, deferred execution via workqueue (scaffolding provided).

---

### Deliverable 11: Shellcode Injection — `lkm/src/inject.c`

**Points:** 8 pts (Rubric item 9)
**What:** Inject AArch64 PIC shellcode into a sleeping process via C2 channel. Uses `kthread_use_mm`, `vm_mmap`, `task_pt_regs` PC redirect, `wake_up_process`.

**Old Assignment:** `old_assignments/kernel-process-injection/kinject.c` (Parts 1 & 2)
**Reuse Level:** Partial Reuse

The capstone `inject.c` is a **stripped-down** version of `kinject.c`. The workqueue-based injection flow from Part 1 (and the clone trampoline from Part 2) are directly relevant:
- `vma_inject_worker()` pattern: `mmgrab` → `kthread_use_mm` → `vm_mmap(RWX)` → `copy_to_user` → `kthread_unuse_mm` → `mmdrop` — **reusable**
- PC hijack: `task_pt_regs` → set `pc` → set `syscallno = ~0UL` → `set_tsk_thread_flag(TIF_SIGPENDING)` → `wake_up_process` — **reusable**
- Clone trampoline (Part 2) for target survival — **reusable** if you want the target to survive

**Changes needed:**
1. Replace the `build_payload()` hardcoded shellcode generation with reading from the staging file or using `shellcode_default[]` (already implemented in stub via `load_staged_shellcode()`)
2. Simplify: no chardev, no scan, no PTE injection — just the `inject_trigger()` function
3. Add clone trampoline logic so the target process survives (x28 = original PC, x27 = payload)
4. The overall flow is: find task → schedule work → vm_mmap → copy shellcode → write trampoline → hijack regs → wake

---

### Deliverable 12: End-to-End Demo

**Points:** 10 pts (Rubric item 10)
**What:** Full COLDSPARK chain in a single sitting: Beachhead → LPE → reflective load → C2 → exfiltrate PIRs. No kernel panics, no manual intervention.

**Old Assignment:** None
**Reuse Level:** Entirely New

This is integration work — wiring all previous deliverables together into a single automated attack chain. No old assignment covers this.

---

### Deliverable 13: Cleanup

**Points:** 5 pts (Rubric item 11)
**What:** `rmmod rootkit` succeeds cleanly. All hooks unregister, no cred/kretprobe leaks, no oops.

**Old Assignment:** `old_assignments/kernel-hooking/kernel-hook-kprobe/guardian_kprobe_main.c` (exit function pattern)
**Reuse Level:** Reference Only

The reverse teardown pattern (exit in reverse order of init) is demonstrated in `guardian_exit()`. The capstone has more subsystems to tear down but the pattern is the same.

---

### Deliverable 14: SNITCH Evasion (Bonus)

**Points:** +20 bonus (Rubric item B2)
**What:** Complete the full chain with `snitch.ko` loaded without triggering any of its 8 detectors.

**Old Assignment:** None
**Reuse Level:** Entirely New

SNITCH evasion is a capstone-specific challenge. No prior assignment covers evading an IDS that monitors kprobes, credential changes, ftrace hooks, `memfd_create`, `finit_module`, and `kthread_use_mm`.

---

### Deliverable 15: Special Feature (Bonus)

**Points:** +10 to +20 bonus (Rubric item B4)
**What:** Something not asked for (e.g., persistence, network C2, in-memory rootkit, anti-forensics).

**Old Assignment:** None
**Reuse Level:** Entirely New

---

## Deliverable 16: Design Writeup — `writeup/README.md`

**Points:** 10 pts (Rubric item 12)
**What:** Explain how each component works, design choices, what you'd do differently, and what would detect your rootkit.

**Old Assignment:** None
**Reuse Level:** Entirely New

---

## Deliverable 17: Reproducibility — `make test`

**Points:** 12 pts (Rubric item 13)
**What:** Clean clone → `make` → `make test` passes end-to-end on fresh VM.

**Old Assignment:** None
**Reuse Level:** Entirely New

---

## Summary Table

| # | Deliverable | Points | Old Assignment File(s) | Reuse Level |
|---|---|---|---|---|
| 1 | Beachhead Shellcode (`shellcode/beachhead.S`) | 8 | `LDPRELOAD-fileio-0/start.S` | Reference Only |
| 2 | LPE Exploit (`exploit/exploit_rwx.c` or `exploit_privesc.c`) | 12 | None | Entirely New |
| 3 | Bonus LPE (`exploit/exploit_modprobe.c`) | +10 | None | Entirely New |
| 4 | Reflective Loader (`loader/`) | 10 | `reflective-loader/loader.c`, `elfsym.h`, `procfsutil.h` | Reference Only |
| 5 | File Hiding (`lkm/src/file_hide.c`) | 7 | `kernel-hooking/kernel-hook-kprobe/cloak_kp.c` | Copy & Paste |
| 6 | Path Protection (`lkm/src/rootkit.c` blocking) | 10 | `kernel-hooking/kernel-hook-ftrace/bouncer_ft.c` | Partial Reuse |
| 7 | Process Hiding (`lkm/src/proc_hide.c`) | 8 | `kernel-hooking/kernel-hook-kprobe/cloak_kp.c` | Partial Reuse |
| 8 | Operator Bypass (across multiple files) | 4 | `kernel-hooking/kernel-hook-kprobe/guardian_kprobe_main.c` | Partial Reuse |
| 9 | Module Self-Hiding (`lkm/src/rootkit.c` hide) | +10 | `ghostmod` lab (not in `old_assignments/`) | Reference Only |
| 10 | Covert C2 (`lkm/src/c2.c`) | 8 | `kernel-hooking/kernel-hook-kprobe/bouncer_kp.c` | Partial Reuse |
| 11 | Shellcode Injection (`lkm/src/inject.c`) | 8 | `kernel-process-injection/kinject.c` | Partial Reuse |
| 12 | End-to-End Demo | 10 | None | Entirely New |
| 13 | Cleanup (`rmmod`) | 5 | `kernel-hooking/kernel-hook-kprobe/guardian_kprobe_main.c` | Reference Only |
| 14 | SNITCH Evasion (bonus) | +20 | None | Entirely New |
| 15 | Special Feature (bonus) | +10–20 | None | Entirely New |
| 16 | Design Writeup (`writeup/README.md`) | 10 | None | Entirely New |
| 17 | Reproducibility (`make test`) | 12 | None | Entirely New |
