# Design changes made to tackle bugs  

## C2 Kill syscall swallow failed 
> Found when test_lkm gave C2 status failed

+ Cause: when swallowing the kill syscall after the work of the signal is done, kill(current->pid, 0) returned negative value which was interpreted as test failed by mykill.c and then by test_lkm.c

+ Remediation: Instead of saying kill(current->pid, 0) where target is the current running task, we swallow by making it kill(1,0) which checks if the "init" process exists or not, which it always does.

+ Possible bypass: Users can instruct the kernel to use a different program as the init process by passing the init= parameter at boot. For example, using init=/bin/bash (NOT TESTED)

---
## Kern_path() needed to resolve traversal paths, but kern_path() sleeps
> inject test gave BUG: scheduling while atomic: mykill/345/0x00000002

+ Cause:
-+ basically something called do_sys_openat2, which is where ftrace intercepted (access_blocking) and called blocking_callback in rootkit.c in atomic context
-+ the callback called kern_path()
-+ now since it was called in a non preemptible context, hence it cannot sleep which resulted in the scheduling while atomic bug

+ Remediation I:
-+ initially we added a check in access_blocking feature of rootkit.c where if (!preemptible()), it would just use raw path (raw_buf)
-+ this immediately was a bad idea since now we cannot block traversal paths because ftrace callback fires with preemption disabled.

+ Remediation II:
-+ since we still cannot use kern_path and also the preemptible() introduces a huge security flaw we made a simple function that would do path resolution for us
-+ It does it by doing simple string manipulation, where it would take a path such as `/mnt/shared/capstone/../../../../tmp/secret/flag.txt` and keep track of `/` to do necessary actions

walkthrough: for input `/mnt/shared/capstone/../../../../tmp/secret/flag.txt`

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

this results into an absolute path such as `/tmp/secret/flag.txt` which then is blocked 

+ Issue: this does not handle/block symlinks made to hidden directories, hence symlinks would pass this blocking 
-+ Possible Remediation: A hook on `do_symlinkat`

+ Hook on `do_symlinkat` did not work hence ended up hooking `__arm64_sys_symlinkat`.  
    -+ an ftrace hook on `__arm64_sys_symlinkat` (double pt_regs)
    -+ very similar to file_hide hook
    -+ We used ftrace instead of kprobe because ftrace allows us to actively modify CPU registers (argument sabotage) before the function executes, guaranteeing the symlink is never actually written to disk, whereas a standard kprobe/kretprobe would only allow us to monitor the creation after it was too late.
    -+ kprobe cannot easily stop the original function from running, it can only return a different value.