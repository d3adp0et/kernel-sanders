# Bugs

## CRASH, kernel panic
> Found when the system crashed

Cause: No NULL check when 

---
## PID still visible after add-gid

---
## C2 file hiding re-enable failed

---
## inject did not create /tmp/pwned (did not work)

+ Gave mykill MAGIC_GID using add_gid 
+ now injection works but target does not survive injection
-+ look at clone trampoline from kinject.c to identify problem

+ clone() trampoline fixed, child and parent process were returning to same br x28. Made parent return first and then child returns with a clean exit(0).