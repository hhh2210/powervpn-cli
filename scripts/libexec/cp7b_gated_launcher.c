#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fail(const char *code)
{
	dprintf(STDERR_FILENO, "cp7b-gated-launcher: %s\n", code);
	return 70;
}

static int write_all(int fd, const char *data, size_t length)
{
	while (length)
	{
		ssize_t written = write(fd, data, length);
		if (written < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}
			return -1;
		}
		data += written;
		length -= (size_t)written;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char pid_line[64];
	char gate_byte;
	struct stat gate_stat;
	int handshake_fd, gate_fd, length;

	if (argc < 5 || strcmp(argv[1], "--") != 0)
	{
		return fail("invalid_arguments");
	}
	if (argv[2][0] != '/' || argv[3][0] != '/' || argv[4][0] != '/')
	{
		return fail("paths_must_be_absolute");
	}
	umask(077);
	gate_fd = open(argv[2], O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (gate_fd < 0 || fstat(gate_fd, &gate_stat) != 0 || !S_ISFIFO(gate_stat.st_mode) ||
		gate_stat.st_uid != geteuid() || (gate_stat.st_mode & 0777) != 0600 ||
		gate_stat.st_nlink != 1)
	{
		if (gate_fd >= 0)
		{
			close(gate_fd);
		}
		return fail("gate_open_failed");
	}
	handshake_fd = open(argv[3], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (handshake_fd < 0)
	{
		close(gate_fd);
		return fail("handshake_open_failed");
	}
	length = snprintf(pid_line, sizeof(pid_line), "pid=%ld\n", (long)getpid());
	if (length <= 0 || (size_t)length >= sizeof(pid_line) ||
		write_all(handshake_fd, pid_line, (size_t)length) != 0 || fsync(handshake_fd) != 0)
	{
		close(handshake_fd);
		close(gate_fd);
		return fail("handshake_write_failed");
	}
	if (close(handshake_fd) != 0)
	{
		close(gate_fd);
		return fail("handshake_close_failed");
	}
	for (;;)
	{
		ssize_t count = read(gate_fd, &gate_byte, 1);
		if (count == 1)
		{
			break;
		}
		if (count < 0 && errno == EINTR)
		{
			continue;
		}
		close(gate_fd);
		return fail("gate_read_failed");
	}
	close(gate_fd);
	if (gate_byte != 'G')
	{
		return fail("gate_token_invalid");
	}
	execv(argv[4], &argv[4]);
	return fail("target_exec_failed");
}
