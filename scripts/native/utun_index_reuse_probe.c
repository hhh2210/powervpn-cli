/*
 * Reproduces, without any VPN connection, the condition behind
 * docs/evidence/native-vip-stale-interface-cache.md: the kernel gives the
 * interface index of a destroyed utun device to a new one that has another
 * name. charon's kernel-pfroute plugin logs what it makes of each device
 * (powervpn native log).
 *
 *   cc -O2 -Wall -o utun_index_reuse_probe scripts/native/utun_index_reuse_probe.c
 *   sudo ./utun_index_reuse_probe          # both devices, reports the reuse
 *   sudo ./utun_index_reuse_probe prime    # first device only
 *
 * The first device asks for a high unit (utun100 or above); the second takes
 * the lowest free unit, as charon's own TUN device does. Each is brought up
 * for a moment and closed again. No address and no route is configured.
 *
 * `prime` leaves charon with a cached entry for the high-unit name, so the
 * TUN device of the next connection gets that index under a lower name.
 *
 * Exit status: 0 the index was reused under another name (or `prime` done),
 * 3 it was not reused, 1 on any error.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>

#define FIRST_HIGH_UNIT 100
#define LAST_HIGH_UNIT 120
#define SETTLE_MICROSECONDS 1000000

struct device {
	int fd;
	char name[IFNAMSIZ];
	unsigned int index;
};

/* unit < 0: let the kernel pick the lowest free unit. */
static int open_utun(int unit, struct device *device)
{
	struct ctl_info info;
	struct sockaddr_ctl addr;
	socklen_t size = sizeof(device->name);

	device->fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (device->fd < 0)
	{
		return -1;
	}
	memset(&info, 0, sizeof(info));
	strncpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name) - 1);
	if (ioctl(device->fd, CTLIOCGINFO, &info) < 0)
	{
		close(device->fd);
		return -1;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sc_len = sizeof(addr);
	addr.sc_family = AF_SYSTEM;
	addr.ss_sysaddr = AF_SYS_CONTROL;
	addr.sc_id = info.ctl_id;
	addr.sc_unit = unit < 0 ? 0 : (u_int32_t)unit + 1;
	if (connect(device->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
		getsockopt(device->fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
				   device->name, &size) < 0)
	{
		close(device->fd);
		return -1;
	}
	device->index = if_nametoindex(device->name);
	return 0;
}

static int bring_up(const struct device *device)
{
	struct ifreq ifr;
	int s, result = -1;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device->name, sizeof(ifr.ifr_name) - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0)
	{
		ifr.ifr_flags |= IFF_UP;
		result = ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	close(s);
	return result;
}

/* Up for a moment, then gone; the pauses let charon and the kernel settle. */
static int show(const char *label, struct device *device)
{
	if (bring_up(device) < 0)
	{
		fprintf(stderr, "could not bring up %s: %s\n", device->name,
				strerror(errno));
		close(device->fd);
		return -1;
	}
	printf("%s: %s index %u\n", label, device->name, device->index);
	fflush(stdout);
	usleep(SETTLE_MICROSECONDS);
	close(device->fd);
	usleep(SETTLE_MICROSECONDS);
	return 0;
}

int main(int argc, char **argv)
{
	struct device first, second;
	int unit, prime = argc > 1 && strcmp(argv[1], "prime") == 0;

	if (argc > 2 || (argc == 2 && !prime))
	{
		fprintf(stderr, "usage: %s [prime]\n", argv[0]);
		return 1;
	}
	if (geteuid() != 0)
	{
		fprintf(stderr, "run with sudo: creating a utun device needs root\n");
		return 1;
	}
	for (unit = FIRST_HIGH_UNIT; unit <= LAST_HIGH_UNIT; unit++)
	{
		if (open_utun(unit, &first) == 0)
		{
			break;
		}
	}
	if (unit > LAST_HIGH_UNIT)
	{
		fprintf(stderr, "no free utun unit in %d-%d: %s\n", FIRST_HIGH_UNIT,
				LAST_HIGH_UNIT, strerror(errno));
		return 1;
	}
	if (show("first ", &first) < 0)
	{
		return 1;
	}
	if (prime)
	{
		printf("primed: the next utun device is expected to get index %u "
			   "under another name\n", first.index);
		return 0;
	}
	if (open_utun(-1, &second) < 0)
	{
		fprintf(stderr, "could not create the second device: %s\n",
				strerror(errno));
		return 1;
	}
	if (show("second", &second) < 0)
	{
		return 1;
	}
	if (first.index == second.index && strcmp(first.name, second.name) != 0)
	{
		printf("reused: index %u was %s and became %s\n", first.index,
			   first.name, second.name);
		return 0;
	}
	printf("not reused: %s had index %u, %s got index %u\n", first.name,
		   first.index, second.name, second.index);
	return 3;
}
