/*
 * Reproduces, without any VPN connection, the condition behind
 * docs/evidence/native-vip-stale-interface-cache.md: the kernel gives the
 * interface index of a destroyed utun device to a new one that has another
 * name, and charon's kernel-pfroute plugin keeps the old name for that index.
 *
 *   cc -O2 -Wall -o utun_index_reuse_probe scripts/native/utun_index_reuse_probe.c
 *   sudo ./utun_index_reuse_probe          # both devices, reports the reuse
 *   sudo ./utun_index_reuse_probe prime    # first device only
 *
 * Each device is configured the way charon configures its own TUN device:
 * IFF_UP | IFF_RUNNING, MTU 1400, and one /32 address that is also the
 * destination. The address is 192.0.2.254 from TEST-NET-1 (RFC 5737), which
 * nothing routes, so the only route it creates is a host route to itself on
 * the probe device, gone when the device is. After a second the device is
 * closed, which destroys it.
 *
 * The first device asks for a high unit (utun100 or above); the second takes
 * the lowest free unit, as charon's TUN device does. The probe prints the
 * routing messages the kernel sent for each device's index: those are what
 * charon sees. In `powervpn native log`, an unpatched charon then reports the
 * second device under the first one's name ("192.0.2.254 appeared on utun100",
 * "interface utun100 activated"); a patched one logs "interface utun100
 * disappeared, index N is now utunM".
 *
 * `prime` creates the first device only. charon keeps it cached, so the TUN
 * device of the next connection is expected to get its index under a lower
 * name: the case that made connections fail.
 *
 * Exit status: 0 the index was reused under another name (or `prime` done),
 * 3 it was not reused, 1 on any error.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>

#define FIRST_HIGH_UNIT 100
#define LAST_HIGH_UNIT 120
#define SETTLE_MICROSECONDS 1000000
#define PROBE_MTU 1400
#define PROBE_ADDRESS "192.0.2.254"

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

static void set_in(struct sockaddr_in *sin, const char *address)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	inet_pton(AF_INET, address, &sin->sin_addr);
}

/* As strongSwan's tun_device_t: up(), set_address(), set_mtu(). */
static int configure(const struct device *device)
{
	struct ifreq ifr;
	struct in_aliasreq ifra;
	int s, result = -1;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device->name, sizeof(ifr.ifr_name) - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
	{
		goto out;
	}
	ifr.ifr_flags |= IFF_RUNNING | IFF_UP;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
	{
		goto out;
	}
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, device->name, sizeof(ifra.ifra_name) - 1);
	set_in(&ifra.ifra_addr, PROBE_ADDRESS);
	set_in(&ifra.ifra_broadaddr, PROBE_ADDRESS);
	set_in(&ifra.ifra_mask, "255.255.255.255");
	if (ioctl(s, SIOCAIFADDR, &ifra) < 0)
	{
		goto out;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device->name, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_mtu = PROBE_MTU;
	result = ioctl(s, SIOCSIFMTU, &ifr);
out:
	close(s);
	return result;
}

static const char *message_name(int type)
{
	switch (type)
	{
		case RTM_ADD: return "RTM_ADD";
		case RTM_DELETE: return "RTM_DELETE";
		case RTM_CHANGE: return "RTM_CHANGE";
		case RTM_NEWADDR: return "RTM_NEWADDR";
		case RTM_DELADDR: return "RTM_DELADDR";
		case RTM_IFINFO: return "RTM_IFINFO";
		default: return NULL;
	}
}

/* Prints the routing messages queued on `route` that name `index`. */
static void drain(int route, unsigned int index)
{
	union {
		struct rt_msghdr rtm;
		struct if_msghdr ifm;
		struct ifa_msghdr ifam;
		char buffer[2048];
	} msg;
	ssize_t len;
	unsigned int about;
	int flags;

	while ((len = recv(route, &msg, sizeof(msg), MSG_DONTWAIT)) > 0)
	{
		if (len < (ssize_t)sizeof(msg.rtm.rtm_msglen) + 2 ||
			!message_name(msg.rtm.rtm_type))
		{
			continue;
		}
		switch (msg.rtm.rtm_type)
		{
			case RTM_IFINFO:
				about = msg.ifm.ifm_index;
				flags = msg.ifm.ifm_flags;
				break;
			case RTM_NEWADDR:
			case RTM_DELADDR:
				about = msg.ifam.ifam_index;
				flags = msg.ifam.ifam_flags;
				break;
			default:
				about = msg.rtm.rtm_index;
				flags = msg.rtm.rtm_flags;
				break;
		}
		if (about == index)
		{
			printf("  kernel: %s index %u flags 0x%x\n",
				   message_name(msg.rtm.rtm_type), about, (unsigned)flags);
		}
	}
}

/* Configured for a second, then destroyed. */
static int show(const char *label, struct device *device, int route)
{
	if (configure(device) < 0)
	{
		fprintf(stderr, "could not configure %s: %s\n", device->name,
				strerror(errno));
		close(device->fd);
		return -1;
	}
	printf("%s: %s index %u\n", label, device->name, device->index);
	usleep(SETTLE_MICROSECONDS);
	drain(route, device->index);
	close(device->fd);
	usleep(SETTLE_MICROSECONDS);
	printf("%s: %s closed\n", label, device->name);
	drain(route, device->index);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct device first, second;
	int route, unit, prime = argc > 1 && strcmp(argv[1], "prime") == 0;

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
	route = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC);
	if (route < 0)
	{
		fprintf(stderr, "no routing socket: %s\n", strerror(errno));
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
	if (show("first ", &first, route) < 0)
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
	if (show("second", &second, route) < 0)
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
