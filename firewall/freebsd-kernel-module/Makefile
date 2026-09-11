# Builds otp_firewall.ko using FreeBSD's own kernel-module build
# infrastructure (bsd.kmod.mk, part of the base system / src.git under
# /usr/src, or the kernel-source-and-headers package) - the direct
# analog of the Linux side's Kbuild + `make -C /lib/modules/.../build`.
#
# Usage (on a FreeBSD machine with kernel sources/headers installed):
#   make
#   sudo make load        # kldload ./otp_firewall.ko
#   sudo make unload      # kldunload otp_firewall
#   sudo make install     # installs into /boot/modules

KMOD =	otp_firewall
SRCS =	otp_firewall.c otp_firewall_proto.h

.include <bsd.kmod.mk>

load: ${KMOD}.ko
	kldload ./${KMOD}.ko

unload:
	kldunload ${KMOD}
