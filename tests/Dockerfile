# Test harness image for harden-and-audit.sh.
#
# Boots real systemd as PID 1 and mirrors a Debian netinst server: a kernel
# (so SCAP's "system_with_kernel" rules apply), GRUB, an unprivileged sudo
# admin (so the anti-lockout preflight passes legitimately), plus seeded
# graphical and legacy packages that the script must remove. libavcodec is
# seeded as a non-graphical package that depends on X11 client libraries, to
# prove the purge never takes collateral packages with it.
ARG DEBIAN_VERSION=12
FROM debian:${DEBIAN_VERSION}

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update; \
    echo 'grub-pc grub-pc/install_devices multiselect' | debconf-set-selections; \
    echo 'grub-pc grub-pc/install_devices_empty boolean true' | debconf-set-selections; \
    avcodec="$(apt-cache search --names-only '^libavcodec[0-9]+$' | awk '{print $1}' | sort | tail -n1)"; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates procps iproute2 kmod \
        linux-image-amd64 grub-pc \
        xserver-xorg-core xauth xterm x11-utils \
        inetutils-telnet rpcbind \
        "${avcodec}"; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    systemctl mask systemd-firstboot.service systemd-udevd.service systemd-udevd-kernel.socket \
        systemd-udevd-control.socket systemd-modules-load.service getty@tty1.service \
        sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount; \
    useradd -m -s /bin/bash -G sudo ciadmin; \
    echo "ciadmin:$(head -c 24 /dev/urandom | base64)Aa1!" | chpasswd

COPY container-init.sh /usr/local/sbin/container-init

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/local/sbin/container-init"]
