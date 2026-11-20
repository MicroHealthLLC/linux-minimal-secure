# Test harness image for harden-and-audit.sh (Debian 12/13, Ubuntu 22.04/24.04/26.04).
#
# Boots real systemd as PID 1 and mirrors a netinst / server install: a
# kernel (so SCAP's "system_with_kernel" rules apply), GRUB, an unprivileged
# sudo admin (so the anti-lockout preflight passes legitimately), plus seeded
# graphical and legacy packages that the script must remove. libavcodec is
# seeded as a non-graphical package that depends on X11 client libraries, to
# prove the purge never takes collateral packages with it.
ARG BASE_IMAGE=debian:12
FROM ${BASE_IMAGE}

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    . /etc/os-release; \
    if [ "$ID" = ubuntu ]; then \
        kernel=linux-image-virtual; \
        # Docker-only artifacts: the passwordless "ubuntu" account (24.04+)
        # and the dpkg path excludes of the minimized image. A server
        # install has neither.
        userdel -r ubuntu 2>/dev/null || true; \
        rm -f /etc/dpkg/dpkg.cfg.d/excludes; \
    else \
        kernel=linux-image-amd64; \
    fi; \
    apt-get update; \
    echo 'grub-pc grub-pc/install_devices multiselect' | debconf-set-selections; \
    echo 'grub-pc grub-pc/install_devices_empty boolean true' | debconf-set-selections; \
    avcodec="$(apt-cache search --names-only '^libavcodec[0-9]+$' | awk '{print $1}' | grep -E '^libavcodec[0-9]+$' | sort -V | tail -n1)"; \
    apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus ca-certificates procps iproute2 kmod \
        "${kernel}" grub-pc \
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
