# Test harness image for harden-and-audit.sh on the RHEL family (Rocky Linux,
# AlmaLinux, CentOS Stream 8/9/10, Fedora). DESKTOP=1 adds a GNOME desktop
# (GDM, graphical.target), printing and Bluetooth, and an enabled sshd: the
# script must keep all of them (desktop mode).
#
# Boots real systemd as PID 1 and mirrors a minimal server install: a kernel
# package (SCAP's "system_with_kernel" applicability), GRUB 2 + grubby, an
# unprivileged wheel admin (anti-lockout preflight), and seeded X11 and legacy
# packages the script must remove. gd (a non-graphical library linked
# against libX11 through libXpm) proves the purge takes no collateral.
ARG BASE_IMAGE=rockylinux/rockylinux:9
FROM ${BASE_IMAGE}
ARG DESKTOP=0
ARG VARIANT=""

ENV container=docker

RUN set -eux; \
    dnf -y -q install --setopt=install_weak_deps=False systemd dbus procps-ng iproute kmod passwd \
        shadow-utils util-linux findutils diffutils sudo; \
    # Kernel and bootloader without their scriptlets: no dracut/initramfs
    # build in a container, but rpm, /boot and /etc/default/grub look real.
    dnf -y -q install --setopt=install_weak_deps=False --setopt=tsflags=noscripts kernel-core grub2-tools grub2-pc grubby; \
    printf 'GRUB_TIMEOUT=5\nGRUB_DISTRIBUTOR="$(sed "s, release .*$,,g" /etc/system-release)"\nGRUB_DEFAULT=saved\nGRUB_DISABLE_SUBMENU=true\nGRUB_TERMINAL_OUTPUT="console"\nGRUB_CMDLINE_LINUX="crashkernel=auto rhgb quiet"\nGRUB_DISABLE_RECOVERY="true"\nGRUB_ENABLE_BLSCFG=true\n' > /etc/default/grub; \
    dnf -y -q install --setopt=install_weak_deps=False xterm xorg-x11-xauth telnet rpcbind gd; \
    if [ "$DESKTOP" = 1 ]; then \
        dnf -y -q install --setopt=install_weak_deps=False gdm gnome-shell cups bluez openssh-server; \
        systemctl enable gdm.service sshd.service; \
        systemctl set-default graphical.target; \
    fi; \
    dnf clean all; \
    rm -rf /var/cache/dnf; \
    systemctl mask systemd-firstboot.service systemd-udevd.service systemd-udevd-kernel.socket \
        systemd-udevd-control.socket systemd-modules-load.service getty@tty1.service console-getty.service \
        sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount; \
    useradd -m -s /bin/bash -G wheel ciadmin; \
    echo "ciadmin:$(head -c 24 /dev/urandom | base64)Aa1!" | chpasswd

# VARIANT=proxmox: Proxmox VE look-alike (Debian only); VARIANT=k8s: real
# container runtime + kubeadm control-plane layout. See the stub scripts.
COPY pve-stub.sh k8s-stub.sh /usr/local/share/ci/
RUN set -eux; \
    case "$VARIANT" in \
        proxmox) sh /usr/local/share/ci/pve-stub.sh ;; \
        k8s) sh /usr/local/share/ci/k8s-stub.sh ;; \
        "") ;; \
        *) echo "unknown VARIANT $VARIANT" >&2; exit 1 ;; \
    esac

COPY container-init.sh /usr/local/sbin/container-init

STOPSIGNAL SIGRTMIN+3
CMD ["/usr/local/sbin/container-init"]
