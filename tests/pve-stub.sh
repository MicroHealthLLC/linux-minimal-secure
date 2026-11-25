#!/bin/sh
# =============================================================================
# tests/pve-stub.sh - turn the Debian test image into a Proxmox VE look-alike.
#
# A real proxmox-ve cannot be installed in a container (pmxcfs, kernel), so the
# management stack is replaced by stub packages with the real names and the
# real dependencies the hardening must never break (postfix, nfs-common ->
# rpcbind, iptables), plus everything the script reads or changes on a node:
#   - the enterprise PVE and Ceph repositories (answer 401 without a key) and
#     the real Proxmox archive keyring (the no-subscription repo must work),
#   - /etc/pve: corosync.conf, storage.cfg (dir + NFS storage), cluster.fw
#     with an admin rule and ipset that must survive,
#   - systemd-boot style /etc/kernel/cmdline and a proxmox-boot-tool stub,
#   - pvebanner.service (rewrites /etc/issue at boot), pve-firewall.service,
#   - an admin sysctl enabling IPv4 forwarding (NAT guests), a root password.
# Stub versions are 99.x so the no-subscription repository never "upgrades"
# them to the real packages during the test.
# =============================================================================
set -eux
. /etc/os-release
case $VERSION_CODENAME in
    bookworm) PVEVER=8.4.1; CEPH=ceph-quincy ;;
    trixie)   PVEVER=9.0.10; CEPH=ceph-squid ;;
    *) echo "no Proxmox VE release for ${VERSION_CODENAME}" >&2; exit 1 ;;
esac

echo 'postfix postfix/main_mailer_type select Local only' | debconf-set-selections
echo "postfix postfix/mailname string pve1.ci.invalid" | debconf-set-selections
apt-get update
apt-get install -y --no-install-recommends curl postfix nfs-common chrony iptables dpkg-dev

# --- Proxmox archive keyring + enterprise repositories (as the installer leaves them)
if [ "$VERSION_CODENAME" = bookworm ]; then
    curl -fsSL -o /etc/apt/trusted.gpg.d/proxmox-release-bookworm.gpg \
        https://enterprise.proxmox.com/debian/proxmox-release-bookworm.gpg
    echo "deb https://enterprise.proxmox.com/debian/pve bookworm pve-enterprise" \
        >/etc/apt/sources.list.d/pve-enterprise.list
    echo "deb https://enterprise.proxmox.com/debian/${CEPH} bookworm enterprise" \
        >/etc/apt/sources.list.d/ceph.list
else
    curl -fsSL -o /usr/share/keyrings/proxmox-archive-keyring.gpg \
        https://enterprise.proxmox.com/debian/proxmox-archive-keyring-trixie.gpg
    cat >/etc/apt/sources.list.d/pve-enterprise.sources <<EOF
Types: deb
URIs: https://enterprise.proxmox.com/debian/pve
Suites: trixie
Components: pve-enterprise
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
    cat >/etc/apt/sources.list.d/ceph.sources <<EOF
Types: deb
URIs: https://enterprise.proxmox.com/debian/${CEPH}
Suites: trixie
Components: enterprise
Signed-By: /usr/share/keyrings/proxmox-archive-keyring.gpg
EOF
fi

# --- stub packages
B=/tmp/pvestub
mk() {  # mk NAME DEPENDS
    install -d "$B/$1/DEBIAN"
    cat >"$B/$1/DEBIAN/control" <<EOF
Package: $1
Version: 99.0-ci1
Architecture: all
Maintainer: CI <ci@invalid>
Depends: $2
Description: CI stub of $1 (harden-and-audit.sh tests)
EOF
}
mk pve-firewall "iptables"
install -d $B/pve-firewall/usr/sbin $B/pve-firewall/lib/systemd/system
cat >$B/pve-firewall/usr/sbin/pve-firewall <<'EOF'
#!/bin/sh
# CI stub: "compile" rejects a cluster.fw without an [OPTIONS] section.
case $1 in
    compile) [ ! -f /etc/pve/firewall/cluster.fw ] || grep -q '^\[OPTIONS\]' /etc/pve/firewall/cluster.fw ;;
    status) echo "Status: enabled/running" ;;
    *) exit 0 ;;
esac
EOF
cat >$B/pve-firewall/lib/systemd/system/pve-firewall.service <<'EOF'
[Unit]
Description=Proxmox VE firewall (CI stub)
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/pve-firewall start
[Install]
WantedBy=multi-user.target
EOF
chmod 0755 $B/pve-firewall/usr/sbin/pve-firewall

mk pve-manager "postfix | mail-transport-agent, nfs-common, pve-firewall, chrony | time-daemon"
install -d $B/pve-manager/usr/bin $B/pve-manager/usr/sbin $B/pve-manager/lib/systemd/system
cat >$B/pve-manager/usr/bin/pveversion <<EOF
#!/bin/sh
echo "pve-manager/${PVEVER}/0000000000000000 (running kernel: \$(uname -r))"
EOF
cat >$B/pve-manager/usr/bin/pvesubscription <<'EOF'
#!/bin/sh
printf 'message: There is no subscription key\nserverid: 00000000000000000000000000000000\nstatus: notfound\nurl: https://www.proxmox.com/en/proxmox-virtual-environment/pricing\n'
EOF
cat >$B/pve-manager/usr/bin/pvebanner <<'EOF'
#!/bin/sh
printf '\n------------------------------------------------------------------------------\n\nWelcome to the Proxmox Virtual Environment. Please use your web browser to\nconfigure this server - connect to:\n\n  https://10.0.0.11:8006/\n\n------------------------------------------------------------------------------\n\n' >/etc/issue
EOF
cat >$B/pve-manager/lib/systemd/system/pvebanner.service <<'EOF'
[Unit]
Description=Proxmox VE Login Banner (CI stub)
[Service]
Type=oneshot
ExecStart=/usr/bin/pvebanner
RemainAfterExit=yes
[Install]
WantedBy=getty.target
EOF
cat >$B/pve-manager/usr/sbin/proxmox-boot-tool <<'EOF'
#!/bin/sh
# CI stub: record what the hardening asks for.
echo "$(date -u +%FT%TZ) $*" >>/var/log/pbt-stub.log
case $1 in status) [ -s /etc/kernel/proxmox-boot-uuids ] ;; *) exit 0 ;; esac
EOF
chmod 0755 $B/pve-manager/usr/bin/* $B/pve-manager/usr/sbin/*

mk proxmox-ve "pve-manager"
for p in pve-firewall pve-manager proxmox-ve; do dpkg-deb --build --root-owner-group "$B/$p" "$B/$p.deb"; done
dpkg -i $B/pve-firewall.deb $B/pve-manager.deb $B/proxmox-ve.deb
systemctl enable pve-firewall.service pvebanner.service
apt-mark manual proxmox-ve pve-manager pve-firewall
rm -rf "$B"

# --- /etc/pve (pmxcfs on a real node; a plain directory here)
install -d -m 0755 /etc/pve/firewall /etc/pve/nodes/pve1/qemu-server /etc/pve/priv/lock
cat >/etc/pve/corosync.conf <<'EOF'
logging {
  debug: off
  to_syslog: yes
}
nodelist {
  node {
    name: pve1
    nodeid: 1
    quorum_votes: 1
    ring0_addr: 10.0.0.11
  }
  node {
    name: pve2
    nodeid: 2
    quorum_votes: 1
    ring0_addr: 10.0.0.12
  }
}
quorum {
  provider: corosync_votequorum
}
totem {
  cluster_name: ci
  config_version: 2
  interface {
    linknumber: 0
  }
  ip_version: ipv4-6
  secauth: on
  version: 2
}
EOF
cat >/etc/pve/storage.cfg <<'EOF'
dir: local
	path /var/lib/vz
	content iso,vztmpl,backup

dir: vmstore
	path /data/vmstore
	content images,rootdir

nfs: backup
	export /export/backup
	path /mnt/pve/backup
	server 10.0.0.50
	content backup

zfspool: local-zfs
	pool rpool/data
	sparse
	content images,rootdir
EOF
cat >/etc/pve/firewall/cluster.fw <<'EOF'
[OPTIONS]

policy_in: DROP

[IPSET management]

10.0.0.0/24

[RULES]

IN ACCEPT -source 10.0.0.0/24 -p tcp -dport 3128 # ci admin rule
EOF
printf 'storage: placeholder\n' >/etc/pve/nodes/pve1/lrm_status
printf 'quorate: 1\n' >/etc/pve/.members
install -d -m 0700 /root/.ssh
install -d /var/lib/vz/images/100 /var/lib/vz/template/iso /data/vmstore

# --- boot: systemd-boot style command line synced by proxmox-boot-tool
install -d /etc/kernel
echo "root=ZFS=rpool/ROOT/pve-1 boot=zfs quiet" >/etc/kernel/cmdline
echo "ABCD-1234" >/etc/kernel/proxmox-boot-uuids

# --- admin settings the hardening must respect
printf 'net.ipv4.ip_forward = 1\n' >/etc/sysctl.d/99-ci-pve-nat.conf
echo "root:$(head -c 24 /dev/urandom | base64)Aa1!" | chpasswd
apt-get purge -y dpkg-dev >/dev/null
apt-get autoremove -y >/dev/null
apt-get clean
rm -rf /var/lib/apt/lists/*
