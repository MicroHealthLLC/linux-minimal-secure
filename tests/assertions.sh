#!/usr/bin/env bash
# =============================================================================
# tests/assertions.sh - functional verification of every owner requirement.
# Runs inside the hardened test container (as root). Exit status = failures.
# =============================================================================
set -uo pipefail

FAILS=0
ok()   { printf '  [PASS] %s\n' "$1"; }
bad()  { printf '  [FAIL] %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
installed() { [[ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null)" == installed ]]; }
not_installed() { ! installed "$1"; }
conf() { grep -Eq "^[[:space:]]*$2[[:space:]]*=[[:space:]]*$3[[:space:]]*$" "$1"; }
# Capture first: with pipefail, an early-exiting grep -q would SIGPIPE sshd.
sshd_t() { local out; out=$(sshd -T -C user=ciadmin,host=localhost,addr=127.0.0.1 2>/dev/null) || return 1; grep -qix "$1" <<<"$out"; }
# installed_like REGEX - some installed package name matches REGEX.
installed_like() { dpkg-query -W -f='${db:Status-Status} ${Package}\n' 2>/dev/null | awk '$1=="installed"{print $2}' | grep -E "$1" >/dev/null; }
# eff_sysctl KEY - value systemd-sysctl applies at boot (last assignment in
# sysctl.d processing order wins).
eff_sysctl() {
    { systemd-analyze cat-config sysctl.d 2>/dev/null \
        || /usr/lib/systemd/systemd-sysctl --cat-config 2>/dev/null \
        || /lib/systemd/systemd-sysctl --cat-config; } | awk -v k="$1" '
        { line=$0; sub(/^[[:space:]]*-/, "", line) }
        line ~ /^[[:space:]]*#/ { next }
        { split(line, kv, "="); key=kv[1]; gsub(/[[:space:]]/, "", key); gsub(/\//, ".", key) }
        key == k { v=substr(line, index(line, "=")+1); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v) }
        END { print v }'
}
sysctl_is() { [[ $(eff_sysctl "$1") == "$2" ]]; }

. /etc/os-release
OS=$ID
HARDEN_PROFILE=${HARDEN_PROFILE:-server}
ADMIN_ACCESS=${ADMIN_ACCESS:-ssh}
WS=0; [[ $HARDEN_PROFILE == workstation ]] && WS=1
SSH=1; [[ $ADMIN_ACCESS == none ]] && SSH=0
GATE_PROFILE=cis_level2_server; [[ $WS == 1 ]] && GATE_PROFILE=cis_level2_workstation
echo "== target: ${PRETTY_NAME} (HARDEN_PROFILE=${HARDEN_PROFILE}, ADMIN_ACCESS=${ADMIN_ACCESS})"

echo "== 1. minimalism"
check "apt Install-Recommends disabled" bash -c "apt-config dump | grep -Eq 'APT::Install-Recommends \"(0|false)\"'"
check "apt Install-Suggests disabled"   bash -c "apt-config dump | grep -Eq 'APT::Install-Suggests \"(0|false)\"'"
PURGED=(xserver-xorg-core xterm xauth x11-utils)
# A workstation keeps xauth: Xwayland's xserver-common depends on it.
[[ $WS == 1 ]] && PURGED=(xserver-xorg-core xterm x11-utils)
for p in "${PURGED[@]}"; do check "graphical package ${p} purged" not_installed "$p"; done
avc=$(dpkg-query -W -f='${Package}\n' 'libavcodec[0-9]*' 2>/dev/null | head -n1)
check "dependency-aware purge kept non-graphical ${avc:-libavcodec}" installed "${avc:-libavcodec-missing}"
for p in inetutils-telnet rpcbind; do check "legacy service ${p} purged" not_installed "$p"; done
check "nothing left listening on the portmapper port 111" bash -c "! ss -Htuln | awk '{print \$5}' | grep -Eq ':111\$'"
if [[ $WS == 1 ]]; then
    check "default target is graphical (workstation)" bash -c "[[ \$(systemctl get-default) == graphical.target ]]"
else
    check "default target is multi-user" bash -c "[[ \$(systemctl get-default) == multi-user.target ]]"
fi

echo "== 2. repositories, base stack, unattended upgrades"
SRC=/etc/apt/sources.list.d/${OS}.sources
check "deb822 official sources incl. -security" grep -q -- "${VERSION_CODENAME}-security" "$SRC"
check "deb822 official sources incl. -updates"  grep -q -- "${VERSION_CODENAME}-updates" "$SRC"
if [[ $OS == ubuntu ]]; then
    check "Ubuntu components main restricted universe multiverse" grep -q '^Components: main restricted universe multiverse$' "$SRC"
    check "no active duplicate official one-line entries" bash -c "! grep -Eq '^[[:space:]]*deb[[:space:]].*ubuntu\.com' /etc/apt/sources.list 2>/dev/null"
fi
BASE=(tmux curl git ufw fail2ban libpam-pwquality auditd unattended-upgrades sudo rsyslog aide apparmor)
[[ $SSH == 1 ]] && BASE=(openssh-server "${BASE[@]}")
for p in "${BASE[@]}"; do
    check "package ${p} installed" installed "$p"
done
check "unattended-upgrade enabled daily" bash -c "apt-config dump | grep -q 'APT::Periodic::Unattended-Upgrade \"1\"'"
if [[ $OS == ubuntu ]]; then
    check "unattended-upgrade security origin" bash -c "apt-config dump | grep -qF 'origin=Ubuntu,archive=\${distro_codename}-security,label=Ubuntu'"
else
    check "unattended-upgrade security origin" bash -c "apt-config dump | grep -q 'label=Debian-Security'"
fi
check "apt-daily-upgrade.timer enabled" systemctl is-enabled apt-daily-upgrade.timer
# Mandatory automatic security updates: effective config, live timers, real run.
for k in APT::Periodic::Enable APT::Periodic::Update-Package-Lists APT::Periodic::Unattended-Upgrade; do
    check "effective ${k} = 1" bash -c "eval \"\$(apt-config shell v $k)\"; [[ \$v == 1 ]]"
done
check "no apt.conf override disables periodic updates" bash -c "! grep -sEq '^[[:space:]]*APT::Periodic::(Enable|Update-Package-Lists|Download-Upgradeable-Packages|Unattended-Upgrade)[[:space:]]+\"?(0|false)' /etc/apt/apt.conf /etc/apt/apt.conf.d/*"
check "auto-upgrade settings read last (zz, sorts last)"  test -f /etc/apt/apt.conf.d/zz-harden-auto-upgrades
for u in apt-daily.timer apt-daily-upgrade.timer; do
    check "${u} active"     systemctl is-active --quiet "$u"
    check "${u} not masked" bash -c "[[ \$(systemctl is-enabled $u 2>/dev/null) != masked ]]"
done
check "no package blacklisted from security updates" bash -c "! apt-config dump | grep -q '^Unattended-Upgrade::Package-Blacklist:: '"
check "unattended-upgrade dry run succeeds"     timeout 300 unattended-upgrade --dry-run

echo "== 3. auditd rotation policy (owner exception)"
A=/etc/audit/auditd.conf
check "max_log_file = 20"                conf $A max_log_file 20
check "max_log_file_action = ROTATE"     conf $A max_log_file_action ROTATE
check "space_left_action = SYSLOG"       conf $A space_left_action SYSLOG
check "admin_space_left_action = SYSLOG" conf $A admin_space_left_action SYSLOG
check "disk_full_action = SYSLOG"        conf $A disk_full_action SYSLOG
check "disk_error_action = SYSLOG"       conf $A disk_error_action SYSLOG
check "no SUSPEND/SINGLE/HALT anywhere in auditd.conf" bash -c "! grep -Eiq '=[[:space:]]*(suspend|single|halt)\b' $A"
check "audit failure mode -f 1 (never panic)" bash -c "grep -hq '^-f 1' /etc/audit/rules.d/*.rules && ! grep -hq '^-f 2' /etc/audit/rules.d/*.rules"
check "audit rules immutable (-e 2)" grep -q '^-e 2' /etc/audit/rules.d/99-harden-finalize.rules
check "privileged command rules generated" grep -q 'path=/usr/bin/sudo' /etc/audit/rules.d/55-harden-privileged.rules
check "audit rules compile" augenrules --check
check "auditd enabled at boot" systemctl is-enabled auditd

echo "== 4. FIPS"
check "fips=1 on the GRUB command line" grep -Eq '^GRUB_CMDLINE_LINUX=".*\bfips=1\b' /etc/default/grub
check "fips=1 on the default GRUB command line string" grep -Eq '^GRUB_CMDLINE_LINUX_DEFAULT=".*\bfips=1\b' /etc/default/grub
check "audit=1 on the GRUB command line" grep -Eq '^GRUB_CMDLINE_LINUX=".*\baudit=1\b' /etc/default/grub
# Effective command line as grub-mkconfig sees it: /etc/default/grub, then
# every drop-in (cloud images override GRUB_CMDLINE_LINUX_DEFAULT there).
check "effective GRUB command line keeps fips=1 and audit=1 after drop-ins" bash -c '
    . /etc/default/grub; for f in /etc/default/grub.d/*.cfg; do [ -f "$f" ] && . "$f"; done
    [[ " $GRUB_CMDLINE_LINUX_DEFAULT " == *" fips=1 "* && " $GRUB_CMDLINE_LINUX " == *" fips=1 "* && " $GRUB_CMDLINE_LINUX " == *" audit=1 "* ]]'
check "GRUB entries remain bootable without password (--unrestricted)" grep -q -- '--unrestricted' /etc/grub.d/10_linux
check "OpenSSL FIPS provider active"    bash -c "openssl list -providers | grep -A3 -E '^[[:space:]]*fips' | grep -q 'status: active'"
check "OpenSSL default provider active" bash -c "openssl list -providers | grep -A3 -E '^[[:space:]]*default' | grep -q 'status: active'"
check "FIPS provider is the validated ${FIPS_VER:=3.1.2}" bash -c "openssl list -providers | grep -A3 -E '^[[:space:]]*fips' | grep -q 'version: ${FIPS_VER}'"
TLS_URL=https://deb.debian.org/debian/
[[ $OS == ubuntu ]] && TLS_URL=https://changelogs.ubuntu.com/meta-release-lts
check "TLS client works through system OpenSSL (curl https)" curl -fsS -o /dev/null --max-time 30 "$TLS_URL"
check "SHA-256 served by FIPS provider" bash -c "echo x | openssl dgst -sha256 -propquery fips=yes"
# FIPS-only context (fips + base providers, as the script's self-test): the
# module itself must refuse MD5 and serve SHA-256. "dgst -propquery" is not
# used: OpenSSL 3.0.2 (Ubuntu 22.04) ignores it for digests.
fips_only_md5_refused() {
    local c rc=0
    c=$(mktemp)
    printf 'openssl_conf = openssl_init\n[openssl_init]\nproviders = provider_sect\n[provider_sect]\nfips = fips_sect\nbase = base_sect\n[base_sect]\nactivate = 1\n' >"$c"
    cat /etc/ssl/fipsmodule.cnf >>"$c"
    echo x | OPENSSL_CONF=$c openssl dgst -md5 >/dev/null 2>&1 && rc=1
    echo x | OPENSSL_CONF=$c openssl dgst -sha256 >/dev/null 2>&1 || rc=1
    rm -f "$c"
    return "$rc"
}
check "MD5 refused by the FIPS module, SHA-256 served (FIPS-only context)" fips_only_md5_refused
check "FIPS module self-test on load passes (integrity + KATs)" bash -c "echo x | openssl dgst -sha384 -provider fips"

echo "== 5. CIS / STIG controls"
check "/etc/shadow root:shadow 0640"  bash -c "[[ \$(stat -c '%U:%G %a' /etc/shadow) == 'root:shadow 640' ]]"
check "/etc/gshadow root:shadow 0640" bash -c "[[ \$(stat -c '%U:%G %a' /etc/gshadow) == 'root:shadow 640' ]]"
check "/etc/passwd root:root 0644"    bash -c "[[ \$(stat -c '%U:%G %a' /etc/passwd) == 'root:root 644' ]]"
check "/etc/group root:root 0644"     bash -c "[[ \$(stat -c '%U:%G %a' /etc/group) == 'root:root 644' ]]"
S=/etc/sysctl.d/60-harden.conf
for kv in 'net.ipv4.ip_forward = 0' 'net.ipv4.conf.all.accept_redirects = 0' 'net.ipv4.conf.all.accept_source_route = 0' \
          'net.ipv4.conf.all.send_redirects = 0' 'net.ipv6.conf.all.accept_redirects = 0' 'net.ipv4.tcp_syncookies = 1'; do
    check "sysctl file: ${kv}" grep -qx "$kv" "$S"
done
# Vendor files (Ubuntu 10-/55-network-security, *protect-links*) must not
# override the hardening at boot.
check "boot-time net.ipv4.conf.all.rp_filter = 1" sysctl_is net.ipv4.conf.all.rp_filter 1
check "boot-time kernel.sysrq = 0"               sysctl_is kernel.sysrq 0
check "boot-time fs.protected_fifos = 2"         sysctl_is fs.protected_fifos 2
if [[ ${CI_PRIVILEGED:-0} == 1 ]]; then
    check "runtime net.ipv4.conf.all.accept_redirects = 0" bash -c "[[ \$(sysctl -n net.ipv4.conf.all.accept_redirects) == 0 ]]"
    check "runtime net.ipv4.ip_forward = 0" bash -c "[[ \$(sysctl -n net.ipv4.ip_forward) == 0 ]]"
fi
if [[ $SSH == 1 ]]; then
    check "sshd config valid"              sshd -t
    check "sshd PermitRootLogin no"        sshd_t 'permitrootlogin no'
    check "sshd X11Forwarding no"          sshd_t 'x11forwarding no'
    check "sshd MaxAuthTries 4"            sshd_t 'maxauthtries 4'
    check "sshd ClientAliveInterval 300"   sshd_t 'clientaliveinterval 300'
    check "sshd ClientAliveCountMax 3"     sshd_t 'clientalivecountmax 3'
    check "sshd FIPS ciphers only"         sshd_t 'ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'
    check "sshd FIPS MACs only"            sshd_t 'macs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'
    check "sshd running" systemctl is-active ssh
    check "ANTI-LOCKOUT: sudo admin can still SSH in with a key" \
        ssh -i /root/ciadmin_key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 ciadmin@127.0.0.1 true
    check "root SSH login is rejected" \
        bash -c "! ssh -i /root/root_key -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 root@127.0.0.1 true"
else
    check "ADMIN_ACCESS=none: openssh-server not installed" not_installed openssh-server
    check "ADMIN_ACCESS=none: nothing listens on port 22" bash -c "! ss -Htln | awk '{print \$4}' | grep -Eq ':22\$'"
    check "ADMIN_ACCESS=none: ssh units masked" bash -c "[[ \$(systemctl is-enabled ssh.service 2>&1) == masked ]]"
fi
check "UFW enabled at boot" bash -c "grep -q '^ENABLED=yes' /etc/ufw/ufw.conf"
check "UFW default deny incoming" bash -c "grep -q '^DEFAULT_INPUT_POLICY=\"DROP\"' /etc/default/ufw"
if [[ $SSH == 1 ]]; then
    check "UFW SSH allowed" bash -c "grep -Eq -- '--dport 22 -j ACCEPT' /etc/ufw/user.rules"
else
    check "UFW opens no SSH port (ADMIN_ACCESS=none)" bash -c "! grep -Eq -- '--dport 22 -j ACCEPT' /etc/ufw/user.rules"
fi
check "UFW does not re-disable martian logging" bash -c "grep -q '^net/ipv4/conf/all/log_martians=1' /etc/ufw/sysctl.conf"
check "login.defs has no unknown items" bash -c "! chage -l root 2>&1 | grep -q 'configuration error'"
if [[ ${CI_PRIVILEGED:-0} == 1 ]]; then
    check "UFW active" bash -c "ufw status | grep -q 'Status: active'"
    check "ufw.service unit active" systemctl is-active ufw.service
    check "runtime log_martians = 1 after UFW start" bash -c "[[ \$(sysctl -n net.ipv4.conf.all.log_martians) == 1 ]]"
fi
check "pam_faillock enabled"    grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth
check "pam_pwquality enabled"   grep -q 'pam_pwquality.so' /etc/pam.d/common-password
check "pam_pwhistory enabled"   grep -q 'pam_pwhistory.so.*remember=24' /etc/pam.d/common-password
check "no nullok"               bash -c "! grep -Eq '^[^#].*nullok' /etc/pam.d/common-auth /etc/pam.d/common-password"
check "DoD banner on /etc/issue.net" grep -q 'U.S. Government (USG) Information System' /etc/issue.net
check "sudo log file configured" grep -q '^Defaults logfile="/var/log/sudo.log"' /etc/sudoers.d/60-harden
check "sudo I/O logging configured" grep -q '^Defaults log_input, log_output' /etc/sudoers.d/60-harden
if [[ -L /etc/alternatives/sudo ]]; then
    check "classic sudo selected over sudo-rs (logging support)" bash -c "[[ \$(readlink -f /etc/alternatives/sudo) == */sudo.ws ]]"
fi
if [[ $OS == ubuntu ]]; then
    check "apport removed or masked" bash -c "! dpkg-query -W -f='\${db:Status-Status}' apport 2>/dev/null | grep -qx installed || systemctl is-enabled apport.service 2>&1 | grep -q masked"
    check "whoopsie not installed" not_installed whoopsie
    check "motd-news disabled" bash -c "[[ ! -f /etc/default/motd-news ]] || grep -q '^ENABLED=0' /etc/default/motd-news"
fi
if [[ $SSH == 1 ]]; then
    check "fail2ban sshd jail active" bash -c "fail2ban-client status sshd"
else
    check "fail2ban sshd jail switched off (no SSH server)" grep -Pzq '\[sshd\]\nenabled  = false' /etc/fail2ban/jail.d/60-harden.local
fi

check "AIDE watches the audit tools in aide.conf" grep -q '^/usr/sbin/auditctl p+i+n+u+g+s+b+acl+selinux+xattrs+sha512$' /etc/aide/aide.conf
check "AIDE configuration valid" aide --config-check --config /etc/aide/aide.conf
check "AIDE skips container storage" bash -c "aide --config /etc/aide/aide.conf -p f:/var/lib/containerd/x 2>&1 | grep -q 'negative rule'"
check "AIDE skips caches" bash -c "aide --config /etc/aide/aide.conf -p f:/var/cache/x 2>&1 | grep -q 'negative rule'"
check "AIDE skips home repositories" bash -c "aide --config /etc/aide/aide.conf -p f:/root/project/x 2>&1 | grep -q 'negative rule'"
check "AIDE still watches authorized_keys" bash -c "aide --config /etc/aide/aide.conf -p f:/root/.ssh/authorized_keys 2>&1 | grep -qi '^\\[x\\]'"
check "AIDE still watches system binaries" bash -c "aide --config /etc/aide/aide.conf -p f:/usr/bin/ls 2>&1 | grep -qi '^\\[x\\]'"  # 0.18 prints [X], 0.19 [x]
if [[ ${CI_PRIVILEGED:-0} == 1 ]]; then
    check "AIDE baseline database built" test -s /var/lib/aide/aide.db
fi
# Ubuntu 24.04+ aide-common ships dailyaidecheck.timer (used as is). Debian
# (whose Debian CIS content checks aidecheck) and Ubuntu 22.04 (cron job
# only) get the script's aidecheck units.
if [[ $OS == ubuntu && ( -f /usr/lib/systemd/system/dailyaidecheck.timer || -f /lib/systemd/system/dailyaidecheck.timer ) ]]; then
    check "vendor dailyaidecheck.timer enabled" systemctl is-enabled dailyaidecheck.timer
    check "no duplicate aidecheck.timer" bash -c "! systemctl cat aidecheck.timer >/dev/null 2>&1"
else
    check "aidecheck.service and timer enabled" bash -c "systemctl is-enabled aidecheck.service && systemctl is-enabled aidecheck.timer"
fi
if [[ $OS == ubuntu ]]; then
    check "TMOUT readonly+exported (POSIX form)" grep -Pzq 'TMOUT=[0-9]+\s+readonly TMOUT\s+export TMOUT' /etc/profile.d/60-harden.sh
    check "/etc/netplan watched by auditd" grep -q '^-w /etc/netplan/ -p wa' /etc/audit/rules.d/52-harden-netplan.rules
fi

echo "== 5b. bounded logs: hourly rotation + /var/log budget"
check "logrotate keeps a short local buffer"     grep -Eq '^rotate ([1-9]|1[0-4])$' /etc/logrotate.conf
check "logrotate size-caps every log"           grep -Eq '^maxsize [0-9]+[kMG]$' /etc/logrotate.conf
check "logrotate.timer runs hourly"             bash -c "systemctl cat logrotate.timer | grep -qx 'OnCalendar=hourly'"
check "logrotate.timer enabled"                 systemctl is-enabled --quiet logrotate.timer
check "budget prune runs after each logrotate"  bash -c "systemctl cat logrotate.service | grep -qx 'ExecStartPost=-/usr/local/sbin/harden-log-budget'"
check "budget prune script is root-only"        bash -c "[[ \$(stat -c '%a %U' /usr/local/sbin/harden-log-budget) == '700 root' ]]"
check "own logs rotated"                        logrotate -d /etc/logrotate.d/harden-and-audit
check "/var/log within budget"                  bash -c "(( \$(du -sxb /var/log | cut -f1) <= \$(numfmt --from=iec 4G) ))"
# Budget prunes oldest rotated archives only, never live logs or the journal.
BT=$(mktemp -d /var/log/ci-budget.XXXX)
head -c 3000000 /dev/zero >"$BT/old.log.1"; touch -d '-9 day' "$BT/old.log.1"
head -c 1000 /dev/zero >"$BT/live.log"
USED=$(du -sxb /var/log | cut -f1)
/usr/local/sbin/harden-log-budget "$(( USED - 1000000 ))" 0 >/dev/null
check "budget prunes the oldest rotated archive" test ! -e "$BT/old.log.1"
check "budget never touches a live log"         test -e "$BT/live.log"
rm -rf "$BT"
check "OpenSCAP closing line reports n/N rules"  grep -Eq "\] OpenSCAP ${GATE_PROFILE}: completed in [0-9hms]+ \(exit [02]\) - [0-9]+/[0-9]+ rules \([0-9]+%\)" /var/log/harden-and-audit.log
check "step counter total is exact"             bash -c "grep -E '\[STEP [0-9]+/[0-9]+\] ===== done =====' /var/log/harden-and-audit.log | tail -n1 | grep -Eq '\[STEP ([0-9]+)/\1\]'"

echo "== 6. CUDA prerequisites and media/coturn libraries"
HDR=linux-headers-amd64
[[ $OS == ubuntu ]] && HDR=linux-headers-virtual     # the CI image boots linux-image-virtual
for p in libc6 libc6-dev gcc make dkms "$HDR" build-essential; do check "package ${p} installed" installed "$p"; done
check "nouveau blacklisted" grep -q '^blacklist nouveau' /etc/modprobe.d/60-harden-nouveau.conf
check "coturn itself NOT installed" not_installed coturn
for p in libopus0 libsrtp2-1 libmariadb3 libpq5 libsqlite3-0 libsystemd0; do check "media/coturn lib ${p}" installed "$p"; done
for r in '^libx264-[0-9]+$' '^libx265-[0-9]+$' '^libvpx[0-9]+' '^libdav1d[0-9]+$' '^libtheora[0-9]'; do
    check "media/coturn lib ${r}" installed_like "$r"
done
check "libevent openssl (coturn TLS) present" bash -c "dpkg-query -W -f='\${db:Status-Status}\n' 'libevent-openssl-2.1-7*' | grep -q installed"
if [[ $WS == 1 ]]; then
    # Xwayland's xserver-common stays; the X.Org server itself must not.
    check "no X.Org server present" bash -c "! dpkg-query -W -f='\${db:Status-Status} \${Package}\n' 'xserver-xorg*' 2>/dev/null | grep -q '^installed'"
else
    check "no X server present" bash -c "! dpkg-query -W -f='\${db:Status-Status} \${Package}\n' 'xserver-*' 2>/dev/null | grep -q '^installed'"
fi

echo "== 6b. no stray backups inside include directories"
check "no backup copies inside *.d / grub.d directories" bash -c "! find /etc -path '*.d/*' \( -name '*.pre-harden' -o -name '*.bak' \) | grep -q ."
if [[ $SSH == 1 ]]; then
    check "originals backed up under /var/backups/harden-and-audit" test -f /var/backups/harden-and-audit/etc/ssh/sshd_config
else
    check "originals backed up under /var/backups/harden-and-audit" test -f /var/backups/harden-and-audit/etc/ssl/openssl.cnf
fi

if [[ $WS == 1 ]]; then
    echo "== 6c. workstation (HARDEN_PROFILE=workstation)"
    for p in gdm3 xwayland pipewire wireplumber bluez network-manager libgl1-mesa-dri libgbm1 dconf-cli; do
        check "workstation package ${p} kept" installed "$p"
    done
    check "X.Org server still removed (Wayland session)" not_installed xserver-xorg-core
    check "xterm removed" not_installed xterm
    check "GDM banner enabled (dconf)"      grep -q '^banner-message-enable=true' /etc/dconf/db/gdm.d/00-harden-login-screen
    check "GDM banner is the DoD notice"    grep -q "^banner-message-text='You are accessing a U.S. Government" /etc/dconf/db/gdm.d/00-harden-login-screen
    check "GDM user list disabled"          grep -q '^disable-user-list=true' /etc/dconf/db/gdm.d/00-harden-login-screen
    check "GDM login-screen keys locked"    grep -qx '/org/gnome/login-screen/banner-message-text' /etc/dconf/db/gdm.d/locks/00-harden-login-screen
    check "XDMCP disabled"                  bash -c "awk '/^\\[xdmcp\\]/{x=1;next} /^\\[/{x=0} x && /^Enable=false\$/{f=1} END{exit !f}' /etc/gdm3/custom.conf"
    check "idle delay 900 s, locked"        bash -c "grep -q '^idle-delay=uint32 900' /etc/dconf/db/local.d/00-harden-session && grep -qx '/org/gnome/desktop/session/idle-delay' /etc/dconf/db/local.d/locks/00-harden-session"
    check "screen lock enabled, locked"     bash -c "grep -q '^lock-enabled=true' /etc/dconf/db/local.d/00-harden-session && grep -qx '/org/gnome/desktop/screensaver/lock-enabled' /etc/dconf/db/local.d/locks/00-harden-session"
    check "automount and autorun off"       bash -c "grep -q '^automount=false' /etc/dconf/db/local.d/00-harden-session && grep -q '^autorun-never=true' /etc/dconf/db/local.d/00-harden-session"
    check "dconf databases compiled"        bash -c "test -s /etc/dconf/db/gdm && test -s /etc/dconf/db/local"
    check "bluetooth.service masked (WORKSTATION_BLUETOOTH=off)" bash -c "[[ \$(systemctl is-enabled bluetooth.service 2>&1) == masked ]]"
    check "usb-storage still blacklisted"   grep -q '^install usb-storage /bin/false' /etc/modprobe.d/60-harden-blacklist.conf
    check "host profile remembered for --scan-only" grep -qx 'HARDEN_PROFILE=workstation' /var/lib/harden-and-audit/profile.env
fi

echo "== 7. OpenSCAP"
if [[ $OS == debian ]]; then
    OSCAP_PKGS=(openscap-utils openscap-scanner ssg-debian)
elif [[ $VERSION_ID == 22.04 ]]; then
    OSCAP_PKGS=(libopenscap8)                 # jammy packages no scanner/ssg split
else
    OSCAP_PKGS=(openscap-utils openscap-scanner ssg-debderived)
fi
for p in "${OSCAP_PKGS[@]}"; do check "package ${p} installed" installed "$p"; done
check "oscap available" command -v oscap
check "gate profile had applicable rules" bash -c "awk '/^(pass|fail):/ {n+=\$2} END {exit !(n>0)}' /var/log/scap-summary.txt"
if [[ $OS == ubuntu && $VERSION_ID == 26.04 ]]; then
    check "26.04 scanned with retargeted LTS content (noted in summary)" grep -q '^content note:' /var/log/scap-summary.txt
fi
check "XML results exist"  test -s /var/log/scap-results.xml
check "HTML report exists" test -s /var/log/scap-report.html
check "HTML report contains score" grep -q 'xccdf:scoring:default\|Score' /var/log/scap-report.html
check "summary written"    test -s /var/log/scap-summary.txt
check "weekly scan timer enabled" systemctl is-enabled scap-audit.timer

echo
if [[ $FAILS -eq 0 ]]; then
    echo "ALL ASSERTIONS PASSED"
else
    echo "${FAILS} ASSERTION(S) FAILED"
fi
exit "$FAILS"
