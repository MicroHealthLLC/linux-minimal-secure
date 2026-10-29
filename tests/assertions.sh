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

echo "== 1. minimalism"
check "apt Install-Recommends disabled" bash -c "apt-config dump | grep -Eq 'APT::Install-Recommends \"(0|false)\"'"
check "apt Install-Suggests disabled"   bash -c "apt-config dump | grep -Eq 'APT::Install-Suggests \"(0|false)\"'"
for p in xserver-xorg-core xterm xauth x11-utils; do check "graphical package ${p} purged" not_installed "$p"; done
avc=$(dpkg-query -W -f='${Package}\n' 'libavcodec[0-9]*' 2>/dev/null | head -n1)
check "dependency-aware purge kept non-graphical ${avc:-libavcodec}" installed "${avc:-libavcodec-missing}"
for p in inetutils-telnet rpcbind; do check "legacy service ${p} purged" not_installed "$p"; done
check "default target is multi-user" bash -c "[[ \$(systemctl get-default) == multi-user.target ]]"

echo "== 2. repositories, base stack, unattended upgrades"
check "deb822 official sources incl. -security" grep -q -- '-security' /etc/apt/sources.list.d/debian.sources
check "deb822 official sources incl. -updates"  grep -q -- '-updates' /etc/apt/sources.list.d/debian.sources
for p in openssh-server tmux curl git ufw fail2ban libpam-pwquality auditd unattended-upgrades sudo rsyslog aide apparmor; do
    check "package ${p} installed" installed "$p"
done
check "unattended-upgrade enabled daily" bash -c "apt-config dump | grep -q 'APT::Periodic::Unattended-Upgrade \"1\"'"
check "unattended-upgrade security origin" bash -c "apt-config dump | grep -q 'label=Debian-Security'"
check "apt-daily-upgrade.timer enabled" systemctl is-enabled apt-daily-upgrade.timer

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
check "GRUB entries remain bootable without password (--unrestricted)" grep -q -- '--unrestricted' /etc/grub.d/10_linux
check "OpenSSL FIPS provider active"    bash -c "openssl list -providers | grep -A3 -E '^[[:space:]]*fips' | grep -q 'status: active'"
check "OpenSSL default provider active" bash -c "openssl list -providers | grep -A3 -E '^[[:space:]]*default' | grep -q 'status: active'"
check "FIPS provider is the validated ${FIPS_VER:=3.1.2}" bash -c "openssl list -providers | grep -A3 -E '^[[:space:]]*fips' | grep -q 'version: ${FIPS_VER}'"
check "TLS client works through system OpenSSL (curl https)" curl -fsS -o /dev/null --max-time 30 https://deb.debian.org/debian/
check "SHA-256 served by FIPS provider" bash -c "echo x | openssl dgst -sha256 -propquery fips=yes"
check "MD5 refused under fips=yes (real FIPS module)" bash -c "! echo x | openssl dgst -md5 -propquery fips=yes"
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
if [[ ${CI_PRIVILEGED:-0} == 1 ]]; then
    check "runtime net.ipv4.conf.all.accept_redirects = 0" bash -c "[[ \$(sysctl -n net.ipv4.conf.all.accept_redirects) == 0 ]]"
    check "runtime net.ipv4.ip_forward = 0" bash -c "[[ \$(sysctl -n net.ipv4.ip_forward) == 0 ]]"
fi
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
check "UFW enabled at boot" bash -c "grep -q '^ENABLED=yes' /etc/ufw/ufw.conf"
check "UFW default deny incoming" bash -c "grep -q '^DEFAULT_INPUT_POLICY=\"DROP\"' /etc/default/ufw"
check "UFW SSH allowed" bash -c "grep -Eq -- '--dport 22 -j ACCEPT' /etc/ufw/user.rules"
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
check "fail2ban sshd jail active" bash -c "fail2ban-client status sshd"

check "AIDE watches the audit tools in aide.conf" grep -q '^/usr/sbin/auditctl p+i+n+u+g+s+b+acl+selinux+xattrs+sha512$' /etc/aide/aide.conf
check "AIDE configuration valid" aide --config-check --config /etc/aide/aide.conf
if [[ ${CI_PRIVILEGED:-0} == 1 ]]; then
    check "AIDE baseline database built" test -s /var/lib/aide/aide.db
fi
check "aidecheck.service and timer enabled" bash -c "systemctl is-enabled aidecheck.service && systemctl is-enabled aidecheck.timer"

echo "== 6. CUDA prerequisites and media/coturn libraries"
for p in libc6 libc6-dev gcc make dkms linux-headers-amd64 build-essential; do check "package ${p} installed" installed "$p"; done
check "nouveau blacklisted" grep -q '^blacklist nouveau' /etc/modprobe.d/60-harden-nouveau.conf
check "coturn itself NOT installed" not_installed coturn
for p in libopus0 libsrtp2-1 libmariadb3 libpq5 libsqlite3-0 libsystemd0 libx264-164; do check "media/coturn lib ${p}" installed "$p"; done
check "libevent openssl (coturn TLS) present" bash -c "dpkg-query -W -f='\${db:Status-Status}\n' 'libevent-openssl-2.1-7*' | grep -q installed"
check "no X server present" bash -c "! dpkg-query -W -f='\${db:Status-Status} \${Package}\n' 'xserver-*' 2>/dev/null | grep -q '^installed'"

echo "== 6b. no stray backups inside include directories"
check "no backup copies inside *.d / grub.d directories" bash -c "! find /etc -path '*.d/*' \( -name '*.pre-harden' -o -name '*.bak' \) | grep -q ."
check "originals backed up under /var/backups/harden-and-audit" test -f /var/backups/harden-and-audit/etc/ssh/sshd_config

echo "== 7. OpenSCAP"
for p in openscap-utils openscap-scanner ssg-debian; do check "package ${p} installed" installed "$p"; done
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
