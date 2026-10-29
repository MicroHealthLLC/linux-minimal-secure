#!/bin/sh
# PID 1 shim for the test container: make the cgroup tree writable for systemd,
# drop Docker's marker file so SCAP evaluates "machine"-platform rules as it
# would on a real host, then hand over to systemd.
set -e
mount -o remount,rw /sys/fs/cgroup 2>/dev/null || true
rm -f /.dockerenv /run/.containerenv
exec /sbin/init "$@"
