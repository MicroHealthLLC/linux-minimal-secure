#!/bin/sh
# PID 1 shim for the test container: make the cgroup tree writable for systemd,
# drop the runtime's marker files so SCAP evaluates "machine"-platform rules as
# it would on a real host, then hand over to systemd. Podman bind-mounts
# /run/.containerenv, so it is unmounted before it can be removed (Docker has
# no such mount; the umount is a no-op there).
set -e
mount -o remount,rw /sys/fs/cgroup 2>/dev/null || true
umount /run/.containerenv 2>/dev/null || true
rm -f /.dockerenv /run/.containerenv
exec /sbin/init "$@"
