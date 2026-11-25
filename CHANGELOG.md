# Changelog

## 2.2.2

Proxmox VE fixes:

- **Root SSH password lockout.** New `PVE_ROOT_PASSWORD_FROM` (CIDRs, default empty): root keeps password login from those networks through a `Match User root Address …` block; everywhere else root stays key-only. The key-only warning no longer looks at `/root/.ssh/authorized_keys`, which on Proxmox links to `/etc/pve/priv/authorized_keys` and always holds the cluster nodes' keys. It now always warns when root is key-only and no password networks are set.
- **faillock no longer locks root on Proxmox VE.** `even_deny_root` and `root_unlock_time` are left out there, because the web UI login (`root@pam`) uses the same PAM stack and anyone on the network could lock root out of both SSH and the web UI. `deny`, `unlock_time` and `fail_interval` still apply to every other user.
- **unattended-upgrades keeps other tools' settings.** `52unattended-upgrades-harden` no longer uses `#clear`, so its `Allowed-Origins`, `Origins-Pattern` and `Package-Blacklist` entries add to existing configuration instead of replacing it. On Proxmox VE, `origin=Proxmox,codename=${distro_codename}` is added to `Origins-Pattern`.
