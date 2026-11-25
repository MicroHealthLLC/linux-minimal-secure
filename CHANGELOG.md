# Changelog

## 2.2.2

Proxmox VE fixes:

- **Root SSH password lockout.** New `PVE_ROOT_PASSWORD_FROM` (CIDRs, default empty): root keeps password login from those networks through a `Match User root Address …` block; everywhere else root stays key-only. The key-only warning no longer looks at `/root/.ssh/authorized_keys`, which on Proxmox links to `/etc/pve/priv/authorized_keys` and always holds the cluster nodes' keys. It now always warns when root is key-only and no password networks are set.
- **faillock no longer locks root on Proxmox VE.** `even_deny_root` and `root_unlock_time` are left out there, because the web UI login (`root@pam`) uses the same PAM stack and anyone on the network could lock root out of both SSH and the web UI. `deny`, `unlock_time` and `fail_interval` still apply to every other user.
- **unattended-upgrades keeps other tools' settings.** `52unattended-upgrades-harden` no longer uses `#clear`, so its `Allowed-Origins`, `Origins-Pattern` and `Package-Blacklist` entries add to existing configuration instead of replacing it. On Proxmox VE, `origin=Proxmox,codename=${distro_codename}` is added to `Origins-Pattern`.
- **No more `-bash: TMOUT: readonly variable` at login (all distributions).** `60-harden.sh` only set TMOUT when it was unset, but never looked at existing TMOUT settings that run after it (a later `/etc/profile.d` file, `/etc/bash.bashrc`, root's dotfiles). Those assignments are now guarded (`[ -n "${TMOUT:-}" ] || …`, backed up first), so they apply only when TMOUT isn't set yet. Other users' dotfiles are reported, not edited.
