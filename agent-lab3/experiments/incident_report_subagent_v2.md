# Incident Report: Unauthorized Access & Compromise (auth.log)

## Executive Summary
An analysis of `auth.log` revealed a successful brute-force attack followed by full system compromise originating from IP `198.51.100.77`. The attacker successfully guessed root credentials, downloaded malicious payloads, and established persistence by creating a privileged backdoor account.

## Evidence
- **Brute Force / Initial Access:** Repeated failed SSH login attempts from `198.51.100.77` leading to a successful password login for `root` at `2026-11-05 01:12:00`.
- **Malicious Command Execution:** Execution of `sudo` to download an external shell script (`/tmp/.x`) via `curl` from the attacker's IP.
- **Persistence Creation:** Creation of a new backdoor user account (`svc-backup`) with root privileges (UID=0, GID=0) at `01:10:46`.

## Attacker Information
- **IP Address:** `198.51.100.77`

## Post-Exploitation Activity
1. **Payload Download:** Fetched remote script to `/tmp/.x` via `curl`.
2. **Backdoor Account:** Created privileged user `svc-backup` with root/UID 0 access.

## Mitigation & Firewall Commands
To immediately block the attacker and secure the system, run the following firewall and remediation commands:

```bash
# Block the attacker IP
sudo ufw deny from 198.51.100.77 to any
sudo ufw reload

# Remove the unauthorized backdoor user and home directory
sudo userdel -r svc-backup

# Remove malicious payload artifacts
sudo rm -f /tmp/.x

# Force password resets / invalidate active sessions for compromised accounts
sudo passwd -l root
```
