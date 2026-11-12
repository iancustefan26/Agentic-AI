# Incident Report: Unauthorized Access and Privilege Escalation

## Executive Summary
- **Severity:** CRITICAL
- **Compromise Confirmed:** Yes
- **Attacker IP:** `198.51.100.77`

## Evidence
- Successful SSH root login from `198.51.100.77` via password authentication.
- Execution of `sudo` command to download a remote payload (`/tmp/.x`) from the attacker's IP via `curl`.
- Creation of a backdoor user account (`svc-backup`) with UID 0 (root privileges).

## Post-Exploitation Activity
- **Payload Download:** Fetched and stored a script from the C2 server to `/tmp/.x`.
- **Persistence:** Created a persistent backdoor root account (`svc-backup`).

## Recommended Firewall / Mitigation Commands
```bash
# UFW
ufw deny from 198.51.100.77 to any port 22

# iptables
iptables -A INPUT -p tcp --dport 22 -s 198.51.100.77 -j DROP
```
