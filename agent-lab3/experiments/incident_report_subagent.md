# Incident Report: Unauthorized SSH Access on srv-auth-01

## Summary
- **Severity:** HIGH
- **Compromised:** Yes
- **Incident Overview:** A brute-force SSH password guessing attack originating from IP `198.51.100.77` successfully targeted the root account on `srv-auth-01`, resulting in unauthorized root access.

## Evidence
- Repeated failed SSH password attempts for user `root` from `198.51.100.77` starting at `2026-11-05 01:05:57`.
- Successful login (`Accepted password for root`) from `198.51.100.77` at `2026-11-05 01:12:00`.

## Attacker
- **IP Address:** `198.51.100.77`

## Post-Exploitation Activity
- Successful authentication to the privileged `root` account via SSH password authentication.

## Remediation & Firewall Commands
To block the attacker IP, execute the following firewall rule:
```bash
sudo ufw deny from 198.51.100.77 to any
```
