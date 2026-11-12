"""Run a worker several times and count how often its report is right.

    cd agent-lab3 && python experiments/score_workers.py subagent 5
    cd agent-lab3 && python experiments/score_workers.py subagent-v1 3   # the first sub-agent prompt
    cd agent-lab3 && python experiments/score_workers.py structured 3
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import lab3_ex3_orchestrator as ex3

V1_PROMPT = ex3.SUBAGENT_SYSTEM.replace(ex3.POST_EXPLOIT_HINT, "")

which = sys.argv[1]
runs = int(sys.argv[2])
if which == "subagent-v1":
    ex3.SUBAGENT_SYSTEM = V1_PROMPT
worker = ex3.delegate_log_triage if which == "structured" else ex3.delegate_log_triage_agent

ex3.make_noisy_log()
rows = []
for i in range(runs):
    ex3.WORKER_TOKENS.clear()
    ex3.WORKER_ERRORS.clear()
    out = worker("auth.log")
    if out.startswith("ERROR"):
        rows.append({"run": i + 1, "result": "ERROR (refused)", "tokens": sum(ex3.WORKER_TOKENS)})
        continue
    r = json.loads(out.split(" NOTE:")[0])
    post = " ".join(r["post_exploitation"]).lower()
    checks = {
        "compromised": r["is_compromised"] is True,
        "only_attacker_ip": r["attacker_ips"] == [ex3.ATTACKER],
        "backdoor_user": "svc-backup" in post,
        "curl_download": "curl" in post or "x.sh" in post,
    }
    rows.append({"run": i + 1, "result": "RIGHT" if all(checks.values()) else "WRONG",
                 "failed": [k for k, ok in checks.items() if not ok], "severity": r["severity"],
                 "tokens": sum(ex3.WORKER_TOKENS)})
    time.sleep(5)

print(f"\n=== {which}: {sum(r['result'] == 'RIGHT' for r in rows)}/{runs} right ===")
for r in rows:
    print(r)
