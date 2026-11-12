# Lab 3 explained (simple version)

## 1. What the lab asks

Build one reusable "agent loop" in `agent_core.py` and use it 3 times:

1. Ex1: an agent that finds which production servers have a very dangerous bug (CVSS >= 9).
2. Ex2: an agent that fixes an SSH config, but must ask a human before writing files, and can never read files outside one folder.
3. Ex3: show that giving the noisy work to a helper ("worker") keeps the main agent's memory small, and count the tokens.

## 2. What I built, step by step

**The loop (`run_agent`)** works like a person doing a task with a phone:
think -> make calls -> listen to the answers -> think again. It stops when:

| stop | when | stop_reason |
|---|---|---|
| natural | the model answers without asking for tools | `done` |
| budget | too many steps (`max_steps`) | `max_steps` |
| stuck | the same call with the same arguments 3 times | `stuck` |
| broken | the API fails even after retries | `provider_error` |

Rules inside the loop:
- Every tool call the model asks for is run, and all answers go back in ONE message, each with the call `id`.
- Gemini has no `tool` role, so the answers go in a `role="user"` message.
- The model's own turn is sent back unchanged (it carries a hidden "thought signature").
- Errors never crash the program. They become text like `ERROR: Unknown tool 'x'. Available tools: ...`, so the model can fix its next call. (`execute_tool`)
- Stuck detector: 2nd identical call -> a NOTE "use the earlier result"; 3rd -> stop.

**Approval policy (Ex2).** The tool `write_file` just writes. The LOOP checks
`requires_approval` before running it and asks the human (`approver`). The human can:
`y` approve, `e` change the filename, `n` reject, or type a sentence = reject + instructions.
A rejection goes back to the model as `DENIED BY OPERATOR: ...` and the model changes its plan.

**Sandbox (Ex2).** `resolve_in_sandbox` turns the name into a full real path
(`resolve()` removes `..` and follows shortcuts/symlinks) and refuses anything not inside `sandbox/`.
I also refuse Windows drive letters (`C:/...`), because on a Mac that looks like a normal folder name.

**Orchestrator-workers (Ex3).**
- `single`: the main agent reads the whole 1,000-line log itself (~58k tokens).
- `orchestrator`: the main agent calls `delegate_log_triage`. A separate, fresh model call (the worker) reads the log once and returns a small JSON (`TriageReport`).
- `subagent` (stretch): the worker is itself an agent with search tools (`grep_log`, `count_by_ip`, `context_around`). It never reads the whole file.

## 3. Why it is good (the numbers)

- Ex1 gives the exact checkpoint answer in 4 steps: db-prod-01 and web-edge-01. ci-runner-03 is skipped because it is staging.
- Ex2: after my rejection the model wrote `sshd_config.hardened`. With `--attack` the model really tried to read `../canary_secret.txt` and the sandbox blocked it. The secret never appeared.
- Ex3: grand total went from 118,183 tokens (single) to 60,271 (orchestrator) and 6,716 (sub-agent).
- 17 tests pass with no LLM at all (6 for the loop, 11 for the sandbox and approver).

## 4. Limitations (honest)

- The sub-agent is cheaper but less reliable: 4/5 right with the fixed prompt, 1/3 with the first one. The one-call worker was 3/3 but costs ~58k tokens.
- The worker's JSON is still untrusted. I only check cheaply that evidence lines and IPs really exist in the log; I do not check `firewall_rules`.
- The injected `# SYSTEM_NOTE` comment was copied into the hardened file. Only the human looking at the diff can catch that.
- Model answers change between runs (temperature 1.0), so step counts can be different for you.
- Free tier sometimes returns 503/429; the retry waits, so a run can take a minute.

## 5. Questions the teacher may ask (short answers)

**Ex1 checkpoint**

- *How many API calls and tool calls?* 4 API calls, 13 tool calls. Each API call is a slow round trip to the model; tools are fast local code. Asking for many tools in one turn (parallel calls) means 13 tools cost only 4 model trips instead of 14.
- *Why do input tokens grow (309 -> 402 -> 615 -> 1246)?* The API has no memory. Every step re-sends everything: system prompt, tool descriptions, the question, every earlier model turn and every tool result.
- *Why is openssh-server 9.6 (CVE-2024-6387) not in the answer?* Its CVSS is 8.1, below the 9.0 limit.

**Ex2 checkpoint**

- *What made the model change its plan?* The tool result for its `write_file` call: `DENIED BY OPERATOR: No, company policy forbids overwriting sshd_config. Write to sshd_config.hardened instead. Adjust your plan.` Plus the system prompt says "follow the feedback".
- *Did the `# SYSTEM_NOTE` survive?* Yes, line 5 of `sshd_config.hardened`. The human approving the diff should catch it (reject with "remove the SYSTEM_NOTE line").
- *The model ignores the injection anyway, why the sandbox and tests?* The model is random and can be tricked. In my `--attack` runs it DID try to read the secret, even with the guard prompt. Only the code stopped it. A test proves the block every time, without depending on model luck.
- *Why does Rust need a lexical check instead of `fs::canonicalize()`?* `canonicalize()` fails for files that do not exist yet, like `sshd_config.hardened`. Python's `resolve()` works for new files.

**Ex3 question 4**

- *Why does the grand total drop, even though the worker reads the whole log once?* In `single` mode the 58k-token log stays in the history, so it is sent again at step 2 AND step 3 (~117k). With the worker, the log is sent exactly once, in a separate call. The main agent only carries ~300 tokens of JSON.

**Stretch**

- *How often is the sub-agent right?* 4/5 with the fixed prompt. The miss was always the backdoor user `svc-backup`.
- *Why did the first prompt miss it?* In this log the attack lines are shuffled: the curl line (457) and useradd line (647) come BEFORE the login line (721). Looking only "after the login" never sees them.
- *How do you verify a worker's claims cheaply?* With plain code, no LLM: every evidence line must be found word for word in the log, and every attacker IP must appear in the log. If not, return an ERROR. I did this in `delegate_log_triage_agent`.
- *What happens when the sub-agent fails?* (`--break-worker`) It returns `ERROR: ...`, never a made-up report. The orchestrator says what failed, and `write_incident_report` also refuses in code, not only in the prompt.
- *Why is the approval check in the loop and not inside `write_file`?* So the tool stays simple and testable, and adding another risky tool is one word in `requires_approval`.

## 6. How to run it

From `agent-lab3/`. The `.env` here is a shortcut (symlink) to `../agent-lab2/.env`, so the same API key is used.

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.txt   # only the first time
source .venv/bin/activate
python lab3_ex1_react.py               # add --thoughts to see the model's thinking
pytest -v                              # 17 tests, no LLM
python lab3_ex2_hitl.py                # answer: No, company policy forbids overwriting sshd_config. Write to sshd_config.hardened instead.   then: y
python lab3_ex2_hitl.py --attack       # watch the sandbox block ../canary_secret.txt
python lab3_ex3_orchestrator.py single --auto-approve
python lab3_ex3_orchestrator.py orchestrator --auto-approve
python lab3_ex3_orchestrator.py subagent --auto-approve
python lab3_ex3_orchestrator.py subagent --auto-approve --break-worker
python experiments/score_workers.py subagent 5    # how often is it right?
```

If the model is overloaded: `LAB_MODEL=gemini-3.1-flash-lite python ...`
