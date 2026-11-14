# Runs the lab's verification test many times, to check it passes reliably
# (temperature 0.7 means answers change from run to run).
import sys, io, contextlib
sys.path.insert(0, "..")
import chat_loop

RUNS = 10
passed = 0
for run in range(1, RUNS + 1):
    script = iter(["My project name is Project Chimera.", "What is the name of my project?", "exit"])
    with contextlib.redirect_stdout(io.StringIO()):
        history = chat_loop.chat(read_input=lambda prompt: next(script))
    answer = history[-1]["content"]
    ok = "chimera" in answer.lower()
    passed += ok
    print(f"run {run:2}: {'PASS' if ok else 'FAIL'} | {answer[:90]!r}")

print(f"\n{passed}/{RUNS} passed")

# Ollama down: point at a port where nothing listens
from openai import OpenAI
chat_loop.client = OpenAI(base_url="http://127.0.0.1:9/v1", api_key="ollama", max_retries=0)
script = iter(["hello", "exit"])
history = chat_loop.chat(read_input=lambda prompt: next(script))
print("history after failed call:", history)
