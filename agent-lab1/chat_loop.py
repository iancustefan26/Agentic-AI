from openai import OpenAI, APIConnectionError

# Same local Ollama server as in client_test.py
client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
MODEL = "qwen2.5:1.5b"

SYSTEM_PROMPT = (
    "You are a friendly academic mentor for a computer science student. "
    "Answer in at most 3 short sentences."
)


def chat(read_input=input):
    # The model remembers nothing between requests,
    # so this list IS the memory. We send all of it every time.
    history = [{"role": "system", "content": SYSTEM_PROMPT}]

    print("Chat started. Type 'exit' or 'quit' to stop.")
    while True:
        try:
            user_text = read_input("You: ").strip()
        except (EOFError, KeyboardInterrupt):  # Ctrl+D / Ctrl+C
            print()
            break

        if user_text.lower() in ("exit", "quit"):
            break
        if not user_text:
            continue

        # 1. Remember what the user said
        history.append({"role": "user", "content": user_text})

        # 2. Send the WHOLE conversation, not just the last message
        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=history,
                temperature=0.7,  # 0.7 = natural conversation (lab section 1)
            )
        except APIConnectionError:
            print("Cannot reach Ollama. Start it with: ollama serve")
            history.pop()  # forget the message that got no answer
            continue

        answer = response.choices[0].message.content
        print("Assistant:", answer)

        # 3. Remember what the model said, so the next turn sees it too
        history.append({"role": "assistant", "content": answer})

    print("Bye!")
    return history


if __name__ == "__main__":
    chat()
