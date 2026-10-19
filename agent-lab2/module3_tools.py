import json
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()


# 1. Deterministic local function with type annotations and docstring
def lookup_cve_details(cve_id: str) -> str:
    """Look up the CVSS severity score and technical summary for a given CVE identifier.

    Args:
        cve_id: The official CVE string, for example 'CVE-2024-3094'.
    """
    mock_db = {
        "CVE-2024-3094": {
            "cvss": 10.0,
            "affected": "xz-utils 5.6.0 and 5.6.1",
            "summary": "Malicious backdoor injected into liblzma build process hooking RSA_public_decrypt in sshd.",
        },
        "CVE-2021-44228": {
            "cvss": 10.0,
            "affected": "Apache Log4j2 2.0-beta9 to 2.14.1",
            "summary": "Unauthenticated remote code execution via JNDI lookup in logged messages (Log4Shell).",
        },
    }
    record = mock_db.get(cve_id.upper(), {"error": f"No record found for {cve_id}"})
    return json.dumps(record)


# Map of tool name -> real Python function, so the host decides what actually runs
TOOLS = {"lookup_cve_details": lookup_cve_details}


def run_manual_tool_roundtrip(user_prompt: str):
    # We disable automatic_function_calling so you can build the 4-step round-trip yourself
    config = types.GenerateContentConfig(
        system_instruction="You are a cybersecurity assistant. Always use tools to verify CVE data.",
        tools=[lookup_cve_details],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        temperature=0.0,
    )

    messages = [types.Content(role="user", parts=[types.Part.from_text(text=user_prompt)])]

    # Step 1 & 2: Send prompt + tool declarations; inspect the model's tool call request
    response = client.models.generate_content(
        model="gemini-3.5-flash-lite",
        contents=messages,
        config=config,
    )

    if response.function_calls:
        tool_call = response.function_calls[0]
        print(f"[LLM Requested Tool] Name: {tool_call.name} | Args: {tool_call.args}")

        # Step 3: Execute the requested function locally (the LLM never runs our code)
        fn = TOOLS.get(tool_call.name)
        if fn is None:
            tool_output = json.dumps({"error": f"Unknown tool {tool_call.name}"})
        else:
            tool_output = fn(**tool_call.args)
        print(f"[Local Function Output] {tool_output}")

        # Step 4a: Append the assistant's turn (the tool call request) to the history
        messages.append(response.candidates[0].content)

        # Step 4b: Append the tool response, paired with the function name.
        # Gemini carries function results in a "user" turn (the API rejects role="tool"
        # for this model with: "Role 'tool' is not supported").
        tool_response_part = types.Part.from_function_response(
            name=tool_call.name,
            response={"result": tool_output},
        )
        messages.append(types.Content(role="user", parts=[tool_response_part]))

        # Step 4c: Second LLM call with the full history -> final synthesized answer
        final_res = client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=messages,
            config=config,
        )
        print(f"\n[Final Synthesized Answer]\n{final_res.text}")
    else:
        print(f"[Direct LLM Answer]\n{response.text}")


if __name__ == "__main__":
    run_manual_tool_roundtrip("What is CVE-2024-3094, what versions are affected, and how severe is it?")
