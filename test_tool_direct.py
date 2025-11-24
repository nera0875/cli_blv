#!/usr/bin/env python3
"""Test save_event tool directly with API."""
import json
import requests

API_BASE = "http://89.116.27.88:5000"
API_KEY = "sk-xHID9OmFQt_Bqe712cYi2w"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Tool definition
tool = {
    "type": "function",
    "function": {
        "name": "save_event",
        "description": "Save BLV test result. ALWAYS fill: pattern, worked, target, technique, impact.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "worked": {"type": "boolean"},
                "target": {"type": "string"},
                "technique": {"type": "string"},
                "impact": {"type": "string"}
            },
            "required": ["pattern", "worked", "target", "technique", "impact"]
        }
    }
}

# Conversation
messages = [
    {"role": "system", "content": "Tu es expert pentest. Quand user dit résultat test, appelle save_event() avec TOUS les paramètres remplis depuis contexte."},
    {"role": "user", "content": "j'ai testé PaRes replay: pris PaRes carte1 validée, collé sur carte2, débit effectué"},
    {"role": "assistant", "content": "Test confirmé. Je vais sauvegarder ce résultat."},
    {"role": "user", "content": "oui sauvegarde"}
]

data = {
    "model": "claude-sonnet-4-5-20250929",
    "messages": messages,
    "tools": [tool],
    "tool_choice": "auto"
}

print("Testing tool call with Sonnet...\n")
response = requests.post(
    f"{API_BASE}/chat/completions",
    headers=headers,
    json=data,
    timeout=30
)

if response.status_code == 200:
    result = response.json()
    message = result["choices"][0]["message"]

    print("Response:")
    print(f"  Content: {message.get('content')}")

    if message.get("tool_calls"):
        print(f"\n✓ Tool called!")
        for tc in message["tool_calls"]:
            print(f"  Name: {tc['function']['name']}")
            args = json.loads(tc['function']['arguments'])
            print(f"  Arguments:")
            for k, v in args.items():
                print(f"    {k}: {v}")
    else:
        print("\n✗ No tool call made")
else:
    print(f"Error {response.status_code}: {response.text}")
