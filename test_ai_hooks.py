#!/usr/bin/env python3
"""Test hooks avec vraie réponse AI."""
import db
from llm import chat_stream

print("=== TEST AI + HOOKS EN CONDITIONS RÉELLES ===\n")

# Init
db.init()

# Test 1: Message qui devrait forcer show_analysis
print("TEST 1: Demande analyse (AI doit appeler show_analysis)")
print("-" * 60)

messages = [
    {"role": "user", "content": "Analyse cette vulnérabilité: XSS reflected sur /search?q= chez example.com"}
]

response = ""
for chunk_type, chunk_content in chat_stream("", messages, use_cache=False):
    if chunk_type == "content":
        response += chunk_content
        print(chunk_content, end="", flush=True)
    elif chunk_type == "tool_call":
        print(f"\n\n🔧 Tool appelé: {chunk_content['name']}")
        print(f"   Args: {chunk_content['args']}")
    elif chunk_type == "tool_result":
        print(f"\n📊 Résultat: {chunk_content[:200]}")
        if "❌ Hook bloqué" in chunk_content:
            print("\n✓ HOOK A BLOQUÉ L'APPEL (expected)")
        elif "📊" in chunk_content or "Analyse" in chunk_content:
            print("\n✓ TOOL EXECUTÉ (args valides)")

print("\n\n" + "="*60 + "\n")

# Test 2: Message gibberish pour ask_clarification
print("TEST 2: Message incompréhensible (AI doit ask_clarification)")
print("-" * 60)

messages = [
    {"role": "user", "content": "zglkjzerg mlkqjerg qmlkjerg"}
]

response = ""
for chunk_type, chunk_content in chat_stream("", messages, use_cache=False):
    if chunk_type == "content":
        response += chunk_content
        print(chunk_content, end="", flush=True)
    elif chunk_type == "tool_call":
        print(f"\n\n🔧 Tool appelé: {chunk_content['name']}")
        print(f"   Args: {chunk_content['args']}")
    elif chunk_type == "tool_result":
        print(f"\n📊 Résultat: {chunk_content[:200]}")
        if "❌ Hook bloqué" in chunk_content:
            print("\n✓ HOOK A BLOQUÉ (question trop longue?)")
        elif "❓" in chunk_content:
            print("\n✓ CLARIFICATION DEMANDÉE")

print("\n\n=== FIN TESTS ===")
