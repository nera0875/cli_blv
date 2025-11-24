#!/usr/bin/env python3
"""Test AI directly via LiteLLM API."""
import sys
sys.path.insert(0, '/home/gesti/projects/cli_blv')

import db
from llm import build_prompt, chat_stream
import os

# Init DB
db.init()

def test_prompt_compliance(question, max_words=150):
    """Test if AI respects word limit."""
    print(f"\n{'='*70}")
    print(f"Question: {question}")
    print(f"Expected: Max {max_words} words")
    print(f"{'='*70}\n")

    # Build messages
    system_prompt = build_prompt()
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": question}
    ]

    # Get response
    response = ""
    try:
        for chunk_type, chunk_content in chat_stream(question, [], thinking_enabled=False):
            if chunk_type == "content":
                response += chunk_content
                print(chunk_content, end="", flush=True)
    except Exception as e:
        print(f"\n\n✗ Error: {e}")
        return False

    # Count words
    word_count = len(response.split())

    print(f"\n\n{'='*70}")
    print(f"Word count: {word_count}")

    if word_count <= max_words:
        print(f"✓ PASS - Under {max_words} words")
        return True
    else:
        print(f"✗ FAIL - Exceeds {max_words} words by {word_count - max_words}")
        return False

# Test 1: Baseline
print("TEST 1: Baseline question (should be under 150 words)")
test1 = test_prompt_compliance("quelles sont tes consignes ?", max_words=150)

# Test 2: Technical explanation
print("\n\nTEST 2: Technical question (should be under 150 words)")
test2 = test_prompt_compliance("explique les race conditions en BLV", max_words=150)

# Test 3: Direct command
print("\n\nTEST 3: Simple question (should be very short)")
test3 = test_prompt_compliance("qu'est-ce qu'un IDOR ?", max_words=100)

# Summary
print(f"\n\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")
print(f"Test 1 (consignes): {'✓ PASS' if test1 else '✗ FAIL'}")
print(f"Test 2 (race conditions): {'✓ PASS' if test2 else '✗ FAIL'}")
print(f"Test 3 (IDOR): {'✓ PASS' if test3 else '✗ FAIL'}")

if all([test1, test2, test3]):
    print("\n🎉 All tests passed!")
else:
    print("\n❌ Some tests failed - need to adjust meta prompt")
