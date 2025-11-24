#!/usr/bin/env python3
"""Test AI behavior with different prompts."""
import sqlite3
import subprocess
import time

DB_PATH = "blv.db"

def update_meta_prompt(content):
    """Update meta prompt in DB."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE prompts SET content=? WHERE name='meta'", (content,))
    conn.commit()
    conn.close()
    print(f"✓ Updated meta prompt: {content[:60]}...")

def ask_ai(question):
    """Ask AI a question via CLI and capture response."""
    # Use echo to send question to CLI
    cmd = f'echo "{question}" | timeout 30 python3 cli.py'

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=35
        )

        # Extract AI response (after "● ")
        output = result.stdout
        lines = output.split('\n')

        # Find response after "● You:"
        response_lines = []
        capture = False
        for line in lines:
            if "● You:" in line and question in line:
                capture = True
                continue
            if capture and line.strip().startswith("●"):
                response_lines.append(line.replace("●", "").strip())

        response = "\n".join(response_lines)
        return response if response else output

    except Exception as e:
        return f"Error: {e}"

def count_words(text):
    """Count words in text."""
    return len(text.split())

def run_test(test_name, meta_prompt, question, expected_behavior):
    """Run single test."""
    print(f"\n{'='*70}")
    print(f"TEST: {test_name}")
    print(f"{'='*70}")

    # Update prompt
    update_meta_prompt(meta_prompt)
    time.sleep(1)

    # Ask question
    print(f"\nQuestion: {question}")
    response = ask_ai(question)

    # Analyze
    word_count = count_words(response)
    print(f"\n--- Response ({word_count} words) ---")
    print(response[:300] + "..." if len(response) > 300 else response)

    print(f"\n--- Analysis ---")
    print(f"Word count: {word_count}")
    print(f"Expected: {expected_behavior}")

    if word_count <= 150:
        print("✓ PASS: Respects 150 word limit")
    else:
        print("✗ FAIL: Exceeds 150 words")

    return word_count <= 150

# Test scenarios
tests = [
    {
        "name": "Baseline - No restriction",
        "prompt": "Réponds normalement.",
        "question": "quelles sont tes consignes ?",
        "expected": "Should be verbose"
    },
    {
        "name": "Strict 150 words",
        "prompt": "CRITICAL: MAX 150 mots. Sois direct. Pas de listes exhaustives.",
        "question": "quelles sont tes consignes ?",
        "expected": "Should be under 150 words"
    },
    {
        "name": "Ultra strict 100 words",
        "prompt": "OBLIGATION ABSOLUE: MAX 100 mots par réponse. Concis uniquement.",
        "question": "explique moi les race conditions",
        "expected": "Should be under 100 words"
    },
    {
        "name": "Bullet points forced",
        "prompt": "Réponds en bullet points courts (5 max). Max 80 mots total.",
        "question": "quels tests faire sur HMAC ?",
        "expected": "Should use bullets, under 80 words"
    }
]

print("🧪 Testing AI Prompt Compliance\n")

results = []
for test in tests:
    passed = run_test(
        test["name"],
        test["prompt"],
        test["question"],
        test["expected"]
    )
    results.append((test["name"], passed))
    time.sleep(2)

# Summary
print(f"\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")
for name, passed in results:
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"{status} - {name}")

# Restore original meta prompt
update_meta_prompt("CRITICAL: Réponds en MAX 150 mots. Sois direct et concis. Pas de listes exhaustives sauf si demandé explicitement.")
print("\n✓ Restored original meta prompt")
