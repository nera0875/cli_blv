#!/usr/bin/env python3
"""Test hooks system."""
import db
from llm import execute_hooks

print("=== TEST HOOKS SYSTEM ===\n")

# Initialize DB
db.init()

# Get all hooks
hooks = db.get_hooks(active_only=False)
print(f"✓ Hooks chargés: {len(hooks)}\n")

# Test 1: show_analysis avec titre trop long (should deny)
print("TEST 1: show_analysis - titre trop long")
args = {
    "title": "A" * 60,  # > 50 chars
    "pattern": "test",
    "hypothesis": "test hyp",
    "tests": ["t1", "t2", "t3"],
    "impact": "HIGH",
    "confidence": "HIGH"
}
action, msg, updated = execute_hooks("pre_tool", "show_analysis", args)
print(f"  Action: {action}")
print(f"  Message: {msg}")
assert action == "deny", "Should deny long title"
print("  ✓ PASS\n")

# Test 2: show_analysis sans hypothesis (should deny)
print("TEST 2: show_analysis - hypothesis manquante")
args = {
    "title": "Test",
    "pattern": "test",
    "tests": ["t1", "t2", "t3"],
    "impact": "HIGH",
    "confidence": "HIGH"
}
action, msg, updated = execute_hooks("pre_tool", "show_analysis", args)
print(f"  Action: {action}")
print(f"  Message: {msg}")
assert action == "deny", "Should deny missing hypothesis"
print("  ✓ PASS\n")

# Test 3: show_analysis avec <3 tests (should deny)
print("TEST 3: show_analysis - <3 tests")
args = {
    "title": "Test",
    "pattern": "test",
    "hypothesis": "test hyp",
    "tests": ["t1", "t2"],  # Only 2
    "impact": "HIGH",
    "confidence": "HIGH"
}
action, msg, updated = execute_hooks("pre_tool", "show_analysis", args)
print(f"  Action: {action}")
print(f"  Message: {msg}")
assert action == "deny", "Should deny <3 tests"
print("  ✓ PASS\n")

# Test 4: show_analysis VALID (should allow)
print("TEST 4: show_analysis - VALIDE")
args = {
    "title": "Test Title",
    "pattern": "XSS bypass",
    "hypothesis": "Input not sanitized",
    "tests": ["t1", "t2", "t3"],
    "impact": "HIGH",
    "confidence": "HIGH"
}
action, msg, updated = execute_hooks("pre_tool", "show_analysis", args)
print(f"  Action: {action}")
print(f"  Message: {msg}")
assert action == "allow", "Should allow valid args"
print("  ✓ PASS\n")

# Test 5: ask_clarification - question trop longue (should deny)
print("TEST 5: ask_clarification - question trop longue")
args = {
    "question": " ".join(["word"] * 40)  # > 30 words
}
action, msg, updated = execute_hooks("pre_tool", "ask_clarification", args)
print(f"  Action: {action}")
print(f"  Message: {msg}")
assert action == "deny", "Should deny long question"
print("  ✓ PASS\n")

# Test 6: save_event sans required fields (should deny)
print("TEST 6: save_event - champs requis manquants")
args = {
    "pattern": "test"
    # Missing: target, technique, impact
}
action, msg, updated = execute_hooks("pre_tool", "save_event", args)
print(f"  Action: {action}")
print(f"  Message: {msg}")
assert action == "deny", "Should deny missing fields"
print("  ✓ PASS\n")

print("=== TOUS LES TESTS PASSÉS ✓ ===")
