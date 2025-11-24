#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('blv.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()

parts = []

# Meta first
prompts = c.execute('SELECT content FROM prompts WHERE active=1 AND name="meta"').fetchall()
for p in prompts:
    parts.append(p['content'] + "\n\n")

# Rules
rules = c.execute('SELECT description FROM rules WHERE active=1').fetchall()
if rules:
    parts.append("# RÈGLES COMPORTEMENTALES\n")
    for r in rules:
        parts.append(f"- {r['description']}\n")
    parts.append("\n")

# Triggers
triggers = c.execute('SELECT pattern, response FROM triggers WHERE active=1').fetchall()
if triggers:
    parts.append("# TRIGGERS BLV\n")
    for t in triggers:
        parts.append(f"- {t['pattern']} → {t['response']}\n")
    parts.append("\n")

# Other prompts
prompts = c.execute('SELECT content FROM prompts WHERE active=1 AND name!="meta"').fetchall()
for p in prompts:
    parts.append(p['content'] + "\n\n")

prompt = "".join(parts)
print(prompt)
