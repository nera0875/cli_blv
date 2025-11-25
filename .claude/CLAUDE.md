# BLV CLI - Context Évolutif

## OBJECTIF
CLI pentest BLV avec routing intelligent multi-modèle.
On itère - le système apprend de l'usage réel.

---

## RÈGLES CRITIQUES

### Validation (OBLIGATOIRE)
```bash
uv run python -m py_compile cli.py db.py llm.py
uv run python -c "import db; db.init(); print('OK')"
```
**TOUJOURS `uv run python` - jamais `python` direct.**

### Git Save
Après chaque feature majeure:
```bash
git add . && git commit -m "feat: [desc]" && git push
```

---

## ARCHITECTURE

```
cli.py  → REPL, commandes, UI Rich
db.py   → SQLite (prompts, requests, findings, chat, tool_declines)
llm.py  → Claude API direct + extended thinking + prompt caching
```

**Stack:** Python 3.12, UV, Anthropic SDK, SQLite, Rich

---

## FEATURES ACTUELLES

- Routing multi-modèle (haiku/sonnet/opus selon complexité)
- `/idea` avec tool suggest_test
- Tool decline history (évite re-proposer tools refusés)
- Smart request summary
- Prompt caching (90% cost reduction)
- Import Burp XML
- Extended thinking pour tâches complexes

---

## MODÈLES CLAUDE

| Modèle | ID | Usage |
|--------|-----|-------|
| Haiku 4.5 | `claude-haiku-4-5-20251001` | Extraction rapide |
| Sonnet 4.5 | `claude-sonnet-4-5-20250929` | Hypothèses, chat |
| Opus 4.5 | `claude-opus-4-5-20251101` | Cartographie, analyse complexe |

### Extended Thinking
```python
response = client.messages.create(
    model="claude-opus-4-5-20251101",
    max_tokens=16000,
    thinking={"type": "enabled", "budget_tokens": 10000},
    messages=[...]
)
```

---

## CODE PATTERNS

```python
# DB: toujours cursor.lastrowid
cursor = c.execute("INSERT...")
return cursor.lastrowid

# Context manager obligatoire
with conn() as c:
    ...
```

---

## CE QUE J'APPRENDS

*(Mis à jour selon usage)*

- User préfère itération rapide > plans rigides
- Simplicité > over-engineering
- Si feature pas validée par usage → pas implémenter
- Routing intelligent > modèle fixe
- Tool decline history évite frustration user
- LiteLLM overkill pour prototype → Claude API direct

---

## À ÉVITER

- Over-engineering features non demandées
- Plans rigides multi-phases
- Dupliquer data (DB = source unique)
- `python` sans `uv run`
- Commit sans validation syntaxe
- Proxy/abstractions inutiles (LiteLLM)

---

## COMMANDES

```
/idea    → Suggère test BLV (tool-based)
/chat    → Stream conversation
/import  → Import Burp XML
/analyze → Cartographie flow (Opus + extended thinking)
/model   → Switch modèle
/clear   → Nouvelle conversation
/stats   → Statistiques usage
```

---

## ÉVOLUTIONS POSSIBLES

*(Idées - à valider par usage réel)*

- Export rapport vulns
- Techniques library (patterns qui marchent)
- Cross-request linking
