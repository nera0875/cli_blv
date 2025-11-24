# Tests Hooks - Guide Utilisateur

## Lancer le CLI

```bash
uv run python cli.py
```

## Tests à faire

### Test 1: Vérifier les hooks installés
```
/hooks
```
**Attendu:** Table avec 10 hooks actifs

---

### Test 2: Forcer show_analysis (devrait réussir)
```
/chat
```
Puis tape:
```
Analyse: XSS sur example.com/search?q= - input non sanitizé - teste <script>alert(1)</script> et variants
```

**Attendu:**
- AI appelle `show_analysis`
- Panel s'affiche avec analyse structurée
- Pas de blocage (args valides)

---

### Test 3: Demande analyse vague (AI devrait ask_clarification)
```
analyse ça
```

**Attendu:**
- AI appelle `ask_clarification`
- Question courte (<30 mots)
- Pas de texte libre >50 mots

---

### Test 4: Gibberish (AI doit demander clarification)
```
qsdkljfqsd mlkqjsdf qmlskdjf
```

**Attendu:**
- AI appelle `ask_clarification`
- Ou refuse de répondre en français

---

### Test 5: Demande suggestion test
```
propose un test pour bypass HMAC validation
```

**Attendu:**
- AI appelle `suggest_test`
- Panel avec steps numérotés
- Pattern + Expected + Variables

---

### Test 6: Toggle un hook puis reteste
```
/back
/hooks
```
Choisis "Toggle hook" → Désactive `analysis-title-length`

Retourne en chat:
```
/chat
```

Demande analyse avec titre ultra long - devrait passer maintenant.

---

## Vérifications

Pour chaque test, vérifie:

1. **Tool call visible:** `🔧 Tool: show_analysis` (ou autre)
2. **Spinner transition:** 0.3s avant Panel
3. **Panel display:** Bordures colorées, expand=False
4. **Hook blocking:** Si args invalides → `❌ Hook bloqué: [raison]`
5. **Aucun texte libre >50 mots** hors Panel

---

## Forcer échec hook (test avancé)

Modifie temporairement llm.py:

```python
# Dans handle_tool_call(), ligne ~180
# Ajoute debug:
if tool_name == "show_analysis":
    args["title"] = "A" * 60  # Force titre trop long
```

Puis relance chat → devrait voir `❌ Hook bloqué: Titre trop long`
