"""LLM streaming with LiteLLM."""
import os
from litellm import completion
from anthropic import Anthropic
from db import get_requests, add_msg, get_findings, add_finding, get_rules, get_triggers, get_prompts, get_plans

API_BASE = os.getenv("LITELLM_API_BASE")
API_KEY = os.getenv("LITELLM_API_KEY")
MODEL = os.getenv("LITELLM_MODEL", "claude-sonnet-4-5-20250929")

# Available models (match LiteLLM config names exactly)
MODELS = {
    "sonnet-4.5": "claude-sonnet-4-5-20250929",
    "opus-4.5": "anthropic/claude-opus-4-5-20251101",  # Prefix required in LiteLLM
    "opus-4.1": "claude-opus-4-1-20250805",
    "haiku-4.5": "claude-haiku-4-5-20251001",
}

# Thinking budgets (max 60K to leave room for response, API limit 64K)
THINKING_BUDGETS = {
    "none": 0,
    "quick": 4000,
    "normal": 16000,
    "deep": 32000,
    "ultra": 60000  # Not 64K to satisfy max_tokens > budget
}

# Global thinking config
THINKING_MODE = os.getenv("THINKING_MODE", "none")  # none, quick, normal, deep, ultra

# =============================================================================
# INTENT CLASSIFICATION SYSTEM (Haiku classifier → deterministic routing)
# =============================================================================

INTENT_CONFIG = {
    "SAVE": {
        "model": "claude-sonnet-4-5-20250929",
        "tool_choice": {"type": "auto"},  # Auto pour permettre dedup (texte si duplicate)
        "temperature": 0.3,  # Précis, pas créatif
        "max_tokens": 1024,  # Réponse courte
        "tools": ["save_event"],  # Seul tool disponible
        "context": "minimal",  # Instructions + events pour dedup
        "description": "User rapporte résultat test"
    },
    "IDEA": {
        "model": "anthropic/claude-opus-4-5-20251101",  # Opus pour qualité
        "tool_choice": {"type": "tool", "name": "suggest_test"},
        "temperature": 0.9,  # Créatif
        "max_tokens": 4096,  # Réponse détaillée
        "tools": ["suggest_test"],
        "context": "full",  # BESOIN: events, requests, rules pour générer idées
        "description": "User demande suggestion test"
    },
    "MEMORY": {
        "model": "claude-sonnet-4-5-20250929",  # Sonnet (Haiku pas sur LiteLLM proxy)
        "tool_choice": {"type": "none"},
        "temperature": 0.1,  # Factuel
        "max_tokens": 2048,
        "tools": [],  # Pas de tools
        "context": "events",  # Juste les events pour lister
        "description": "User demande infos stockées"
    },
    "CHAT": {
        "model": "claude-sonnet-4-5-20250929",
        "tool_choice": {"type": "auto"},
        "temperature": 0.7,  # Équilibré
        "max_tokens": 4096,
        "tools": ["save_event", "suggest_test", "show_analysis", "ask_clarification"],
        "context": "full",  # Discussion peut référencer tout
        "description": "Discussion générale"
    }
}

def classify_intent(msg: str) -> str:
    """
    Classify user intent using Haiku (cheap, fast, deterministic).
    Returns: SAVE | IDEA | MEMORY | CHAT
    """
    # Use Anthropic SDK directly for Haiku (more reliable than LiteLLM for this)
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        # Fallback to CHAT if no API key
        return "CHAT"

    client = Anthropic(api_key=anthropic_key)

    prompt = f"""Classifie ce message en UNE catégorie:
- SAVE: user rapporte résultat de test (ex: "j'ai testé X", "ça marche", "vulnérable", "bloqué")
- IDEA: user demande suggestion/idée (ex: "idée de bypass", "quoi tester", "suggère")
- MEMORY: user demande infos stockées (ex: "t'as quoi en mémoire", "montre events", "liste")
- CHAT: autre (questions, discussions, explications)

Message: "{msg}"

Réponds UNIQUEMENT par: SAVE, IDEA, MEMORY ou CHAT"""

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=10,
            temperature=0,  # CRITIQUE: déterministe
            messages=[{"role": "user", "content": prompt}]
        )

        intent = response.content[0].text.strip().upper()

        # Validate intent
        if intent in INTENT_CONFIG:
            return intent

        # Fallback if unexpected response
        return "CHAT"

    except Exception as e:
        # Fallback on error
        print(f"[dim]Intent classifier error: {e}[/dim]")
        return "CHAT"

# Tools for auto-learning
BLV_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "save_event",
            "description": """Sauvegarde un résultat de test BLV (avec dédup automatique).

⚠️ QUAND UTILISER (OBLIGATOIRE - toutes conditions):
- User décrit un test qu'il a FAIT dans son message ACTUEL
- User confirme résultat (marche/bloqué) dans son message ACTUEL
- Keywords: "j'ai testé", "ça marche", "vulnérable", "bloqué", "refusé"

❌ JAMAIS UTILISER SI:
- User demande une idée/suggestion → utilise suggest_test
- User pose une question → réponds en texte
- Info vient de messages PRÉCÉDENTS (anti-bleeding)
- Aucun résultat explicite dans message ACTUEL
- Pattern+target DÉJÀ dans les "PATTERNS VALIDÉS" du contexte

📝 NOTE: Dédup automatique par hash(pattern+target). Si duplicate → message "déjà en mémoire".

RÈGLE: 1 message = 1 intent. Ne JAMAIS combiner save_event + suggest_test.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Pattern descriptif (ex: 3DS2 PaRes replay cross-card, HMAC bypass state manipulation)"},
                    "worked": {"type": "boolean", "description": "True si vulnérable/bypass réussi, False si bloqué/refusé"},
                    "target": {"type": "string", "description": "Nom du site/app (ex: Cdiscount, PayPal, Stripe)"},
                    "technique": {"type": "string", "description": "Méthode technique précise (ex: Replay token cross-card, Drop validation + reuse requestId)"},
                    "impact": {"type": "string", "description": "Conséquence sécurité (ex: Payment bypass, IDOR account takeover, Double-spend)"},
                    "notes": {"type": "string", "description": "Détails contextuels du user et résultat observé"},
                    "payload": {"type": "string", "description": "Requête HTTP ou payload utilisé (optionnel)"}
                },
                "required": ["pattern", "worked", "target", "technique", "impact"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "show_analysis",
            "description": """Affiche analyse structurée dans Panel. OBLIGATOIRE pour toute analyse >50 mots.

Utilise pour: réponses hypothèses, analyses patterns, explications techniques.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Titre court (ex: 3DS Bypass Analysis)"},
                    "pattern": {"type": "string", "description": "Nom du pattern analysé"},
                    "target": {"type": "string", "description": "Cible (site/API)"},
                    "hypothesis": {"type": "string", "description": "Hypothèse technique"},
                    "tests": {"type": "array", "items": {"type": "string"}, "description": "Liste tests à effectuer (3-5 max)"},
                    "impact": {"type": "string", "description": "Impact si vulnérable"},
                    "confidence": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH"], "description": "Niveau confiance"}
                },
                "required": ["title", "pattern", "hypothesis", "tests"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_test",
            "description": """Suggère un test précis avec steps.

⚠️ QUAND UTILISER:
- User demande une idée: "idée de bypass", "quoi tester", "suggère"
- User demande suite logique: "et après?", "next step"

❌ JAMAIS UTILISER SI:
- User rapporte un résultat de test → utilise save_event
- User pose question générale → réponds en texte

RÈGLE: Ne JAMAIS combiner avec save_event dans même réponse.""",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Pattern à tester"},
                    "target": {"type": "string", "description": "Cible"},
                    "steps": {"type": "array", "items": {"type": "string"}, "description": "Étapes précises (3-5 max)"},
                    "variables": {"type": "array", "items": {"type": "string"}, "description": "Variables critiques à manipuler"},
                    "expected": {"type": "string", "description": "Résultat attendu si vulnérable"}
                },
                "required": ["pattern", "steps", "expected"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "ask_clarification",
            "description": """Demande clarification quand input ambigu.

⚠️ QUAND UTILISER:
- Message incompréhensible ou <10 caractères
- Manque contexte critique pour répondre
- Ambiguïté sur ce que user veut

❌ JAMAIS UTILISER SI:
- Message clair même si court
- Contexte suffisant dans historique""",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {"type": "string", "description": "Question claire (max 20 mots)"}
                },
                "required": ["question"]
            }
        }
    }
]

def execute_hooks(event, tool_name, args):
    """Execute hooks for given event and tool. Returns (action, message, updated_args)."""
    from db import get_hooks
    import json
    import re

    # Get matching hooks
    hooks = get_hooks(event=event, active_only=True)

    for hook in hooks:
        # Check if hook matches tool (exact match or wildcard)
        matcher = hook['matcher']
        if matcher != "*" and matcher != tool_name:
            # Try regex match
            try:
                if not re.match(matcher, tool_name):
                    continue
            except:
                continue  # Invalid regex, skip

        # Execute check based on check_type
        check_type = hook['check_type']
        check_value = hook['check_value']
        action = hook['action']
        message = hook['message'] or ""

        try:
            if check_type == "length":
                # Check text length (for field specified in check_value)
                field = check_value or "title"
                value = args.get(field, "")
                max_len = 50  # Default
                if ":" in check_value:
                    field, max_len = check_value.split(":")
                    max_len = int(max_len)
                    value = args.get(field, "")

                if len(value) > max_len:
                    return (action, message.format(field=field, max=max_len), args)

            elif check_type == "required_fields":
                # Check required fields exist and non-empty
                fields = json.loads(check_value) if check_value else []
                missing = [f for f in fields if not args.get(f)]
                if missing:
                    return (action, message.format(fields=", ".join(missing)), args)

            elif check_type == "min_count":
                # Check array has minimum items
                field, min_count = check_value.split(":") if ":" in check_value else (check_value, "1")
                value = args.get(field, [])
                if not isinstance(value, list) or len(value) < int(min_count):
                    return (action, message.format(field=field, min=min_count), args)

            elif check_type == "max_count":
                # Check array has maximum items
                field, max_count = check_value.split(":") if ":" in check_value else (check_value, "10")
                value = args.get(field, [])
                if isinstance(value, list) and len(value) > int(max_count):
                    return (action, message.format(field=field, max=max_count), args)

            elif check_type == "enum":
                # Check value is in allowed list
                field, allowed = check_value.split(":") if ":" in check_value else (check_value, "")
                value = args.get(field)
                allowed_values = allowed.split(",")
                if value and value not in allowed_values:
                    return (action, message.format(field=field, allowed=allowed), args)

        except Exception as e:
            # Hook execution error, log but continue
            pass

    # All hooks passed
    return ("allow", "", args)

def handle_tool_call(tool_name, args):
    """Execute tool and return result."""
    # Execute pre_tool hooks
    action, hook_msg, updated_args = execute_hooks("pre_tool", tool_name, args)
    if action == "deny":
        return f"❌ Hook bloqué: {hook_msg}"
    elif action == "warn":
        # Continue but show warning
        pass
    # Use updated args if modified by hooks
    args = updated_args

    if tool_name == "save_event" or tool_name == "save_finding":
        from db import add_event
        import json
        import sys

        # Validate required fields
        if not args.get("pattern") or not args.get("target"):
            return f"✗ Error: Missing required fields (pattern={args.get('pattern')}, target={args.get('target')})"

        # Try to save (returns status)
        status, data = add_event(
            pattern=args.get("pattern"),
            worked=args.get("worked", True),
            target=args.get("target"),
            technique=args.get("technique"),
            impact=args.get("impact"),
            notes=args.get("notes"),
            payload=args.get("payload")
        )

        # Handle duplicate
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            console = Console(file=sys.stderr)

            if status == "duplicate":
                console.print(f"[yellow]⚠️ Duplicate:[/] [dim]{args.get('pattern')}[/] on [dim]{args.get('target')}[/] [yellow](déjà en mémoire)[/]")
                return ""

            # Status line for new event
            if args.get("worked"):
                status_line = f"[green]✓ Saved:[/] [bold red]💥 VULN[/] [white]{args.get('pattern')}[/] on [cyan]{args.get('target')}[/]"
            else:
                status_line = f"[green]✓ Saved:[/] [bold blue]🛡️ BLOCKED[/] [white]{args.get('pattern')}[/] by [cyan]{args.get('target')}[/]"

            console.print(status_line)

            # Quick prompt for details (Enter=skip, d=details)
            console.print("[#FF8C00]   ↳ Enter=continuer, d=détails[/]", end="")
            try:
                choice = input(" ").strip().lower()
                if choice == 'd':
                    # Show full details in panel
                    details = []
                    if args.get("technique"):
                        details.append(f"[yellow]Technique:[/] {args.get('technique')}")
                    if args.get("impact"):
                        details.append(f"[red]Impact:[/] {args.get('impact')}")
                    if args.get("notes"):
                        details.append(f"[#FF8C00]Notes:[/] [white]{args.get('notes')}[/]")
                    if args.get("payload"):
                        details.append(f"[cyan]Payload:[/] {args.get('payload')[:100]}...")

                    if details:
                        console.print(Panel(
                            "\n".join(details),
                            title="[bold]📋 Détails[/]",
                            border_style="dim",
                            padding=(0, 1),
                            expand=False
                        ))
            except (EOFError, KeyboardInterrupt):
                pass  # User pressed Ctrl+C or Ctrl+D, just continue

            return ""
        except Exception:
            if args.get("worked"):
                return f"✓ Saved: VULN {args.get('pattern')} on {args.get('target')}"
            else:
                return f"✓ Saved: BLOCKED {args.get('pattern')} by {args.get('target')}"

    elif tool_name == "show_analysis":
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            import time

            console = Console(file=sys.stderr)

            with console.status("[cyan]📊 Construction analyse...", spinner="dots"):
                time.sleep(0.2)

            # Highlight pattern keywords
            pattern_text = args.get("pattern", "Inconnu")
            for keyword in ['bypass', 'injection', 'replay', 'corruption', 'HMAC', '3DS']:
                if keyword in pattern_text:
                    pattern_text = pattern_text.replace(keyword, f'[bold red]{keyword}[/]', 1)

            tests = args.get("tests", [])
            tests_formatted = '\n'.join([f"  [cyan]▸[/] {test}" for test in tests])

            confidence = args.get("confidence", "MEDIUM")
            conf_color = {"LOW": "yellow", "MEDIUM": "yellow", "HIGH": "green"}.get(confidence, "yellow")

            analysis = f"""[bold cyan]═══════════════════════════════[/]
[bold white]{pattern_text}[/]
[bold cyan]═══════════════════════════════[/]

[red]●[/] [bold white]Cible[/] [dim]→[/] [bold magenta]{args.get('target', 'Inconnu')}[/]
[yellow]●[/] [bold white]Hypothèse[/] [dim]→[/] [italic yellow]{args.get('hypothesis', 'Inconnu')}[/]

[bold magenta]⚡ TESTS[/]
{tests_formatted}

[bold]─────────────────────────────[/]
[green]✓[/] [dim]Impact:[/] [bold]{args.get('impact', 'Inconnu')}[/]
[{conf_color}]◆[/] [dim]Confiance:[/] [bold {conf_color}]{confidence}[/]"""

            console.print(Panel(
                analysis,
                title=f"📊 {args.get('title', 'Analyse')}",
                border_style="cyan",
                padding=(1, 2),
                expand=False
            ))

            return ""
        except Exception as e:
            return f"Analyse: {args.get('pattern', 'Inconnu')}"

    elif tool_name == "suggest_test":
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            import time

            console = Console(file=sys.stderr)

            with console.status("[cyan]🧪 Préparation test...", spinner="dots"):
                time.sleep(0.2)

            steps = args.get("steps", [])
            steps_formatted = '\n'.join([f"  [green]{i+1}.[/] {step}" for i, step in enumerate(steps)])

            variables = args.get("variables", [])
            vars_formatted = '\n'.join([f"  [yellow]•[/] {var}" for var in variables]) if variables else "  [dim]None specified[/]"

            test_panel = f"""[bold white]Pattern:[/] [bold cyan]{args.get('pattern', 'Unknown')}[/]
[bold white]Target:[/] [red]{args.get('target', 'Unknown')}[/]

[bold yellow]⚡ EXECUTION STEPS[/]
{steps_formatted}

[bold yellow]🎯 VARIABLES[/]
{vars_formatted}

[bold]─────────────────────────────[/]
[green]✓[/] [dim]Expected:[/] [bold]{args.get('expected', 'Unknown')}[/]"""

            console.print(Panel(
                test_panel,
                title="🧪 Test Suggestion",
                border_style="green",
                padding=(1, 2),
                expand=False
            ))

            return ""
        except Exception as e:
            return f"Test: {args.get('pattern', 'Unknown')}"

    elif tool_name == "ask_clarification":
        return f"❓ {args.get('question', 'Peux-tu préciser ?')}"

    return "Unknown tool"

LAST_PROMPT_TOKENS = 0
LAST_CACHE_READ_TOKENS = 0

def count_tokens(messages):
    """Estimate tokens (4 chars ≈ 1 token)."""
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, list):
            content = "".join(str(c.get("text", "")) for c in content)
        total += len(str(content)) // 4 + 4  # +4 for message overhead
    return total

def build_prompt(context_level="full"):
    """
    Build system prompt based on context level.

    context_level:
      - "full": everything (rules, plans, triggers, prompts, events, requests)
      - "events": only events (for MEMORY intent)
      - "minimal": just tool instructions (for SAVE intent)
    """
    parts = []

    # MINIMAL: instructions + recent events for dedup check
    if context_level == "minimal":
        parts.append("""# RÈGLE ABSOLUE
AVANT d'appeler save_event, tu DOIS vérifier la liste ci-dessous.
Si un event SIMILAIRE existe déjà → NE PAS appeler save_event → réponds "🔄 Déjà en mémoire: [pattern existant]"

Similaire = même pattern OU même technique OU même target+type de test

""")
        # Add recent events for dedup check by LLM
        from db import get_events
        events = get_events(worked_only=False, limit=20)
        if events:
            parts.append("# EVENTS EXISTANTS\n")
            for e in events:
                status = "💥" if e.get('worked') else "🛡️"
                parts.append(f"{status} {e['pattern']} | {e['target']}\n")
            parts.append("\n")

        parts.append("""# INSTRUCTION
- Si NOUVEAU test (pas dans la liste) → appelle save_event
- Si SIMILAIRE à un event existant → réponds "🔄 Déjà en mémoire: [pattern]"
- Réponds TOUJOURS en français
""")
        return "".join(parts)

    # EVENTS: only events list (for MEMORY intent)
    if context_level == "events":
        parts.append("Tu es un assistant BLV. Voici les events stockés en mémoire:\n\n")
        from db import get_events
        events = get_events(worked_only=False, limit=50)  # Plus d'events pour MEMORY
        if events:
            for e in events:
                status = "💥 VULN" if e.get('worked') else "🛡️ BLOCKED"
                line = f"- {status} | {e['pattern']}"
                if e.get('target'):
                    line += f" | {e['target']}"
                if e.get('technique'):
                    line += f" | {e['technique']}"
                if e.get('impact'):
                    line += f" | Impact: {e['impact']}"
                parts.append(line + "\n")
        else:
            parts.append("(aucun event enregistré)\n")
        parts.append("\nRéponds TOUJOURS en français.\n")
        return "".join(parts)

    # FULL: everything
    # 1. Behavioral Rules (SQLite) - FIRST for max impact
    rules = get_rules(active_only=True)
    if rules:
        parts.append("# RÈGLES COMPORTEMENTALES\n")
        for r in rules:
            parts.append(f"- {r['description']}\n")
        parts.append("\n")

    # 2. Plans (Targets & Objectives)
    plans = get_plans(active_only=True)
    if plans:
        parts.append("# PLAN ACTIF\n")
        for p in plans:
            parts.append(f"## {p['name']}\n")
            parts.append(f"- Target: {p['target']}\n")
            parts.append(f"- Objectif: {p['objective']}\n")
        parts.append("\n")

    # 3. BLV Triggers (SQLite)
    triggers = get_triggers(active_only=True)
    if triggers:
        parts.append("# TRIGGERS BLV\n")
        for t in triggers:
            parts.append(f"- {t['pattern']} → {t['response']}\n")
        parts.append("\n")

    # 4. Prompts (SQLite)
    prompts = get_prompts(active_only=True)
    for p in prompts:
        parts.append(p['content'] + "\n\n")

    # 5. Events DB (mémoire de l'IA)
    from db import get_events
    events = get_events(worked_only=False, limit=15)
    if events:
        parts.append("# 🧠 MÉMOIRE (events déjà enregistrés - NE PAS re-suggérer)\n")
        for e in events:
            status = "💥" if e.get('worked') else "🛡️"
            line = f"- {status} {e['pattern']}"
            if e.get('target'):
                line += f" | {e['target']}"
            if e.get('technique'):
                line += f" | {e['technique'][:50]}"
            parts.append(line + "\n")
        parts.append("\n⚠️ Ne JAMAIS suggérer un test similaire à ceux ci-dessus.\n\n")

    # 6. HTTP Requests DB (SQL)
    reqs = get_requests()
    if reqs:
        parts.append(f"# HTTP REQUESTS ({len(reqs)})\n")
        for r in reqs:
            parts.append(f"- {r['method']} {r['url']}\n")

    return "".join(parts)

def build_messages(history, new_msg, context_level="full"):
    """Build message list with cache_control for system + history."""
    messages = []

    # System prompt with cache
    sys_prompt = build_prompt(context_level)
    if sys_prompt:
        messages.append({
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": sys_prompt,
                    "cache_control": {"type": "ephemeral"}
                }
            ]
        })

    # Cache all history except last 2 messages
    if len(history) > 2:
        for msg in history[:-2]:
            if msg["role"] == "user":
                messages.append({
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": msg["content"],
                            "cache_control": {"type": "ephemeral"}
                        }
                    ]
                })
            else:
                messages.append(msg)

        # Last 2 messages (not cached)
        messages.extend(history[-2:])
    else:
        # History too short, no caching
        messages.extend(history)

    # New message (not cached)
    messages.append({"role": "user", "content": new_msg})

    # Count prompt tokens
    global LAST_PROMPT_TOKENS
    LAST_PROMPT_TOKENS = count_tokens(messages)

    return messages

def chat_stream_anthropic(msg, history, thinking_budget, use_tools=True, tool_choice=None, temperature=None, max_tokens=None, filtered_tools=None, context_level="full"):
    """Direct Anthropic API streaming with Extended Thinking support."""
    # Initialize Anthropic client (API key from .env)
    anthropic_key = os.getenv("ANTHROPIC_API_KEY")
    if not anthropic_key:
        raise ValueError("ANTHROPIC_API_KEY not set in .env")

    client = Anthropic(api_key=anthropic_key)

    # Build system prompt with appropriate context level
    sys_prompt = build_prompt(context_level)

    # Build messages (Anthropic format) - filter empty content
    messages = []
    for h in history:
        content = h["content"]
        # Skip messages with empty content (tool calls without response)
        if content and content.strip():
            messages.append({
                "role": h["role"],
                "content": content
            })
    messages.append({"role": "user", "content": msg})

    # Add user message to DB
    add_msg("user", msg)

    # Get model ID (strip LiteLLM prefix if present)
    model = os.getenv("LITELLM_MODEL", MODEL)
    if model.startswith("anthropic/"):
        model = model.replace("anthropic/", "")

    # Build API call kwargs (stream=True implicit with .stream())
    # Get config (override or from .env)
    final_max_tokens = max_tokens or int(os.getenv("MAX_TOKENS", "8192"))
    final_temperature = temperature if temperature is not None else float(os.getenv("TEMPERATURE", "1.0"))

    # Determine max_tokens based on thinking mode
    if thinking_budget > 0:
        # Thinking enabled: use 64K total (thinking uses budget, rest for response)
        base_max_tokens = 64000
    else:
        # No thinking: use override or user config
        base_max_tokens = final_max_tokens

    kwargs = {
        "model": model,
        "max_tokens": base_max_tokens,
        "temperature": final_temperature,
        "system": [
            {
                "type": "text",
                "text": sys_prompt,
                "cache_control": {"type": "ephemeral"}
            }
        ],
        "messages": messages
    }

    # Add thinking
    if thinking_budget > 0:
        kwargs["thinking"] = {
            "type": "enabled",
            "budget_tokens": thinking_budget
        }

    # Add tools
    if use_tools:
        # Use filtered tools if provided, otherwise all tools
        tools_to_use = filtered_tools if filtered_tools else BLV_TOOLS
        kwargs["tools"] = [
            {
                "name": tool["function"]["name"],
                "description": tool["function"]["description"],
                "input_schema": tool["function"]["parameters"]
            }
            for tool in tools_to_use
        ]
        # Add tool_choice if specified (force specific tool or disable)
        if tool_choice:
            kwargs["tool_choice"] = tool_choice

    # Stream response
    text = ""
    thinking_text = ""
    thinking_detected = False
    tool_calls_builder = {}
    usage_data = None

    with client.messages.stream(**kwargs) as stream:
        for event in stream:
            # Handle thinking blocks
            if hasattr(event, 'type'):
                if event.type == 'content_block_start':
                    if hasattr(event, 'content_block'):
                        block = event.content_block
                        if hasattr(block, 'type') and block.type == 'thinking':
                            thinking_detected = True
                            yield ("thinking_start", "")

                elif event.type == 'content_block_delta':
                    if hasattr(event, 'delta'):
                        delta = event.delta
                        if hasattr(delta, 'type'):
                            if delta.type == 'thinking_delta':
                                thinking_text += delta.thinking
                                yield ("thinking_chunk", delta.thinking)
                            elif delta.type == 'text_delta':
                                text += delta.text
                                yield ("content", delta.text)
                            elif delta.type == 'input_json_delta':
                                # Tool call arguments streaming
                                pass  # Handle below

                elif event.type == 'content_block_stop':
                    # Block finished
                    pass

            # Handle tool use (simpler in SDK)
            if hasattr(event, 'type') and event.type == 'content_block_start':
                if hasattr(event, 'content_block'):
                    block = event.content_block
                    if hasattr(block, 'type') and block.type == 'tool_use':
                        idx = event.index if hasattr(event, 'index') else 0
                        tool_calls_builder[idx] = {
                            "id": block.id,
                            "name": block.name,
                            "arguments": ""
                        }
                        yield ("tool_start", block.name)

            # Accumulate tool arguments
            if hasattr(event, 'type') and event.type == 'content_block_delta':
                if hasattr(event, 'delta') and hasattr(event.delta, 'type'):
                    if event.delta.type == 'input_json_delta':
                        idx = event.index if hasattr(event, 'index') else 0
                        if idx in tool_calls_builder:
                            tool_calls_builder[idx]["arguments"] += event.delta.partial_json

        # Extract usage after stream ends
        final_message = stream.get_final_message()
        if hasattr(final_message, 'usage'):
            usage_data = final_message.usage

    # Extract cache info and update globals
    global LAST_CACHE_READ_TOKENS, LAST_PROMPT_TOKENS
    if usage_data:
        # Anthropic SDK format
        LAST_PROMPT_TOKENS = getattr(usage_data, 'input_tokens', 0)
        LAST_CACHE_READ_TOKENS = getattr(usage_data, 'cache_read_input_tokens', 0)
    else:
        LAST_CACHE_READ_TOKENS = 0
        LAST_PROMPT_TOKENS = len(text) // 4  # Fallback estimate

    # Yield tool calls for cli.py to handle (with confirmation if needed)
    import json
    for idx in sorted(tool_calls_builder.keys()):
        tc = tool_calls_builder[idx]
        if tc["name"]:
            try:
                args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                # Yield for cli.py to confirm/execute
                yield ("tool_ready", {"name": tc["name"], "args": args})
            except Exception as e:
                yield ("tool_error", str(e))

    # Save assistant response with actual tokens
    output_tokens = getattr(usage_data, 'output_tokens', len(text)//4) if usage_data else len(text)//4
    add_msg("assistant", text, output_tokens)

    # Parse and save findings
    import re
    pattern_regex = r'\[FINDING:([^|\]]+)\|([^|\]]+)\|([^\]]*)\]'
    for match in re.finditer(pattern_regex, text, re.IGNORECASE):
        pat, worked, target = match.groups()
        add_finding(
            pattern=pat.strip(),
            worked=worked.strip().lower() in ('true', '1', 'yes', 'oui'),
            target=target.strip() if target.strip() else None
        )
        yield ("tool", f"save_finding({pat.strip()}, worked={worked.strip()}, target={target.strip()})")

def chat_stream(msg, history, thinking_enabled=None, use_tools=True, tool_choice=None, force_model=None, temperature=None, max_tokens=None, filtered_tools=None, context_level="full"):
    """
    thinking_enabled:
      - None = use THINKING_MODE from .env (default)
      - True = force enable (use .env budget or normal)
      - False = force disable (for /idea, etc.)
    tool_choice:
      - None = auto (model decides)
      - {"type": "tool", "name": "X"} = force specific tool
      - {"type": "none"} = no tools
      - {"type": "auto"} = explicit auto
    force_model:
      - Override model selection (for routing)
    temperature:
      - Override temperature (for routing)
    max_tokens:
      - Override max_tokens (for routing)
    filtered_tools:
      - List of tools to use (subset of BLV_TOOLS)
    context_level:
      - "full" / "events" / "minimal" (for routing optimization)
    """
    # Get model (forced or from env)
    model = force_model or os.getenv("LITELLM_MODEL", MODEL)

    # Determine thinking budget
    global THINKING_MODE
    thinking_mode = os.getenv("THINKING_MODE", THINKING_MODE)
    budget = THINKING_BUDGETS.get(thinking_mode, 0)

    # Override based on explicit thinking_enabled parameter
    if thinking_enabled is True and budget == 0:
        # Force enable with default budget
        budget = THINKING_BUDGETS["normal"]
    elif thinking_enabled is False:
        # Force disable (e.g., /idea)
        budget = 0
    # else: thinking_enabled is None, use .env config (budget already set)

    # Route to Anthropic SDK if Opus 4.5 (always, thinking or not)
    # Reason: LiteLLM doesn't support thinking, and consistent routing
    if "20251101" in model:
        # Use direct Anthropic API (thinking optional)
        yield from chat_stream_anthropic(msg, history, budget, use_tools, tool_choice, temperature, max_tokens, filtered_tools, context_level)
        return

    # Otherwise use LiteLLM (existing implementation)
    messages = build_messages(history, msg, context_level)

    add_msg("user", msg)

    # Get config (override or from .env)
    final_max_tokens = max_tokens or int(os.getenv("MAX_TOKENS", "8192"))
    final_temperature = temperature if temperature is not None else float(os.getenv("TEMPERATURE", "1.0"))

    kwargs = {
        "model": model,
        "messages": messages,
        "stream": True,
        "api_base": API_BASE,
        "api_key": API_KEY,
        "timeout": 120,
        "max_tokens": final_max_tokens,
        "temperature": final_temperature
    }

    if use_tools:
        # Use filtered tools if provided, otherwise all tools
        kwargs["tools"] = filtered_tools if filtered_tools else BLV_TOOLS
        # Add tool_choice if specified - convert Anthropic format to OpenAI format for LiteLLM
        if tool_choice:
            tc_type = tool_choice.get("type")
            if tc_type == "tool" and "name" in tool_choice:
                # Anthropic format → OpenAI format
                kwargs["tool_choice"] = {"type": "function", "function": {"name": tool_choice["name"]}}
            elif tc_type == "none":
                kwargs["tool_choice"] = "none"
            elif tc_type == "auto":
                kwargs["tool_choice"] = "auto"
            else:
                kwargs["tool_choice"] = tool_choice

    # Note: Thinking only works with Opus 4.5 via direct Anthropic SDK (above)
    # LiteLLM/Sonnet don't support Extended Thinking - ignore budget here

    response = completion(**kwargs)

    text = ""
    thinking_text = ""
    thinking_detected = False
    last_chunk = None
    tool_calls_builder = {}  # index → {name, arguments}

    for chunk in response:
        last_chunk = chunk

        if hasattr(chunk, 'choices') and chunk.choices:
            delta = chunk.choices[0].delta

            # Handle thinking content streaming (Claude 4+ format)
            if budget > 0:
                # Check for thinking in content blocks
                if hasattr(delta, 'content') and isinstance(delta.content, list):
                    for block in delta.content:
                        if hasattr(block, 'type') and block.type == 'thinking':
                            if not thinking_detected:
                                yield ("thinking_start", "")
                                thinking_detected = True
                            if hasattr(block, 'thinking'):
                                thinking_text += block.thinking
                                yield ("thinking_chunk", block.thinking)
                        elif hasattr(block, 'type') and block.type == 'text':
                            if hasattr(block, 'text'):
                                text += block.text
                                yield ("content", block.text)
                # Legacy format
                elif hasattr(delta, 'thinking') and delta.thinking:
                    if not thinking_detected:
                        yield ("thinking_start", "")
                        thinking_detected = True
                    thinking_text += delta.thinking
                    yield ("thinking_chunk", delta.thinking)

            # Handle tool calls (streaming - accumulate by index)
            if hasattr(delta, 'tool_calls') and delta.tool_calls:
                for tc in delta.tool_calls:
                    idx = tc.index if hasattr(tc, 'index') else 0

                    if idx not in tool_calls_builder:
                        tool_calls_builder[idx] = {"name": None, "arguments": "", "started": False}

                    if hasattr(tc, 'function'):
                        if hasattr(tc.function, 'name') and tc.function.name:
                            tool_calls_builder[idx]["name"] = tc.function.name
                            # Yield tool_start on first detection
                            if not tool_calls_builder[idx]["started"]:
                                yield ("tool_start", tc.function.name)
                                tool_calls_builder[idx]["started"] = True
                        if hasattr(tc.function, 'arguments') and tc.function.arguments:
                            tool_calls_builder[idx]["arguments"] += tc.function.arguments

            # Handle normal content (string format, when not in content blocks)
            if hasattr(delta, 'content') and delta.content and isinstance(delta.content, str):
                text += delta.content
                yield ("content", delta.content)

    # Yield tool calls for cli.py to handle (with confirmation if needed)
    import json
    for idx in sorted(tool_calls_builder.keys()):
        tc = tool_calls_builder[idx]
        if tc["name"]:
            try:
                args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                yield ("tool_ready", {"name": tc["name"], "args": args})
            except Exception as e:
                yield ("tool_error", str(e))

    # Extract cache info from last chunk (Anthropic format)
    global LAST_CACHE_READ_TOKENS
    if last_chunk and hasattr(last_chunk, 'usage'):
        usage = last_chunk.usage
        if hasattr(usage, 'cache_read_input_tokens'):
            LAST_CACHE_READ_TOKENS = usage.cache_read_input_tokens
        elif hasattr(usage, 'prompt_tokens_details'):
            details = usage.prompt_tokens_details
            if hasattr(details, 'cached_tokens'):
                LAST_CACHE_READ_TOKENS = details.cached_tokens
        else:
            LAST_CACHE_READ_TOKENS = 0
    else:
        LAST_CACHE_READ_TOKENS = 0

    add_msg("assistant", text, len(text)//4)
    
    # Parse and save findings from text (multiple formats)
    import re
    # Format: [FINDING:pattern|true|target]
    pattern_regex = r'\[FINDING:([^|\]]+)\|([^|\]]+)\|([^\]]*)\]'
    for match in re.finditer(pattern_regex, text, re.IGNORECASE):
        pat, worked, target = match.groups()
        add_finding(
            pattern=pat.strip(),
            worked=worked.strip().lower() in ('true', '1', 'yes', 'oui'),
            target=target.strip() if target.strip() else None
        )
        # Notify about saved finding
        yield ("tool", f"save_finding({pat.strip()}, worked={worked.strip()}, target={target.strip()})")


# =============================================================================
# ROUTED CHAT (Auto intent classification → forced tool_choice)
# =============================================================================

def chat_stream_routed(msg, history, use_routing=True):
    """
    Smart routing: Haiku classifies intent → routes to appropriate model with forced tool_choice.

    Args:
        msg: User message
        history: Conversation history
        use_routing: If False, fallback to regular chat_stream (for /idea, etc.)

    Yields: Same events as chat_stream + ("intent", intent_name) at start
    """
    if not use_routing:
        # Bypass routing (e.g., /idea already knows it wants suggest_test)
        yield from chat_stream(msg, history)
        return

    # 1. Classify intent with Haiku (~$0.0003, ~150ms)
    intent = classify_intent(msg)

    # Yield intent for UI feedback
    yield ("intent", intent)

    # 2. Get routing config
    config = INTENT_CONFIG.get(intent, INTENT_CONFIG["CHAT"])

    # 3. Extract all config params
    force_model = config["model"]
    tool_choice = config["tool_choice"]
    temperature = config.get("temperature", 0.7)
    max_tokens = config.get("max_tokens", 4096)
    allowed_tools = config.get("tools", [])
    context_level = config.get("context", "full")

    # For MEMORY intent, disable tools entirely
    use_tools = tool_choice.get("type") != "none" and len(allowed_tools) > 0

    # 4. Filter tools based on config
    filtered_tools = None
    if use_tools and allowed_tools:
        filtered_tools = [t for t in BLV_TOOLS if t["function"]["name"] in allowed_tools]

    # 5. Stream with forced config + context level
    yield from chat_stream(
        msg=msg,
        history=history,
        thinking_enabled=False,  # No thinking for routed calls (speed)
        use_tools=use_tools,
        tool_choice=tool_choice if use_tools else None,
        force_model=force_model,
        temperature=temperature,
        max_tokens=max_tokens,
        filtered_tools=filtered_tools,
        context_level=context_level
    )
