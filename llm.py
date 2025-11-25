"""LLM streaming with Anthropic SDK - Full Claude API implementation."""
import os
import json
import re
from anthropic import Anthropic
from db import get_requests, add_msg, get_findings, add_finding, get_rules, get_triggers, get_prompts, get_plans

# Initialize Anthropic client
client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# =============================================================================
# MODELS
# =============================================================================

MODELS = {
    "haiku": "claude-haiku-4-5-20251001",
    "sonnet": "claude-sonnet-4-5-20250929",
    "opus": "claude-opus-4-5-20251101",
}

DEFAULT_MODEL = os.getenv("CLAUDE_MODEL", MODELS["sonnet"])

# =============================================================================
# THINKING BUDGETS (Extended Thinking)
# =============================================================================

THINKING_BUDGETS = {
    "none": 0,
    "quick": 4000,
    "normal": 16000,
    "deep": 32000,
    "ultra": 60000  # Max ~60K to leave room for response
}

THINKING_MODE = os.getenv("THINKING_MODE", "none")

# =============================================================================
# INTENT ROUTING SYSTEM
# =============================================================================

INTENT_CONFIG = {
    "SAVE": {
        "model": MODELS["sonnet"],
        "tool_choice": {"type": "auto"},
        "temperature": 0.2,
        "max_tokens": 512,
        "tools": ["save_event"],
        "context": "minimal",
        "description": "User rapporte résultat test"
    },
    "IDEA": {
        "model": MODELS["sonnet"],
        "tool_choice": {"type": "tool", "name": "suggest_test"},
        "temperature": 0.85,
        "max_tokens": 1500,
        "tools": ["suggest_test"],
        "context": "events",
        "description": "User demande suggestion test"
    },
    "MEMORY": {
        "model": MODELS["haiku"],
        "tool_choice": {"type": "none"},
        "temperature": 0.1,
        "max_tokens": 1024,
        "tools": [],
        "context": "events",
        "description": "User demande infos stockées"
    },
    "CHAT": {
        "model": MODELS["sonnet"],
        "tool_choice": {"type": "auto"},
        "temperature": 0.6,
        "max_tokens": 2048,
        "tools": ["save_event", "suggest_test", "show_analysis", "ask_clarification"],
        "context": "full",
        "description": "Discussion générale"
    },
    "ANALYZE": {
        "model": MODELS["opus"],
        "tool_choice": {"type": "none"},
        "temperature": 0.3,
        "max_tokens": 8192,
        "tools": [],
        "context": "full",
        "thinking_budget": THINKING_BUDGETS["deep"],
        "description": "Cartographie flow complexe"
    }
}

# =============================================================================
# TOOLS DEFINITIONS
# =============================================================================

BLV_TOOLS = [
    {
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

📝 NOTE: Dédup automatique par hash(pattern+target). Si duplicate → message "déjà en mémoire".

RÈGLE: 1 message = 1 intent. Ne JAMAIS combiner save_event + suggest_test.""",
        "input_schema": {
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
    },
    {
        "name": "show_analysis",
        "description": """Affiche analyse structurée dans Panel. OBLIGATOIRE pour toute analyse >50 mots.

Utilise pour: réponses hypothèses, analyses patterns, explications techniques.""",
        "input_schema": {
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
    },
    {
        "name": "suggest_test",
        "description": """Suggère un test précis avec steps.

⚠️ QUAND UTILISER:
- User demande une idée: "idée de bypass", "quoi tester", "suggère"
- User demande suite logique: "et après?", "next step"

❌ JAMAIS UTILISER SI:
- User rapporte un résultat de test → utilise save_event
- User pose question générale → réponds en texte

RÈGLE: Ne JAMAIS combiner avec save_event dans même réponse.""",
        "input_schema": {
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
    },
    {
        "name": "ask_clarification",
        "description": """Demande clarification quand input ambigu.

⚠️ QUAND UTILISER:
- Message incompréhensible ou <10 caractères
- Manque contexte critique pour répondre
- Ambiguïté sur ce que user veut

❌ JAMAIS UTILISER SI:
- Message clair même si court
- Contexte suffisant dans historique""",
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {"type": "string", "description": "Question claire (max 20 mots)"}
            },
            "required": ["question"]
        }
    }
]

# =============================================================================
# INTENT CLASSIFIER (Haiku - fast, cheap)
# =============================================================================

def classify_intent(msg: str) -> str:
    """Classify user intent using Haiku."""
    prompt = f"""Classifie ce message en UNE catégorie:
- SAVE: user rapporte résultat de test (ex: "j'ai testé X", "ça marche", "vulnérable", "bloqué")
- IDEA: user demande suggestion/idée (ex: "idée de bypass", "quoi tester", "suggère")
- MEMORY: user demande infos stockées (ex: "t'as quoi en mémoire", "montre events", "liste")
- CHAT: autre (questions, discussions, explications)

Message: "{msg}"

Réponds UNIQUEMENT par: SAVE, IDEA, MEMORY ou CHAT"""

    try:
        response = client.messages.create(
            model=MODELS["haiku"],
            max_tokens=10,
            temperature=0,
            messages=[{"role": "user", "content": prompt}]
        )
        intent = response.content[0].text.strip().upper()
        return intent if intent in INTENT_CONFIG else "CHAT"
    except Exception as e:
        print(f"[dim]Intent classifier error: {e}[/dim]")
        return "CHAT"

# =============================================================================
# PROMPT BUILDER
# =============================================================================

def build_prompt(context_level="full"):
    """Build system prompt based on context level."""
    parts = []

    if context_level == "minimal":
        parts.append("""# RÈGLE ABSOLUE
AVANT d'appeler save_event, tu DOIS vérifier la liste ci-dessous.
Si un event SIMILAIRE existe déjà → NE PAS appeler save_event → réponds "🔄 Déjà en mémoire: [pattern existant]"

""")
        from db import get_events
        events = get_events(worked_only=False, limit=20)
        if events:
            parts.append("# EVENTS EXISTANTS\n")
            for e in events:
                status = "💥" if e.get('worked') else "🛡️"
                parts.append(f"{status} {e['pattern']} | {e['target']}\n")
            parts.append("\n")
        parts.append("# INSTRUCTION\nRéponds TOUJOURS en français\n")
        return "".join(parts)

    if context_level == "events":
        parts.append("Tu es un assistant BLV. Voici les events stockés en mémoire:\n\n")
        from db import get_events
        events = get_events(worked_only=False, limit=50)
        if events:
            for e in events:
                status = "💥 VULN" if e.get('worked') else "🛡️ BLOCKED"
                line = f"- {status} | {e['pattern']}"
                if e.get('target'):
                    line += f" | {e['target']}"
                if e.get('technique'):
                    line += f" | {e['technique']}"
                parts.append(line + "\n")
        else:
            parts.append("(aucun event enregistré)\n")
        parts.append("\nRéponds TOUJOURS en français.\n")
        return "".join(parts)

    # FULL context
    rules = get_rules(active_only=True)
    if rules:
        parts.append("# RÈGLES COMPORTEMENTALES\n")
        for r in rules:
            parts.append(f"- {r['description']}\n")
        parts.append("\n")

    plans = get_plans(active_only=True)
    if plans:
        parts.append("# PLAN ACTIF\n")
        for p in plans:
            parts.append(f"## {p['name']}\n- Target: {p['target']}\n- Objectif: {p['objective']}\n")
        parts.append("\n")

    triggers = get_triggers(active_only=True)
    if triggers:
        parts.append("# TRIGGERS BLV\n")
        for t in triggers:
            parts.append(f"- {t['pattern']} → {t['response']}\n")
        parts.append("\n")

    prompts = get_prompts(active_only=True)
    for p in prompts:
        parts.append(p['content'] + "\n\n")

    from db import get_events
    events = get_events(worked_only=False, limit=15)
    if events:
        parts.append("# 🧠 MÉMOIRE (events déjà enregistrés - NE PAS re-suggérer)\n")
        for e in events:
            status = "💥" if e.get('worked') else "🛡️"
            line = f"- {status} {e['pattern']}"
            if e.get('target'):
                line += f" | {e['target']}"
            parts.append(line + "\n")
        parts.append("\n")

    reqs = get_requests()
    if reqs:
        parts.append(f"# HTTP REQUESTS ({len(reqs)} endpoints)\n")
        for r in reqs[:15]:
            line = f"- {r['method']} {r['url']}"
            if r.get('body'):
                try:
                    body_data = json.loads(r['body'])
                    if isinstance(body_data, dict):
                        keys = [k for k in body_data.keys() if any(
                            x in k.lower() for x in ['id', 'user', 'amount', 'price', 'payment', 'order', 'token', 'card']
                        )]
                        if keys:
                            line += f" | params: {', '.join(keys[:5])}"
                except:
                    pass
            parts.append(line + "\n")

    return "".join(parts)

# =============================================================================
# TOOL EXECUTION
# =============================================================================

def handle_tool_call(tool_name, args):
    """Execute tool and return result."""
    if tool_name == "save_event":
        from db import add_event

        if not args.get("pattern") or not args.get("target"):
            return f"✗ Error: Missing required fields"

        status, data = add_event(
            pattern=args.get("pattern"),
            worked=args.get("worked", True),
            target=args.get("target"),
            technique=args.get("technique"),
            impact=args.get("impact"),
            notes=args.get("notes"),
            payload=args.get("payload")
        )

        try:
            from rich.console import Console
            import sys
            console = Console(file=sys.stderr)

            if status == "duplicate":
                console.print(f"[yellow]⚠️ Duplicate:[/] [dim]{args.get('pattern')}[/] [yellow](déjà en mémoire)[/]")
                return ""

            if args.get("worked"):
                console.print(f"[green]✓ Saved:[/] [bold red]💥 VULN[/] [white]{args.get('pattern')}[/] on [cyan]{args.get('target')}[/]")
            else:
                console.print(f"[green]✓ Saved:[/] [bold blue]🛡️ BLOCKED[/] [white]{args.get('pattern')}[/] by [cyan]{args.get('target')}[/]")
            return ""
        except:
            return f"✓ Saved: {args.get('pattern')}"

    elif tool_name == "show_analysis":
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            console = Console(file=sys.stderr)

            tests = args.get("tests", [])
            tests_formatted = '\n'.join([f"  [cyan]▸[/] {test}" for test in tests])
            confidence = args.get("confidence", "MEDIUM")
            conf_color = {"LOW": "yellow", "MEDIUM": "yellow", "HIGH": "green"}.get(confidence, "yellow")

            analysis = f"""[bold white]{args.get('pattern', 'Unknown')}[/]

[red]●[/] Cible → [magenta]{args.get('target', 'Unknown')}[/]
[yellow]●[/] Hypothèse → [italic]{args.get('hypothesis', 'Unknown')}[/]

[bold magenta]⚡ TESTS[/]
{tests_formatted}

[green]✓[/] Impact: {args.get('impact', 'Unknown')}
[{conf_color}]◆[/] Confiance: [{conf_color}]{confidence}[/]"""

            console.print(Panel(analysis, title=f"📊 {args.get('title', 'Analyse')}", border_style="cyan"))
            return ""
        except:
            return f"Analyse: {args.get('pattern', 'Unknown')}"

    elif tool_name == "suggest_test":
        try:
            from rich.console import Console
            from rich.panel import Panel
            import sys
            console = Console(file=sys.stderr)

            steps = args.get("steps", [])
            steps_formatted = '\n'.join([f"  [green]{i+1}.[/] {step}" for i, step in enumerate(steps)])
            variables = args.get("variables", [])
            vars_formatted = '\n'.join([f"  [yellow]•[/] {var}" for var in variables]) if variables else "  [dim]None[/]"

            test_panel = f"""[bold white]Pattern:[/] [cyan]{args.get('pattern', 'Unknown')}[/]
[bold white]Target:[/] [red]{args.get('target', 'Unknown')}[/]

[bold yellow]⚡ STEPS[/]
{steps_formatted}

[bold yellow]🎯 VARIABLES[/]
{vars_formatted}

[green]✓[/] Expected: {args.get('expected', 'Unknown')}"""

            console.print(Panel(test_panel, title="🧪 Test Suggestion", border_style="green"))
            return ""
        except:
            return f"Test: {args.get('pattern', 'Unknown')}"

    elif tool_name == "ask_clarification":
        return f"❓ {args.get('question', 'Peux-tu préciser ?')}"

    return "Unknown tool"

# =============================================================================
# TOKEN TRACKING
# =============================================================================

LAST_PROMPT_TOKENS = 0
LAST_CACHE_READ_TOKENS = 0

# =============================================================================
# MAIN STREAMING FUNCTION
# =============================================================================

def chat_stream(msg, history, thinking_budget=0, use_tools=True, tool_choice=None,
                model=None, temperature=None, max_tokens=None, filtered_tools=None,
                context_level="full"):
    """
    Stream chat with Claude API.

    Args:
        msg: User message
        history: Conversation history
        thinking_budget: Extended thinking tokens (0 = disabled)
        use_tools: Enable tools
        tool_choice: Force tool selection
        model: Override model
        temperature: Override temperature
        max_tokens: Override max_tokens
        filtered_tools: Subset of tools to use
        context_level: "full" / "events" / "minimal"

    Yields:
        ("content", text) - Text chunks
        ("thinking_start", "") - Thinking started
        ("thinking_chunk", text) - Thinking content
        ("tool_start", name) - Tool call started
        ("tool_ready", {name, args}) - Tool ready for execution
        ("intent", name) - Intent classification result
    """
    global LAST_PROMPT_TOKENS, LAST_CACHE_READ_TOKENS

    # Build system prompt with caching
    sys_prompt = build_prompt(context_level)

    # Build messages
    messages = []
    for h in history:
        content = h.get("content", "")
        if content and content.strip():
            messages.append({"role": h["role"], "content": content})
    messages.append({"role": "user", "content": msg})

    # Save user message
    add_msg("user", msg)

    # Configure API call
    final_model = model or DEFAULT_MODEL
    final_max_tokens = max_tokens or int(os.getenv("MAX_TOKENS", "8192"))
    final_temperature = temperature if temperature is not None else float(os.getenv("TEMPERATURE", "0.7"))

    # Adjust max_tokens for thinking mode
    if thinking_budget > 0:
        final_max_tokens = 64000  # Need room for thinking + response

    kwargs = {
        "model": final_model,
        "max_tokens": final_max_tokens,
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

    # Add extended thinking
    if thinking_budget > 0:
        kwargs["thinking"] = {
            "type": "enabled",
            "budget_tokens": thinking_budget
        }

    # Add tools
    if use_tools:
        tools_to_use = filtered_tools if filtered_tools else BLV_TOOLS
        kwargs["tools"] = tools_to_use
        if tool_choice:
            kwargs["tool_choice"] = tool_choice

    # Stream response
    text = ""
    thinking_text = ""
    tool_calls_builder = {}
    usage_data = None

    with client.messages.stream(**kwargs) as stream:
        for event in stream:
            if hasattr(event, 'type'):
                # Thinking block
                if event.type == 'content_block_start':
                    if hasattr(event, 'content_block'):
                        block = event.content_block
                        if hasattr(block, 'type'):
                            if block.type == 'thinking':
                                yield ("thinking_start", "")
                            elif block.type == 'tool_use':
                                idx = event.index if hasattr(event, 'index') else 0
                                tool_calls_builder[idx] = {
                                    "id": block.id,
                                    "name": block.name,
                                    "arguments": ""
                                }
                                yield ("tool_start", block.name)

                # Content deltas
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
                                idx = event.index if hasattr(event, 'index') else 0
                                if idx in tool_calls_builder:
                                    tool_calls_builder[idx]["arguments"] += delta.partial_json

        # Get final usage
        final_message = stream.get_final_message()
        if hasattr(final_message, 'usage'):
            usage_data = final_message.usage

    # Update token tracking
    if usage_data:
        LAST_PROMPT_TOKENS = getattr(usage_data, 'input_tokens', 0)
        LAST_CACHE_READ_TOKENS = getattr(usage_data, 'cache_read_input_tokens', 0)

    # Yield tool calls
    for idx in sorted(tool_calls_builder.keys()):
        tc = tool_calls_builder[idx]
        if tc["name"]:
            try:
                args = json.loads(tc["arguments"]) if tc["arguments"] else {}
                yield ("tool_ready", {"name": tc["name"], "args": args})
            except Exception as e:
                yield ("tool_error", str(e))

    # Save assistant response
    output_tokens = getattr(usage_data, 'output_tokens', len(text)//4) if usage_data else len(text)//4
    add_msg("assistant", text, output_tokens)

# =============================================================================
# ROUTED CHAT (Intent classification → smart routing)
# =============================================================================

def chat_stream_routed(msg, history, use_routing=True):
    """
    Smart routing: Haiku classifies intent → routes to appropriate config.
    """
    if not use_routing:
        yield from chat_stream(msg, history)
        return

    # Classify intent
    intent = classify_intent(msg)
    yield ("intent", intent)

    # Get config
    config = INTENT_CONFIG.get(intent, INTENT_CONFIG["CHAT"])

    # Extract params
    model = config["model"]
    tool_choice = config["tool_choice"]
    temperature = config.get("temperature", 0.7)
    max_tokens = config.get("max_tokens", 4096)
    allowed_tools = config.get("tools", [])
    context_level = config.get("context", "full")
    thinking_budget = config.get("thinking_budget", 0)

    # Filter tools
    use_tools = tool_choice.get("type") != "none" and len(allowed_tools) > 0
    filtered_tools = None
    if use_tools and allowed_tools:
        filtered_tools = [t for t in BLV_TOOLS if t["name"] in allowed_tools]

    # Stream with config
    yield from chat_stream(
        msg=msg,
        history=history,
        thinking_budget=thinking_budget,
        use_tools=use_tools,
        tool_choice=tool_choice if use_tools else None,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        filtered_tools=filtered_tools,
        context_level=context_level
    )

# =============================================================================
# ANALYZE FLOW (Opus + Extended Thinking)
# =============================================================================

def analyze_flow(requests_data: list, existing_map: dict = None) -> dict:
    """
    Cartographie intelligente du flow avec Opus + Extended Thinking.

    Args:
        requests_data: Liste des requêtes HTTP importées
        existing_map: Cartographie existante (pour update incrémental)

    Returns:
        dict: Cartographie du flow {endpoints, relations, attack_surface, suggestions}
    """
    # Build analysis prompt
    prompt_parts = ["""Tu es un expert en sécurité applicative spécialisé BLV (Business Logic Vulnerabilities).

Analyse ces requêtes HTTP et produis une CARTOGRAPHIE STRUCTURÉE du flow.

# OUTPUT FORMAT (JSON strict)
{
    "site": "nom du site",
    "flow_type": "payment|auth|order|transfer|other",
    "endpoints": [
        {
            "url": "...",
            "method": "...",
            "role": "initiate|validate|finalize|callback",
            "params_sensibles": ["param1", "param2"],
            "ids_dynamiques": ["orderId", "sessionId"]
        }
    ],
    "relations": [
        {
            "from": "endpoint1",
            "to": "endpoint2",
            "type": "sequential|conditional|callback",
            "shared_params": ["param"]
        }
    ],
    "trust_boundaries": [
        {
            "location": "between X and Y",
            "risk": "description du risque"
        }
    ],
    "attack_surface": [
        {
            "pattern": "PATTERN_NAME",
            "target_endpoint": "url",
            "target_param": "param",
            "hypothesis": "Si X alors Y",
            "confidence": "HIGH|MEDIUM|LOW",
            "priority": 1
        }
    ]
}
"""]

    # Add existing map for incremental update
    if existing_map:
        prompt_parts.append(f"\n# CARTOGRAPHIE EXISTANTE (à enrichir)\n{json.dumps(existing_map, indent=2)}\n")

    # Add requests
    prompt_parts.append("\n# REQUÊTES À ANALYSER\n")
    for req in requests_data:
        prompt_parts.append(f"## {req.get('method', 'GET')} {req.get('url', '')}\n")
        if req.get('body'):
            prompt_parts.append(f"Body: {req.get('body', '')[:500]}\n")
        if req.get('headers'):
            prompt_parts.append(f"Headers: {req.get('headers', '')[:300]}\n")
        prompt_parts.append("\n")

    prompt = "".join(prompt_parts)

    # Call Opus with Extended Thinking
    try:
        response = client.messages.create(
            model=MODELS["opus"],
            max_tokens=64000,
            temperature=0.3,
            thinking={
                "type": "enabled",
                "budget_tokens": THINKING_BUDGETS["deep"]
            },
            messages=[{"role": "user", "content": prompt}]
        )

        # Extract JSON from response
        result_text = ""
        for block in response.content:
            if hasattr(block, 'text'):
                result_text += block.text

        # Parse JSON
        json_match = re.search(r'\{[\s\S]*\}', result_text)
        if json_match:
            return json.loads(json_match.group())

        return {"error": "No JSON in response", "raw": result_text}

    except Exception as e:
        return {"error": str(e)}
